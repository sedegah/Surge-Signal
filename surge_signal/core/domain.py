"""Domain models shared by the UI, storage, analysis and reporting layers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Iterable


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().replace(microsecond=0).isoformat()


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def human_time(value: str | None) -> str:
    parsed = parse_datetime(value)
    if not parsed:
        return "—"
    return parsed.astimezone().strftime("%d %b %Y, %H:%M")


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }[self.value]

    @property
    def label(self) -> str:
        return self.value.capitalize()


class FindingStatus(StrEnum):
    VERIFIED = "verified"
    POTENTIAL = "potential"
    OBSERVATION = "observation"


class AssessmentStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    COMPLETE = "complete"
    ARCHIVED = "archived"


class AuditStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SecurityFamily(StrEnum):
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    OWE = "owe"
    ENTERPRISE = "enterprise"
    UNKNOWN = "unknown"


BSSID_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$", re.IGNORECASE)


def normalize_bssid(value: str | None) -> str:
    if not value:
        return ""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(cleaned) != 12:
        return value.strip().upper()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2)).upper()


def valid_bssid(value: str | None) -> bool:
    return bool(value and BSSID_RE.fullmatch(normalize_bssid(value)))


def signal_to_dbm(percent: int | float | None) -> int | None:
    if percent is None:
        return None
    try:
        numeric = max(0, min(100, float(percent)))
    except (TypeError, ValueError):
        return None
    return int(round(numeric / 2 - 100))


def dbm_label(dbm: int | None) -> str:
    if dbm is None:
        return "—"
    if dbm >= -50:
        quality = "excellent"
    elif dbm >= -60:
        quality = "good"
    elif dbm >= -70:
        quality = "fair"
    elif dbm >= -80:
        quality = "weak"
    else:
        quality = "very weak"
    return f"{dbm} dBm ({quality})"


def channel_to_band(channel: int | None) -> str:
    if channel is None:
        return "Unknown"
    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 177:
        return "5 GHz"
    if channel >= 5935:
        return "6 GHz"
    return "Unknown"


def classify_security(
    authentication: str | None, encryption: str | None
) -> SecurityFamily:
    auth = (authentication or "").lower()
    enc = (encryption or "").lower()
    if "owe" in auth or "enhanced open" in auth:
        return SecurityFamily.OWE
    if "wpa3" in auth or "sae" in auth:
        return SecurityFamily.WPA3
    if "wpa2" in auth or "rsn" in auth:
        return SecurityFamily.WPA2
    if "wpa" in auth:
        return SecurityFamily.WPA
    if "wep" in auth or "wep" in enc or enc in {"wep-40", "wep-104"}:
        return SecurityFamily.WEP
    if "open" in auth or not auth:
        if "wep" in enc:
            return SecurityFamily.WEP
        if enc in {"", "none"}:
            return SecurityFamily.OPEN
    if "802.1x" in auth or "enterprise" in auth or "eap" in auth:
        return SecurityFamily.ENTERPRISE
    return SecurityFamily.UNKNOWN


def security_summary(authentication: str, encryption: str) -> str:
    family = classify_security(authentication, encryption)
    enc = (encryption or "unknown").upper()
    if family is SecurityFamily.OPEN:
        return "Open — no encryption"
    if family is SecurityFamily.WEP:
        return f"WEP ({enc}) — broken"
    if family is SecurityFamily.WPA:
        return f"WPA ({enc}) — legacy"
    if family is SecurityFamily.WPA2:
        return f"WPA2 ({enc})"
    if family is SecurityFamily.WPA3:
        return f"WPA3 ({enc})"
    if family is SecurityFamily.OWE:
        return "OWE — encrypted open"
    if family is SecurityFamily.ENTERPRISE:
        return f"Enterprise ({enc})"
    return f"{authentication or 'Unknown'} / {enc}"


@dataclass(slots=True)
class NetworkObservation:
    """A wireless network as observed by one discovery source."""

    ssid: str
    bssid: str
    signal_dbm: int | None = None
    signal_percent: int | None = None
    channel: int | None = None
    band: str = "Unknown"
    standards: str = ""
    authentication: str = ""
    encryption: str = ""
    pmf: str = "Unknown"
    wps: str = "Unknown"
    hidden: bool = False
    source: str = "windows"
    first_seen: str = field(default_factory=iso_now)
    last_seen: str = field(default_factory=iso_now)
    raw: dict[str, Any] = field(default_factory=dict)
    id: int | None = None
    assessment_id: str | None = None

    def __post_init__(self) -> None:
        self.bssid = normalize_bssid(self.bssid)
        self.ssid = (self.ssid or "").strip()
        self.hidden = self.hidden or not self.ssid or self.ssid == "<hidden>"
        if self.band == "Unknown" and self.channel:
            self.band = channel_to_band(self.channel)

    @property
    def display_ssid(self) -> str:
        return self.ssid if self.ssid else "<hidden network>"

    @property
    def family(self) -> SecurityFamily:
        return classify_security(self.authentication, self.encryption)

    @property
    def security(self) -> str:
        return security_summary(self.authentication, self.encryption)


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    explanation: str
    impact: str
    remediation: str
    status: FindingStatus = FindingStatus.POTENTIAL
    confidence: str = "Medium"
    evidence: str = ""
    bssid: str = ""
    ssid: str = ""
    id: int | None = None
    assessment_id: str | None = None
    network_id: int | None = None
    created_at: str = field(default_factory=iso_now)


@dataclass(slots=True)
class Assessment:
    name: str
    organisation: str
    scope: str
    permitted_targets: list[str]
    tester: str
    status: AssessmentStatus = AssessmentStatus.DRAFT
    start_date: str = ""
    end_date: str = ""
    notes: str = ""
    id: str = ""
    created_at: str = field(default_factory=iso_now)
    updated_at: str = field(default_factory=iso_now)

    def target_is_permitted(self, bssid: str | None, ssid: str | None = None) -> bool:
        if not self.permitted_targets:
            return False
        bssid_n = normalize_bssid(bssid)
        ssid_n = (ssid or "").strip().casefold()
        for raw in self.permitted_targets:
            target = raw.strip()
            if not target:
                continue
            if valid_bssid(target) and normalize_bssid(target) == bssid_n:
                return True
            if ssid_n and target.casefold() == ssid_n:
                return True
        return False

    @property
    def target_count(self) -> int:
        return len([t for t in self.permitted_targets if t.strip()])

    @property
    def is_open(self) -> bool:
        return self.status in {AssessmentStatus.ACTIVE, AssessmentStatus.DRAFT}


@dataclass(slots=True)
class Capture:
    filename: str
    stored_path: str
    format: str
    size_bytes: int
    sha256: str
    packet_count: int = 0
    start_ts: str = ""
    end_ts: str = ""
    bssid: str = ""
    ssid: str = ""
    link_type: str = ""
    integrity: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)
    id: int | None = None
    assessment_id: str | None = None
    imported_at: str = field(default_factory=iso_now)
    status: str = "imported"


@dataclass(slots=True)
class Evidence:
    label: str
    kind: str
    path: str
    sha256: str = ""
    notes: str = ""
    capture_id: int | None = None
    id: int | None = None
    assessment_id: str | None = None
    added_at: str = field(default_factory=iso_now)


@dataclass(slots=True)
class AuditEvent:
    action: str
    detail: str
    actor: str = "operator"
    assessment_id: str | None = None
    timestamp: str = field(default_factory=iso_now)
    id: int | None = None


@dataclass(slots=True)
class PasswordAuditResult:
    status: AuditStatus
    method: str
    candidates_tested: int = 0
    recovered: bool = False
    matched_index: int | None = None
    masked_secret: str = ""
    elapsed_seconds: float = 0.0
    detail: str = ""
    engine: str = "local"
    strength_score: int | None = None


def severity_counts(findings: Iterable[Finding] | Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        if isinstance(finding, Finding):
            key = finding.severity.value
        else:
            key = str(finding.get("severity", "info")).lower()
        if key in counts:
            counts[key] += 1
    return counts


def mask_secret(secret: str) -> str:
    """Return a non-reversible display form; never reveal a recovered PSK."""
    if not secret:
        return ""
    if len(secret) <= 2:
        return "*" * len(secret)
    return f"{secret[0]}{'*' * max(4, len(secret) - 2)}{secret[-1]}"


def coerce_severity(value: str | Severity) -> Severity:
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value).lower())
    except ValueError:
        return Severity.INFO


def coerce_status(value: str | FindingStatus) -> FindingStatus:
    if isinstance(value, FindingStatus):
        return value
    try:
        return FindingStatus(str(value).lower())
    except ValueError:
        return FindingStatus.POTENTIAL

