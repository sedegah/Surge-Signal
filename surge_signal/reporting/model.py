"""Report context and shared helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..core.branding import APP_NAME, APP_VERSION
from ..core.db import Database
from ..core.domain import (
    Assessment,
    AuditEvent,
    Capture,
    Evidence,
    Finding,
    NetworkObservation,
    severity_counts,
)


@dataclass(slots=True)
class ReportContext:
    assessment: Assessment
    networks: list[NetworkObservation]
    findings: list[Finding]
    captures: list[Capture]
    evidence: list[Evidence]
    audits: list[dict[str, Any]]
    audit_events: list[AuditEvent]
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    )
    report_id: str = ""

    @property
    def counts(self) -> dict[str, int]:
        return severity_counts(self.findings)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def verified_count(self) -> int:
        return sum(1 for item in self.findings if item.status.value == "verified")

    @property
    def potential_count(self) -> int:
        return sum(1 for item in self.findings if item.status.value == "potential")

    @property
    def observation_count(self) -> int:
        return sum(1 for item in self.findings if item.status.value == "observation")

    @property
    def highest_severity(self) -> str:
        for name in ("critical", "high", "medium", "low", "info"):
            if self.counts.get(name):
                return name
        return "none"

    @property
    def networks_by_bssid(self) -> dict[str, NetworkObservation]:
        return {item.bssid: item for item in self.networks}

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda item: (
                item.severity.rank,
                {"verified": 0, "potential": 1, "observation": 2}.get(
                    item.status.value, 3
                ),
                item.ssid,
            ),
        )

    def finding_for(self, finding: Finding) -> NetworkObservation | None:
        for network in self.networks:
            if finding.network_id and network.id == finding.network_id:
                return network
            if finding.bssid and network.bssid == finding.bssid:
                return network
        return None


def collect_report_context(db: Database, assessment_id: str) -> ReportContext:
    assessment = db.get_assessment(assessment_id)
    if not assessment:
        raise ValueError(f"Assessment {assessment_id} was not found.")
    return ReportContext(
        assessment=assessment,
        networks=db.list_networks(assessment_id),
        findings=db.list_findings(assessment_id),
        captures=db.list_captures(assessment_id),
        evidence=db.list_evidence(assessment_id),
        audits=db.list_password_audits(assessment_id),
        audit_events=db.list_audit_events(assessment_id, limit=100),
        report_id=f"RPT-{assessment_id}-{datetime.now(timezone.utc):%Y%m%d%H%M}",
    )


def executive_summary(context: ReportContext) -> list[str]:
    counts = context.counts
    assessment = context.assessment
    paragraphs = [
        (
            f"{APP_NAME} assessed {len(context.networks)} wireless network"
            f"{'s' if len(context.networks) != 1 else ''} for the authorised scope "
            f"\"{assessment.name}\" on behalf of {assessment.organisation or 'the assessment owner'}."
        )
    ]
    if context.total_findings:
        paragraphs.append(
            f"The assessment recorded {counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low and {counts['info']} informational "
            f"finding{'' if context.total_findings == 1 else 's'}. "
            f"{context.verified_count} finding(s) were marked verified, "
            f"{context.potential_count} remain potential risks requiring validation, and "
            f"{context.observation_count} are observations."
        )
    else:
        paragraphs.append(
            "No findings were recorded. This may indicate a strong configuration baseline "
            "or that inspection has not yet been completed; absence of findings is not proof "
            "that the environment is secure."
        )
    if context.captures:
        complete = sum(
            1
            for item in context.captures
            if item.metadata.get("handshakes")
        )
        paragraphs.append(
            f"{len(context.captures)} capture file(s) were imported and registered as evidence. "
            f"{complete} capture(s) contain a complete WPA handshake suitable for controlled "
            "offline auditing."
        )
    if counts["critical"] or counts["high"]:
        paragraphs.append(
            "Priority remediation should focus on the critical and high findings before "
            "lower-severity configuration improvements."
        )
    else:
        paragraphs.append(
            "No critical or high-severity findings were recorded from the evidence available "
            "at report time. Verify scope coverage before treating this as a clean result."
        )
    return paragraphs


def report_metadata(context: ReportContext) -> dict[str, str]:
    return {
        "product": f"{APP_NAME} {APP_VERSION}",
        "report_id": context.report_id,
        "assessment_id": context.assessment.id,
        "generated_at": context.generated_at,
        "classification": "Authorised security assessment",
    }

