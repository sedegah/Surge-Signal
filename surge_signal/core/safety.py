"""Safety and authorisation gates.

Surge Signal is passive/offline by design. Every research command passes through
an allow-list that excludes disruptive wireless tooling, and every password
audit must be tied to an active assessment whose permitted targets include the
capture's BSSID.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .domain import Assessment, AssessmentStatus, normalize_bssid, valid_bssid


class SafetyError(RuntimeError):
    """A requested operation violates the product safety policy."""


class AuthorisationError(SafetyError):
    """The assessment scope does not authorise the requested target."""


                                                                           
                                                                              
ALLOWED_PROGRAMS = frozenset(
    {
        "aircrack-ng",
        "airmon-ng",
        "airodump-ng",
        "apt-get",
        "env",
        "iw",
        "iwconfig",
        "ip",
        "ethtool",
        "lsusb",
        "lspci",
        "uname",
        "which",
        "command",
        "id",
        "cat",
        "sha256sum",
        "stat",
        "tshark",
        "dumpcap",
        "capinfos",
        "hcxpcapngtool",
        "timeout",
        "echo",
    }
)

                                                                       
FORBIDDEN_MARKERS = (
    "--deauth",
    "deauthenticate",
    "disassociate",
    "aireplay-ng",
    "airbase-ng",
    "mdk3",
    "mdk4",
    "bettercap",
    "beacon-flood",
    "auth-flood",
    "pktmx",
    "wifi-pumpkin",
    "eaphammer",
    "pmkid-attack",
    "handshake-capture --active",
)


def validate_argv(argv: Sequence[str], *, allow_sudo: bool = False) -> None:
    """Validate an argument vector before execution.

    The first element must be an approved tool; sudo may only prefix an already
    approved program and is itself never run as a bare shell.
    """
    if not argv:
        raise SafetyError("No command was supplied.")
    program = Path(argv[0]).name.lower()
    if program == "sudo":
        if not allow_sudo:
            raise SafetyError("Elevation was not requested through the privileged path.")
        if "--" not in argv:
            raise SafetyError(
                "Privileged commands must separate sudo options from the command with '--'."
            )
        separator = argv.index("--")
        command = list(argv[separator + 1 :])
        if not command:
            raise SafetyError("No privileged command was supplied after '--'.")
        return validate_argv(command, allow_sudo=False)
    if program not in ALLOWED_PROGRAMS:
        raise SafetyError(
            f"Tool '{program}' is not permitted by the Surge Signal safety policy."
        )
    joined = " ".join(shlex.quote(part) for part in argv).lower()
    for marker in FORBIDDEN_MARKERS:
        if marker in joined:
            raise SafetyError(
                "The command contains a disruptive or active-testing operation that "
                "is outside the application safety policy."
            )
    if ">" in joined or "|" in joined or "&&" in joined or ";" in joined:
        raise SafetyError("Shell metacharacters are not accepted in research commands.")


def require_active_assessment(assessment: Assessment) -> None:
    if assessment.status is not AssessmentStatus.ACTIVE:
        raise AuthorisationError(
            "The assessment must be marked Active before running a password audit."
        )


def require_permitted_target(assessment: Assessment, bssid: str, ssid: str = "") -> None:
    target = normalize_bssid(bssid)
    if not valid_bssid(target):
        raise AuthorisationError("A valid BSSID is required for an authorised audit.")
    if not assessment.target_is_permitted(target, ssid):
        raise AuthorisationError(
            f"BSSID {target} is not listed in the permitted targets for "
            f"assessment {assessment.id}. Add it explicitly to the scope before testing."
        )


@dataclass(frozen=True, slots=True)
class AuditAuthorisation:
    assessment_id: str
    bssid: str
    ssid: str
    operator_confirmed: bool


def authorize_offline_audit(
    assessment: Assessment,
    bssid: str,
    ssid: str,
    *,
    confirmed: bool,
    lab_attestation: bool,
) -> AuditAuthorisation:
    require_active_assessment(assessment)
    require_permitted_target(assessment, bssid, ssid)
    if not confirmed or not lab_attestation:
        raise AuthorisationError(
            "The operator must confirm that the capture is from an authorised "
            "laboratory network and that offline auditing is permitted."
        )
    return AuditAuthorisation(
        assessment_id=assessment.id,
        bssid=normalize_bssid(bssid),
        ssid=ssid,
        operator_confirmed=True,
    )


def is_safe_path_within(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
        return True
    except (ValueError, OSError):
        return False


def redact_argv(argv: Iterable[str]) -> str:
    """Summarise a command for logs without arguments that may be sensitive."""
    parts = list(argv)
    if not parts:
        return ""
    safe: list[str] = []
    for index, part in enumerate(parts):
        if index == 0:
            safe.append(Path(part).name)
        elif "pass" in part.lower() or "key" in part.lower():
            safe.append("<redacted>")
        elif Path(part).suffix.lower() in {".cap", ".pcap", ".pcapng", ".22000"}:
            safe.append(Path(part).name)
        else:
            safe.append(part if len(part) < 120 else "<argument>")
    return " ".join(safe)


