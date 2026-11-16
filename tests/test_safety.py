from __future__ import annotations

import pytest

from surge_signal.core.domain import Assessment, AssessmentStatus
from surge_signal.core.safety import (
    AuthorisationError,
    SafetyError,
    authorize_offline_audit,
    redact_argv,
    validate_argv,
)
from tests.helpers import AP


def test_disruptive_tools_are_blocked() -> None:
    with pytest.raises(SafetyError):
        validate_argv(["aireplay-ng", "--deauth", "100", "-a", AP, "wlan0"])
    with pytest.raises(SafetyError):
        validate_argv(["mdk4", "wlan0", "b"])
    with pytest.raises(SafetyError):
        validate_argv(["aircrack-ng", "-w", "list;rm", "-b", AP, "cap.pcap"])


def test_offline_tools_are_allowed() -> None:
    validate_argv(["aircrack-ng", "-w", "words.txt", "-b", AP, "capture.pcap"])
    validate_argv(["airmon-ng"])
    validate_argv(["tshark", "-r", "capture.pcapng"])


def test_authorisation_requires_active_scope_and_attestation() -> None:
    assessment = Assessment(
        name="Lab",
        organisation="Lab",
        scope="Authorised",
        permitted_targets=[AP],
        tester="Tester",
        status=AssessmentStatus.DRAFT,
    )
    with pytest.raises(AuthorisationError):
        authorize_offline_audit(
            assessment, AP, "Lab", confirmed=True, lab_attestation=True
        )
    assessment.status = AssessmentStatus.ACTIVE
    with pytest.raises(AuthorisationError):
        authorize_offline_audit(
            assessment, AP, "Lab", confirmed=False, lab_attestation=True
        )
    with pytest.raises(AuthorisationError):
        authorize_offline_audit(
            assessment, "00:11:22:33:44:55", "Other", confirmed=True, lab_attestation=True
        )
    result = authorize_offline_audit(
        assessment, AP, "Lab", confirmed=True, lab_attestation=True
    )
    assert result.assessment_id == assessment.id
    assert result.bssid == AP


def test_command_redaction() -> None:
    summary = redact_argv(["aircrack-ng", "-w", "secret-password.txt", "-b", AP, "x.pcap"])
    assert "secret-password.txt" not in summary
    assert "<redacted>" in summary



def test_sudo_command_validator_skips_its_own_flags() -> None:
    validate_argv(
        ["sudo", "-S", "-p", "", "--", "apt-get", "install", "-y", "aircrack-ng"],
        allow_sudo=True,
    )
    with pytest.raises(SafetyError):
        validate_argv(["sudo", "-S", "apt-get", "update"], allow_sudo=True)
