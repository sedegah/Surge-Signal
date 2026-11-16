from __future__ import annotations

import json
from pathlib import Path

import pytest

from surge_signal.core.domain import AssessmentStatus, NetworkObservation
from tests.helpers import AP, PASSPHRASE, SSID, make_handshake_capture


def _seed_assessment(service):
    assessment = service.create_assessment(
        name="Authorised Lab",
        organisation="Surge Lab",
        scope="Isolated laboratory network under written authorisation.",
        permitted_targets=[AP],
        tester="Test Operator",
        status=AssessmentStatus.ACTIVE,
        start_date="2026-11-16",
    )
    service.db.upsert_networks(
        assessment.id,
        [
            NetworkObservation(
                ssid=SSID,
                bssid=AP,
                signal_dbm=-48,
                channel=6,
                band="2.4 GHz",
                standards="802.11n",
                authentication="WPA2-Personal",
                encryption="CCMP",
                pmf="Disabled",
                wps="Enabled",
                source="windows",
            )
        ],
    )
    return assessment


def test_full_authorised_workflow(service, tmp_path) -> None:
    assessment = _seed_assessment(service)
    findings = service.inspect_assessment(assessment.id)
    assert findings
    assert service.db.finding_counts(assessment.id)["high"] >= 1
    capture = service.import_capture(
        assessment.id, make_handshake_capture(tmp_path / "handshake.pcap")
    )
    assert capture.packet_count == 4
    assert capture.integrity == "valid"
    assert service.db.list_evidence(assessment.id)
    record = service.wordlists.create_custom_list(
        "authorised-lab", ["wrong-candidate", PASSPHRASE], "Test list"
    )
    prepared = service.prepare_wordlist([int(record["id"])], max_candidates=100)
    assert prepared.candidate_count == 2
    result = service.run_local_audit(
        assessment.id,
        capture.id,
        prepared.path,
        bssid=AP,
        confirmed=True,
        lab_attestation=True,
        max_candidates=2,
    )
    assert result.recovered
    assert result.masked_secret
    assert PASSPHRASE not in result.masked_secret
    audits = service.db.list_password_audits(assessment.id)
    assert audits[0]["recovered"] == 1
    assert PASSPHRASE not in json.dumps(audits)
    events = service.db.list_audit_events(assessment.id, limit=100)
    assert PASSPHRASE not in "\n".join(event.detail for event in events)


def test_out_of_scope_audit_is_blocked(service, tmp_path) -> None:
    assessment = service.create_assessment(
        name="Scoped Lab",
        organisation="Lab",
        scope="Only one BSSID",
        permitted_targets=["11:22:33:44:55:66"],
        tester="Tester",
        status=AssessmentStatus.ACTIVE,
    )
    capture = service.import_capture(
        assessment.id, make_handshake_capture(tmp_path / "handshake.pcap")
    )
    wordlist = service.wordlists.create_custom_list("items", [PASSPHRASE])
    with pytest.raises(Exception):
        service.run_local_audit(
            assessment.id,
            capture.id,
            wordlist["path"],
            bssid=AP,
            confirmed=True,
            lab_attestation=True,
        )


def test_inactive_assessment_blocks_audit(service, tmp_path) -> None:
    assessment = _seed_assessment(service)
    service.set_assessment_status(assessment.id, AssessmentStatus.COMPLETE)
    capture = service.import_capture(
        assessment.id, make_handshake_capture(tmp_path / "handshake.pcap")
    )
    wordlist = service.wordlists.create_custom_list("items", [PASSPHRASE])
    with pytest.raises(Exception):
        service.run_local_audit(
            assessment.id,
            capture.id,
            wordlist["path"],
            bssid=AP,
            confirmed=True,
            lab_attestation=True,
        )


