from __future__ import annotations

from pathlib import Path

from surge_signal.core.domain import AssessmentStatus, NetworkObservation
from tests.helpers import AP


def test_assessment_roundtrip(db) -> None:
    assessment = db.create_assessment(
        __import__("surge_signal.core.domain", fromlist=["Assessment"]).Assessment(
            name="Lab",
            organisation="Org",
            scope="Authorised scope",
            permitted_targets=[AP],
            tester="Tester",
            status=AssessmentStatus.ACTIVE,
        )
    )
    loaded = db.get_assessment(assessment.id)
    assert loaded is not None
    assert loaded.name == "Lab"
    assert loaded.permitted_targets == [AP]
    assert loaded.status is AssessmentStatus.ACTIVE
    assert db.integrity_check()[0]


def test_network_upsert_and_search(db) -> None:
    assessment = db.create_assessment(
        __import__("surge_signal.core.domain", fromlist=["Assessment"]).Assessment(
            name="Lab",
            organisation="",
            scope="",
            permitted_targets=[AP],
            tester="",
        )
    )
    network = NetworkObservation(
        ssid="LabNet",
        bssid=AP,
        signal_dbm=-42,
        channel=6,
        authentication="WPA2-Personal",
        encryption="CCMP",
    )
    db.upsert_networks(assessment.id, [network])
    db.upsert_networks(assessment.id, [network])
    assert db.network_count(assessment.id) == 1
    found = db.list_networks(assessment.id, search="LabNet")
    assert len(found) == 1
    assert found[0].signal_dbm == -42


def test_audit_log_persists(db) -> None:
    db.log("test.action", "A detail", actor="tester")
    events = db.list_audit_events(limit=5)
    assert events[0].action == "test.action"
    assert events[0].actor == "tester"

