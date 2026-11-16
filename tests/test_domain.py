from __future__ import annotations

from surge_signal.core.domain import (
    Assessment,
    AssessmentStatus,
    FindingStatus,
    NetworkObservation,
    SecurityFamily,
    classify_security,
    normalize_bssid,
    severity_counts,
)
from tests.helpers import AP


def test_bssid_normalisation() -> None:
    assert normalize_bssid("aa-bb-cc-11-22-33") == "AA:BB:CC:11:22:33"
    assert normalize_bssid("aabbcc112233") == AP


def test_security_classification() -> None:
    assert classify_security("Open", "None") is SecurityFamily.OPEN
    assert classify_security("Open", "WEP") is SecurityFamily.WEP
    assert classify_security("WPA2-Personal", "CCMP") is SecurityFamily.WPA2
    assert classify_security("WPA3-Personal", "CCMP") is SecurityFamily.WPA3
    assert classify_security("OWE", "CCMP") is SecurityFamily.OWE


def test_scope_requires_explicit_target() -> None:
    assessment = Assessment(
        name="Lab",
        organisation="Lab",
        scope="Authorised lab",
        permitted_targets=[AP],
        tester="Tester",
        status=AssessmentStatus.ACTIVE,
        id="SS-2026-TEST01",
    )
    assert assessment.target_is_permitted(AP)
    assert not assessment.target_is_permitted("11:22:33:44:55:66")
    assert not Assessment(
        name="Empty",
        organisation="",
        scope="",
        permitted_targets=[],
        tester="",
    ).target_is_permitted(AP)


def test_network_family_and_counts() -> None:
    network = NetworkObservation(
        ssid="Lab",
        bssid=AP,
        authentication="WPA2-Personal",
        encryption="CCMP",
        source="windows",
    )
    assert network.family is SecurityFamily.WPA2
    assert "WPA2" in network.security
    assert severity_counts([])["critical"] == 0

