from __future__ import annotations

from surge_signal.core.domain import FindingStatus, NetworkObservation, SecurityFamily, Severity
from surge_signal.core.rules import analyze_network
from tests.helpers import AP


def _network(**overrides) -> NetworkObservation:
    values = dict(
        ssid="Lab",
        bssid=AP,
        authentication="WPA2-Personal",
        encryption="CCMP",
        pmf="Capable",
        wps="Not advertised",
        source="windows",
    )
    values.update(overrides)
    return NetworkObservation(**values)


def test_open_network_rule() -> None:
    findings = analyze_network(_network(authentication="Open", encryption="None"))
    rule = next(item for item in findings if item.rule_id == "SS-AUTH-001")
    assert rule.severity is Severity.HIGH
    assert rule.status is FindingStatus.POTENTIAL
    assert rule.remediation


def test_wep_rule_is_critical() -> None:
    findings = analyze_network(_network(authentication="Open", encryption="WEP"))
    assert any(
        item.rule_id == "SS-AUTH-002" and item.severity is Severity.CRITICAL
        for item in findings
    )


def test_wpa1_and_tkip_rules() -> None:
    findings = analyze_network(_network(authentication="WPA-Personal", encryption="TKIP"))
    ids = {item.rule_id for item in findings}
    assert "SS-AUTH-003" in ids
    assert "SS-AUTH-004" in ids


def test_wpa3_has_no_legacy_finding() -> None:
    findings = analyze_network(
        _network(authentication="WPA3-Personal", encryption="CCMP", pmf="Required")
    )
    assert not [item for item in findings if item.severity is Severity.HIGH]


def test_wps_and_pmf_rules() -> None:
    findings = analyze_network(_network(pmf="Disabled", wps="Enabled"))
    ids = {item.rule_id for item in findings}
    assert "SS-AUTH-005" in ids
    assert "SS-AUTH-007" in ids


def test_hidden_network_is_observation_only() -> None:
    findings = analyze_network(_network(ssid="", hidden=True))
    hidden = next(item for item in findings if item.rule_id == "SS-OBS-001")
    assert hidden.status is FindingStatus.OBSERVATION
    assert hidden.severity is Severity.INFO

