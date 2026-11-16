from __future__ import annotations

from surge_signal.wireless.captures import analyze_capture, extract_handshakes
from surge_signal.audit.password_audit import verify_handshake_candidate
from tests.helpers import AP, PASSPHRASE, SSID, make_beacon_capture, make_handshake_capture


def test_beacon_capture_metadata(tmp_path) -> None:
    path = make_beacon_capture(tmp_path / "beacon.pcap")
    analysis = analyze_capture(path)
    assert analysis.format == "pcap"
    assert analysis.packet_count == 1
    assert analysis.integrity == "valid"
    assert analysis.ssid == SSID
    assert analysis.bssid == AP
    assert analysis.channel == 6
    assert analysis.authentication == "WPA2-Personal"
    assert analysis.encryption == "CCMP"
    assert analysis.wps == "Enabled"
    assert analysis.pmf == "Disabled"
    assert analysis.beacon_count == 1


def test_handshake_extraction_and_verification(tmp_path) -> None:
    path = make_handshake_capture(tmp_path / "handshake.pcap")
    analysis = analyze_capture(path)
    assert analysis.eapol_count == 2
    assert len(analysis.handshakes) == 1
    handshake = analysis.handshakes[0]
    assert handshake.complete
    assert handshake.ssid == SSID
    assert handshake.bssid == AP
    assert verify_handshake_candidate(PASSPHRASE, handshake)
    assert not verify_handshake_candidate("wrong passphrase", handshake)


def test_sha256_and_evidence_metadata(tmp_path) -> None:
    path = make_beacon_capture(tmp_path / "beacon.pcap")
    analysis = analyze_capture(path)
    assert len(analysis.sha256) == 64
    assert analysis.metadata()["packet_count"] == 1
    assert analysis.metadata()["handshakes"] == []


def test_truncated_capture_is_reported(tmp_path) -> None:
    path = make_beacon_capture(tmp_path / "truncated.pcap")
    data = path.read_bytes()
    path.write_bytes(data[:-10])
    analysis = analyze_capture(path)
    assert analysis.integrity in {"truncated", "invalid"}

