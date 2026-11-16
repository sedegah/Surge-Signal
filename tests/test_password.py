from __future__ import annotations

import threading

from surge_signal.audit.password_audit import (
    LocalWpaAuditor,
    evaluate_password,
    inspect_wordlist,
    parse_aircrack_output,
)
from tests.helpers import AP, PASSPHRASE, make_handshake_capture


def test_strength_evaluation_common_and_strong() -> None:
    weak = evaluate_password("password123")
    assert weak.score <= 1
    assert weak.issues
    strong = evaluate_password("Correct-Horse-Battery-9!")
    assert strong.score >= 3
    assert strong.policy_compliant


def test_strength_is_deterministic_and_never_logs(caplog) -> None:
    with caplog.at_level("DEBUG"):
        result = evaluate_password("Unique-Lab-Phrase-42!")
    assert result.length == 21
    assert "Unique-Lab-Phrase-42!" not in caplog.text


def test_wordlist_inspection(tmp_path) -> None:
    path = tmp_path / "words.txt"
    path.write_text("short\ncorrect-length-password\n\nanother-password\n", encoding="utf-8")
    info = inspect_wordlist(path)
    assert info.line_count == 3
    assert info.min_length == 5
    assert info.max_length == 23
    assert len(info.sha256) == 64


def test_local_auditor_recovers_authorised_test_capture(tmp_path) -> None:
    capture = make_handshake_capture(tmp_path / "handshake.pcap")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("wrong-one\nwrong-two\n" + PASSPHRASE + "\n", encoding="utf-8")
    result = LocalWpaAuditor().audit(capture, wordlist, AP)
    assert result.recovered
    assert result.candidates_tested == 3
    assert "*" in result.masked_secret
    assert PASSPHRASE not in result.masked_secret
    assert PASSPHRASE not in result.detail


def test_local_auditor_no_match_and_no_handshake(tmp_path) -> None:
    capture = make_handshake_capture(tmp_path / "handshake.pcap")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("wrong-one\nwrong-two\n", encoding="utf-8")
    result = LocalWpaAuditor().audit(capture, wordlist, AP)
    assert result.status.value == "completed"
    assert not result.recovered
    other = tmp_path / "other.pcap"
    other.write_bytes(capture.read_bytes()[:100])
    failed = LocalWpaAuditor().audit(other, wordlist, AP)
    assert failed.status.value == "failed"


def test_local_auditor_cancel(tmp_path) -> None:
    capture = make_handshake_capture(tmp_path / "handshake.pcap")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("\n".join(f"wrong-{i}" for i in range(100)), encoding="utf-8")
    event = threading.Event()
    event.set()
    result = LocalWpaAuditor(stop_event=event).audit(capture, wordlist, AP)
    assert result.status.value in {"cancelled", "completed"}


def test_aircrack_output_parser_masks_secret() -> None:
    recovered, masked, detail = parse_aircrack_output(
        "KEY FOUND! [ example-passphrase-123 ]\n"
    )
    assert recovered
    assert "example-passphrase-123" not in masked
    assert "*" in masked
    assert detail



def test_aircrack_secret_parser_returns_value_for_terminal() -> None:
    from surge_signal.audit.password_audit import parse_aircrack_secret

    found, secret, detail = parse_aircrack_secret("KEY FOUND! [ Correct-Lab-Key-9 ]")
    assert found
    assert secret == "Correct-Lab-Key-9"
    assert detail
