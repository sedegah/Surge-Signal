from __future__ import annotations

import json
from pathlib import Path

from surge_signal.core.domain import AssessmentStatus, NetworkObservation
from tests.helpers import AP, PASSPHRASE, SSID, make_handshake_capture


def _prepare(service, tmp_path):
    assessment = service.create_assessment(
        name="Reporting Lab",
        organisation="Surge Lab",
        scope="Authorised reporting test",
        permitted_targets=[AP],
        tester="Tester",
        status=AssessmentStatus.ACTIVE,
    )
    service.db.upsert_networks(
        assessment.id,
        [
            NetworkObservation(
                ssid=SSID,
                bssid=AP,
                signal_dbm=-40,
                channel=6,
                authentication="WPA2-Personal",
                encryption="CCMP",
                pmf="Disabled",
                wps="Enabled",
            )
        ],
    )
    service.inspect_assessment(assessment.id)
    capture = service.import_capture(
        assessment.id, make_handshake_capture(tmp_path / "handshake.pcap")
    )
    wordlist = service.wordlists.create_custom_list("report-test", [PASSPHRASE])
    prepared = service.prepare_wordlist([int(wordlist["id"])])
    service.run_local_audit(
        assessment.id,
        capture.id,
        prepared.path,
        bssid=AP,
        confirmed=True,
        lab_attestation=True,
        max_candidates=10,
    )
    return assessment


def test_html_pdf_json_reports(service, tmp_path) -> None:
    assessment = _prepare(service, tmp_path)
    output = tmp_path / "reports"
    generated = service.generate_reports(assessment.id, ["html", "json", "pdf"], output)
    assert {item.format for item in generated} == {"html", "json", "pdf"}
    for item in generated:
        path = Path(item.path)
        assert path.is_file()
        assert path.stat().st_size > 1000
        assert len(item.sha256) == 64
    html_text = next(Path(item.path).read_text(encoding="utf-8") for item in generated if item.format == "html")
    assert "Potential risk" in html_text or "POTENTIAL" in html_text
    assert "Authorised" in html_text
    assert "WPA2" in html_text
    assert PASSPHRASE not in html_text
    json_text = next(Path(item.path).read_text(encoding="utf-8") for item in generated if item.format == "json")
    payload = json.loads(json_text)
    assert payload["schema"] == "surge-signal.report.v1"
    assert payload["assessment"]["id"] == assessment.id
    assert payload["findings"]
    assert payload["risk_classification"]["potential"] >= 1
    assert PASSPHRASE not in json_text
    assert payload["password_audits"][0]["masked_secret"]


def test_report_pdf_magic(service, tmp_path) -> None:
    assessment = _prepare(service, tmp_path)
    generated = service.generate_reports(assessment.id, ["pdf"], tmp_path / "pdf")
    data = Path(generated[0].path).read_bytes()
    assert data.startswith(b"%PDF")

