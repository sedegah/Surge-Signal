from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def qt_app(tmp_path_factory):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


def test_application_launches_without_demo_data(qt_app, tmp_path) -> None:
    from surge_signal.app import create_application

    app, window, service = create_application(tmp_path / "data", smoke_test=True)
    try:
        assert window.current_assessment() is None
        assert service.db.stats()["assessments"] == 0
        assert len(window.pages) == 10
        for key in window.pages:
            window.navigate(key)
            app.processEvents()
        assert window.windowTitle().startswith("Surge Signal")
    finally:
        window.close()
        app.processEvents()


def test_ui_loads_assessment_and_pages(qt_app, tmp_path) -> None:
    from surge_signal.app import create_application
    from surge_signal.core.domain import AssessmentStatus, NetworkObservation
    from tests.helpers import AP, SSID

    app, window, service = create_application(tmp_path / "data2", smoke_test=True)
    try:
        assessment = service.create_assessment(
            name="UI Lab",
            organisation="Lab",
            scope="Scoped",
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
                    signal_dbm=-44,
                    channel=6,
                    authentication="WPA2-Personal",
                    encryption="CCMP",
                    pmf="Disabled",
                    wps="Enabled",
                )
            ],
        )
        service.inspect_assessment(assessment.id)
        window.reload_assessments()
        for key in window.pages:
            window.navigate(key)
            app.processEvents()
        assert window.current_assessment() is not None
        assert window.current_assessment().id == assessment.id
    finally:
        window.close()
        app.processEvents()



def test_scanner_keeps_selected_network_across_refresh(qt_app, tmp_path) -> None:
    from surge_signal.app import create_application
    from surge_signal.core.domain import AssessmentStatus, NetworkObservation

    app, window, service = create_application(tmp_path / "data3", smoke_test=True)
    try:
        assessment = service.create_assessment(
            name="Selection Lab",
            organisation="Lab",
            scope="Scoped",
            permitted_targets=["AA:BB:CC:11:22:33"],
            tester="Tester",
            status=AssessmentStatus.ACTIVE,
        )
        service.db.upsert_networks(
            assessment.id,
            [
                NetworkObservation(
                    ssid=f"Network-{index}",
                    bssid=f"AA:BB:CC:11:22:{index:02X}",
                    signal_dbm=-40 - index,
                    channel=6,
                    authentication="WPA2-Personal",
                    encryption="CCMP",
                )
                for index in range(1, 5)
            ],
        )
        window.reload_assessments()
        window.navigate("scanner")
        app.processEvents()
        page = window.pages["scanner"]
        page.table.selectRow(2)
        app.processEvents()
        selected = page._selected_id
        assert selected is not None
        page.refresh()
        app.processEvents()
        assert page._selected_id == selected
        assert page.detail_title.text() == "Network-3"
    finally:
        window.close()
        app.processEvents()
