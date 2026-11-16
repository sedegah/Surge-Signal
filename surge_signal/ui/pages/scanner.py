"""Wireless Scanner: Host discovery and authorised inventory import."""

from __future__ import annotations

import csv
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ...core.branding import SOURCE_LABELS
from ...core.domain import NetworkObservation, human_time
from ..widgets import (
    EmptyState,
    InfoBanner,
    KeyValueRow,
    format_number,
    make_table,
    set_cell,
    set_chip_cell,
    set_column_widths,
    severity_colour,
)
from .base import BasePage


class ScannerPage(BasePage):
    title = "Wireless Scanner"
    subtitle = (
        "Passive wireless discovery and authorised inventory imports, with "
        "each observation labelled by its source."
    )

    def __init__(self, service, window):
        super().__init__(service, window)
        self._networks: list[NetworkObservation] = []
        self._selected_id: int | None = None
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(220)
        self._search_timer.timeout.connect(self.refresh)
        self.auto_timer = QTimer(self)
        self.auto_timer.timeout.connect(self.auto_scan)
        self._scanning = False
        self._build()

    def _build(self) -> None:
        self.scan_button = self.add_action("Scan Wi-Fi", lambda: self.scan(), primary=True)
        self.more_button = QToolButton()
        self.more_button.setText("More")
        self.more_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        more_menu = QMenu(self.more_button)
        self.import_action = QAction("Import inventory", self)
        self.import_action.triggered.connect(self.import_inventory)
        self.export_action = QAction("Export CSV", self)
        self.export_action.triggered.connect(self.export_csv)
        more_menu.addAction(self.import_action)
        more_menu.addAction(self.export_action)
        self.more_button.setMenu(more_menu)
        self.actions.addWidget(self.more_button)

        self.banner = InfoBanner(
            "Host discovery reports nearby networks using the client Wi-Fi adapter. "
            "It is not monitor mode. Kali research observations and imported inventories "
            "are retained with a separate source label.",
        )
        self.content.addWidget(self.banner)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(9)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search SSID or BSSID…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(lambda _text: self._search_timer.start())
        toolbar.addWidget(self.search, 1)
        self.source_filter = QComboBox()
        self.source_filter.addItem("All sources", "")
        self.source_filter.addItem("Host discovery", "windows")
        self.source_filter.addItem("Kali research", "kali")
        self.source_filter.addItem("Imported data", "import")
        self.source_filter.currentIndexChanged.connect(lambda _index: self.refresh())
        toolbar.addWidget(self.source_filter)
        self.auto_check = QCheckBox("Auto-refresh")
        self.auto_check.setToolTip(
            "Passively refresh nearby Wi-Fi every 45 seconds while this page is open."
        )
        self.auto_check.setChecked(
            self.service.settings.get_bool("auto_scan_on_open", True)
        )
        self.auto_check.toggled.connect(self._auto_toggled)
        toolbar.addWidget(self.auto_check)
        self.count_label = QLabel("0 networks")
        self.count_label.setProperty("role", "small")
        toolbar.addWidget(self.count_label)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedWidth(120)
        self.progress.setVisible(False)
        toolbar.addWidget(self.progress)
        self.content.addLayout(toolbar)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = make_table(
            ["SSID", "BSSID", "Signal", "Ch / band", "Security", "Source", "Last seen"],
            stretch_column=0,
        )
        set_column_widths(
            self.table, {1: 158, 2: 88, 3: 104, 4: 155, 5: 138, 6: 138}
        )
        self.table.itemSelectionChanged.connect(self._selection_changed)
        splitter.addWidget(self.table)

        self.detail = QWidget()
        detail_layout = QVBoxLayout(self.detail)
        detail_layout.setContentsMargins(16, 14, 16, 14)
        detail_layout.setSpacing(6)
        header = QHBoxLayout()
        self.detail_title = QLabel("Select a network")
        self.detail_title.setProperty("role", "h2")
        header.addWidget(self.detail_title)
        header.addStretch(1)
        self.inspect_button = QPushButton("Inspect this network")
        self.inspect_button.setEnabled(False)
        self.inspect_button.clicked.connect(self.inspect_selected)
        header.addWidget(self.inspect_button)
        detail_layout.addLayout(header)
        self.detail_sub = QLabel(
            "Choose a row to review advertised security, radio and discovery metadata."
        )
        self.detail_sub.setProperty("role", "small")
        self.detail_sub.setWordWrap(True)
        detail_layout.addWidget(self.detail_sub)
        self.detail_rows = {
            "auth": KeyValueRow("Authentication", "—"),
            "encryption": KeyValueRow("Encryption", "—"),
            "pmf": KeyValueRow("PMF", "—"),
            "wps": KeyValueRow("WPS", "—"),
            "standards": KeyValueRow("Standards", "—"),
            "seen": KeyValueRow("First / last seen", "—"),
        }
        for row in self.detail_rows.values():
            detail_layout.addWidget(row)
        self.detail.setObjectName("Card")
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([430, 230])
        self.content.addWidget(splitter, 1)

    def on_show(self) -> None:
        self.refresh()
        interval = max(20, self.service.settings.get_int("auto_scan_interval_seconds", 45))
        self.auto_timer.setInterval(interval * 1000)
        if self.auto_check.isChecked():
            self.auto_timer.start()
            QTimer.singleShot(500, self.auto_scan)
        else:
            self.auto_timer.stop()

    def hideEvent(self, event) -> None:              
        self.auto_timer.stop()
        super().hideEvent(event)

    def _auto_toggled(self, checked: bool) -> None:
        self.service.settings.set("auto_scan_on_open", checked)
        if checked:
            self.auto_timer.start()
            QTimer.singleShot(250, self.auto_scan)
        else:
            self.auto_timer.stop()

    def auto_scan(self) -> None:
        if self.window.smoke_test or self._scanning:
            return
        if self.current_assessment() is None:
            return
        if not self.auto_check.isChecked():
            return
        self.scan(silent=True)

    def refresh(self) -> None:
        assessment = self.current_assessment()
        enabled = assessment is not None
        self.scan_button.setEnabled(enabled and not self.progress.isVisible())
        self.import_action.setEnabled(enabled)
        if not assessment:
            self._networks = []
            self.table.setRowCount(1)
            set_cell(
                self.table, 0, 0, "Create an assessment to begin discovery.", colour="#a8a8a8"
            )
            self.table.setSpan(0, 0, 1, 7)
            self.count_label.setText("0 networks")
            self.export_action.setEnabled(False)
            return
        self._networks = self.service.db.list_networks(
            assessment.id,
            search=self.search.text().strip(),
            source=self.source_filter.currentData() or "",
        )
        preserve_id = self._selected_id
        self.export_action.setEnabled(bool(self._networks))
        self.table.blockSignals(True)
        try:
            self.table.clearSpans()
            self.table.setRowCount(0)
            for row, network in enumerate(self._networks):
                self.table.insertRow(row)
                set_cell(self.table, row, 0, network.display_ssid, tooltip=network.ssid)
                set_cell(self.table, row, 1, network.bssid, mono=True)
                signal_text = f"{network.signal_dbm} dBm" if network.signal_dbm is not None else "—"
                colour = (
                    "#4ade80"
                    if network.signal_dbm and network.signal_dbm >= -55
                    else "#f5c451"
                    if network.signal_dbm and network.signal_dbm >= -70
                    else "#ff8a5b"
                )
                set_cell(self.table, row, 2, signal_text, colour=colour)
                set_cell(
                    self.table,
                    row,
                    3,
                    f"{network.channel or '—'} / {network.band}",
                )
                security = network.security
                sec_colour = (
                    "#ff6b7a"
                    if network.family.value in {"open", "wep"}
                    else "#f5c451"
                    if network.family.value in {"wpa", "unknown"}
                    else "#d8d8d8"
                )
                set_cell(self.table, row, 4, security, colour=sec_colour)
                set_cell(
                    self.table,
                    row,
                    5,
                    SOURCE_LABELS.get(network.source, network.source.title()),
                )
                set_cell(
                    self.table,
                    row,
                    6,
                    human_time(network.last_seen),
                    colour="#a8a8a8",
                )
            if not self._networks:
                self.table.setRowCount(1)
                set_cell(
                    self.table,
                    0,
                    0,
                    "No networks recorded for this view.",
                    colour="#a8a8a8",
                )
                self.table.setSpan(0, 0, 1, 7)
        finally:
            self.table.blockSignals(False)
        self.count_label.setText(f"{format_number(len(self._networks))} networks")
        if not self._networks:
            self._clear_detail()
            return
        target_row = None
        if preserve_id is not None:
            target_row = next(
                (row for row, network in enumerate(self._networks) if network.id == preserve_id),
                None,
            )
        if target_row is None and self._selected_id is None:
            target_row = 0
        if target_row is not None:
            self.table.selectRow(target_row)
            self.table.scrollToItem(self.table.item(target_row, 0))
        elif preserve_id is not None and self.table.currentRow() >= 0:
                                                                     
            self._clear_detail()

    def _selection_changed(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            self._clear_detail()
            return
        row = rows[0].row()
        if row >= len(self._networks):
            return
        network = self._networks[row]
        self._selected_id = network.id
        self.detail_title.setText(network.display_ssid)
        self.detail_sub.setText(f"{network.bssid}  ·  {network.security}")
        self.detail_rows["auth"].set_value(network.authentication or "Unknown")
        self.detail_rows["encryption"].set_value(network.encryption or "Unknown")
        self.detail_rows["pmf"].set_value(network.pmf)
        self.detail_rows["wps"].set_value(network.wps)
        self.detail_rows["standards"].set_value(network.standards or "Not reported")
        self.detail_rows["seen"].set_value(
            f"{human_time(network.first_seen)}  →  {human_time(network.last_seen)}"
        )
        self.inspect_button.setEnabled(True)

    def _clear_detail(self) -> None:
        self._selected_id = None
        self.detail_title.setText("Select a network")
        self.detail_sub.setText(
            "Choose a row to review advertised security, radio and discovery metadata."
        )
        for row in self.detail_rows.values():
            row.set_value("—")
        self.inspect_button.setEnabled(False)

    def scan(self, silent: bool = False) -> None:
        assessment = self.require_assessment()
        if not assessment:
            return
        if self._scanning:
            return
        self._scanning = True
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Scanning…")
        self.progress.setVisible(True)
        if not silent:
            self.notify("Scanning nearby wireless networks through Host discovery…")

        def done(result) -> None:
            self._scanning = False
            self.progress.setVisible(False)
            self.scan_button.setEnabled(True)
            self.scan_button.setText("Scan Wi-Fi")
            self.refresh()
            if result.networks:
                self.notify(
                    f"Discovery complete: {len(result.networks)} network(s) recorded.",
                    "success",
                )
            else:
                self.notify(
                    result.warnings[0] if result.warnings else "No networks were discovered.",
                    "warn",
                )
            if result.warnings and not silent:
                QMessageBox.information(
                    self,
                    "Discovery notes",
                    "\n\n".join(result.warnings),
                )

        def failed(message: str) -> None:
            self._scanning = False
            self.progress.setVisible(False)
            self.scan_button.setEnabled(True)
            self.scan_button.setText("Scan Wi-Fi")
            self.notify(f"Discovery failed: {message}", "error")
            if not silent:
                QMessageBox.warning(self, "Discovery failed", message)

        self.tasks.start(
            lambda: self.service.scan_windows(assessment.id),
            on_done=done,
            on_error=failed,
        )

    def import_inventory(self) -> None:
        assessment = self.require_assessment()
        if not assessment:
            return
        path, _filter = QFileDialog.getOpenFileName(
            self, "Import network inventory", "", "JSON inventory (*.json);;All files (*)"
        )
        if not path:
            return
        self.import_action.setEnabled(False)

        def done(summary) -> None:
            self.import_action.setEnabled(True)
            self.refresh()
            message = (
                f"Imported {summary.imported} network(s); {summary.skipped} skipped."
            )
            if summary.errors:
                message += "\n\n" + "\n".join(summary.errors[:8])
            self.notify(message.splitlines()[0], "success" if summary.imported else "warn")
            QMessageBox.information(self, "Inventory import", message)

        def failed(message: str) -> None:
            self.import_action.setEnabled(True)
            self.notify(f"Import failed: {message}", "error")
            QMessageBox.warning(self, "Import failed", message)

        self.tasks.start(
            lambda: self.service.import_networks(assessment.id, path),
            on_done=done,
            on_error=failed,
        )

    def export_csv(self) -> None:
        if not self._networks:
            return
        assessment = self.current_assessment()
        path, _filter = QFileDialog.getSaveFileName(
            self,
            "Export network inventory",
            f"{assessment.id if assessment else 'surge'}-networks.csv",
            "CSV (*.csv)",
        )
        if not path:
            return
        try:
            with Path(path).open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(
                    [
                        "ssid",
                        "bssid",
                        "signal_dbm",
                        "channel",
                        "band",
                        "standards",
                        "authentication",
                        "encryption",
                        "pmf",
                        "wps",
                        "source",
                        "first_seen",
                        "last_seen",
                    ]
                )
                for network in self._networks:
                    writer.writerow(
                        [
                            network.ssid,
                            network.bssid,
                            network.signal_dbm,
                            network.channel,
                            network.band,
                            network.standards,
                            network.authentication,
                            network.encryption,
                            network.pmf,
                            network.wps,
                            network.source,
                            network.first_seen,
                            network.last_seen,
                        ]
                    )
            self.notify(f"Inventory exported to {Path(path).name}.", "success")
        except OSError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))

    def inspect_selected(self) -> None:
        assessment = self.current_assessment()
        if not assessment or not self._selected_id:
            return
        try:
            self.service.inspect_assessment(assessment.id, self._selected_id)
        except Exception as exc:                
            QMessageBox.warning(self, "Inspection failed", str(exc))
            return
        self.notify("Network configuration inspected; findings recorded.", "success")
        self.window.navigate("inspector")

