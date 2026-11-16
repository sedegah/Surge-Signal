"""Capture Manager: authorised import, integrity and 802.11 metadata."""

from __future__ import annotations

import html
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ...core.domain import Capture, human_time
from ..live_capture import KaliCaptureDialog
from ..widgets import (
    KeyValueRow,
    format_bytes,
    format_number,
    make_table,
    open_path,
    set_cell,
    set_chip_cell,
    set_column_widths,
)
from .base import BasePage


class CapturesPage(BasePage):
    title = "Capture Manager"
    subtitle = (
        "Import authorised PCAP/PCAPNG evidence. SURGE Signal validates container "
        "integrity, hashes the file and extracts beacon and WPA handshake metadata."
    )

    def __init__(self, service, window):
        super().__init__(service, window)
        self._captures: list[Capture] = []
        self._selected_id: int | None = None
        self._build()

    def _build(self) -> None:
        self.import_button = self.add_action("Import capture", self.import_capture, primary=True)
        self.live_button = self.add_action("Live capture (Kali)", self.live_capture)
        self.reanalyze_button = self.add_action("Re-analyse", self.reanalyze)
        self.export_button = self.add_action("Export evidence", self.export_capture)
        self.folder_button = self.add_action("Open capture folder", self.open_folder)

        toolbar = QHBoxLayout()
        self.count_label = QLabel("0 captures")
        self.count_label.setProperty("role", "small")
        toolbar.addWidget(self.count_label)
        toolbar.addStretch(1)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedWidth(150)
        self.progress.setVisible(False)
        toolbar.addWidget(self.progress)
        self.content.addLayout(toolbar)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = make_table(
            ["File", "Format", "Packets", "BSSID", "SSID", "Integrity", "Imported"],
            stretch_column=0,
        )
        set_column_widths(
            self.table, {1: 85, 2: 85, 3: 155, 4: 155, 5: 105, 6: 145}
        )
        self.table.itemSelectionChanged.connect(self._selection_changed)
        splitter.addWidget(self.table)

        self.detail = QWidget()
        self.detail.setObjectName("Card")
        detail_layout = QVBoxLayout(self.detail)
        detail_layout.setContentsMargins(18, 15, 18, 15)
        detail_layout.setSpacing(7)
        header = QHBoxLayout()
        self.detail_title = QLabel("Select a capture")
        self.detail_title.setProperty("role", "h2")
        self.detail_title.setWordWrap(True)
        header.addWidget(self.detail_title, 1)
        self.handshake_chip = QLabel("")
        header.addWidget(self.handshake_chip)
        detail_layout.addLayout(header)
        self.detail_meta = QLabel("Imported captures appear here with cryptographic integrity metadata.")
        self.detail_meta.setProperty("role", "small")
        self.detail_meta.setWordWrap(True)
        detail_layout.addWidget(self.detail_meta)
        row_box = QHBoxLayout()
        left = QVBoxLayout()
        right = QVBoxLayout()
        self.detail_rows = {
            "bssid": KeyValueRow("BSSID / SSID"),
            "security": KeyValueRow("Security"),
            "radio": KeyValueRow("Channel / band"),
            "packets": KeyValueRow("Packets"),
            "time": KeyValueRow("Capture window"),
            "size": KeyValueRow("Size / format"),
            "sha": KeyValueRow("SHA-256"),
        }
        for key, row in self.detail_rows.items():
            (left if key in {"bssid", "security", "radio", "packets"} else right).addWidget(row)
        row_box.addLayout(left, 1)
        row_box.addLayout(right, 1)
        detail_layout.addLayout(row_box)
        self.notes = QTextBrowser()
        self.notes.setOpenExternalLinks(False)
        self.notes.setFrameShape(QFrame.Shape.NoFrame)
        self.notes.setMinimumHeight(100)
        self.notes.setStyleSheet(
            "QTextBrowser{background:transparent;border:none;color:#c8c8c8;font-size:11px;}"
        )
        detail_layout.addWidget(self.notes, 1)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([350, 330])
        self.content.addWidget(splitter, 1)

    def refresh(self) -> None:
        assessment = self.current_assessment()
        self.import_button.setEnabled(assessment is not None)
        self.live_button.setEnabled(assessment is not None)
        if not assessment:
            self._captures = []
            self.table.clearSpans()
            self.table.setRowCount(1)
            set_cell(self.table, 0, 0, "Create an assessment before importing a capture.", colour="#a8a8a8")
            self.table.setSpan(0, 0, 1, 7)
            self.count_label.setText("0 captures")
            self.reanalyze_button.setEnabled(False)
            self.export_button.setEnabled(False)
            self.folder_button.setEnabled(False)
            return
        self._captures = self.service.db.list_captures(assessment.id)
        self.folder_button.setEnabled(True)
        self.table.clearSpans()
        self.table.setRowCount(0)
        for row, capture in enumerate(self._captures):
            self.table.insertRow(row)
            set_cell(self.table, row, 0, capture.filename, tooltip=capture.stored_path)
            set_cell(self.table, row, 1, capture.format.upper())
            set_cell(self.table, row, 2, format_number(capture.packet_count))
            set_cell(self.table, row, 3, capture.bssid or "—", mono=True)
            set_cell(self.table, row, 4, capture.ssid or "—")
            colour = {"valid": "#4ade80", "truncated": "#f5c451", "invalid": "#ff6b7a"}.get(
                capture.integrity, "#a8a8a8"
            )
            set_chip_cell(self.table, row, 5, capture.integrity.upper(), colour)
            set_cell(self.table, row, 6, human_time(capture.imported_at), colour="#a8a8a8")
        self.count_label.setText(f"{format_number(len(self._captures))} captures")
        if not self._captures:
            self.table.setRowCount(1)
            set_cell(
                self.table,
                0,
                0,
                "No captures imported. Use Import capture to register authorised evidence.",
                colour="#a8a8a8",
            )
            self.table.setSpan(0, 0, 1, 7)
            self._clear_detail()
        elif self._selected_id:
            for row, capture in enumerate(self._captures):
                if capture.id == self._selected_id:
                    self.table.selectRow(row)
                    break
        else:
            if self.table.currentRow() < 0:
                self.table.selectRow(0)
        self.reanalyze_button.setEnabled(self._selected_id is not None)
        self.export_button.setEnabled(self._selected_id is not None)

    def _selection_changed(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            self._clear_detail()
            return
        row = rows[0].row()
        if row >= len(self._captures):
            return
        capture = self._captures[row]
        self._selected_id = capture.id
        self.reanalyze_button.setEnabled(True)
        self.export_button.setEnabled(True)
        self.detail_title.setText(capture.filename)
        handshakes = capture.metadata.get("handshakes", [])
        complete = [item for item in handshakes if item.get("complete")]
        self.handshake_chip.setText(
            f"{len(complete)} complete handshake(s)" if complete else "No complete handshake"
        )
        self.handshake_chip.setStyleSheet(
            "background-color:#173328;color:#4ade80;border:1px solid #2f6b4f;"
            "border-radius:0px;padding:3px 8px;font-size:10px;font-weight:700;"
            if complete
            else "background-color:#332d18;color:#f5c451;border:1px solid #75642c;"
            "border-radius:0px;padding:3px 8px;font-size:10px;font-weight:700;"
        )
        self.detail_meta.setText(
            f"Imported {human_time(capture.imported_at)} · integrity {capture.integrity.upper()} "
            f"· link type {capture.link_type or 'unknown'}"
        )
        self.detail_rows["bssid"].set_value(
            f"{capture.bssid or '—'}\n{capture.ssid or '—'}"
        )
        self.detail_rows["security"].set_value(
            f"{capture.metadata.get('authentication') or '—'} / "
            f"{capture.metadata.get('encryption') or '—'} · PMF "
            f"{capture.metadata.get('pmf') or 'Unknown'}"
        )
        self.detail_rows["radio"].set_value(
            f"{capture.metadata.get('channel') or '—'} / not recorded"
        )
        self.detail_rows["packets"].set_value(
            f"{format_number(capture.packet_count)} · "
            f"{capture.metadata.get('beacon_count', 0)} beacons · "
            f"{capture.metadata.get('eapol_count', 0)} EAPOL"
        )
        self.detail_rows["time"].set_value(
            f"{human_time(capture.start_ts)}\n→ {human_time(capture.end_ts)}"
        )
        self.detail_rows["size"].set_value(f"{format_bytes(capture.size_bytes)} · {capture.format.upper()}")
        self.detail_rows["sha"].set_value(capture.sha256)
        notes = capture.metadata.get("notes", [])
        handshake_html = "".join(
            f"<li>{html.escape(str(item.get('ssid') or capture.ssid or '—'))} · "
            f"<span style='font-family:Consolas'>{html.escape(str(item.get('bssid') or ''))}</span> · "
            f"{'complete' if item.get('complete') else 'PMKID only'}</li>"
            for item in handshakes
        )
        self.notes.setHtml(
            "<div style='color:#a8a8a8;font-size:10px;text-transform:uppercase;'>Analysis notes</div>"
            + ("<ul>" + "".join(f"<li>{html.escape(str(note))}</li>" for note in notes) + "</ul>" if notes else "<p>No analysis notes.</p>")
            + ("<div style='color:#a8a8a8;font-size:10px;text-transform:uppercase;'>Handshakes</div><ul>" + handshake_html + "</ul>" if handshakes else "")
            + f"<p style='color:#a8a8a8'>Stored at: {html.escape(capture.stored_path)}</p>"
        )

    def _clear_detail(self) -> None:
        self._selected_id = None
        self.detail_title.setText("Select a capture")
        self.detail_meta.setText(
            "Imported captures appear here with cryptographic integrity metadata."
        )
        self.handshake_chip.setText("")
        for row in self.detail_rows.values():
            row.set_value("—")
        self.notes.clear()
        self.reanalyze_button.setEnabled(False)
        self.export_button.setEnabled(False)

    def live_capture(self) -> None:
        assessment = self.require_assessment()
        if not assessment:
            return
        existing = getattr(self, "_capture_dialog", None)
        if existing is not None and existing.isVisible():
            existing.raise_()
            existing.activateWindow()
            return
        dialog = KaliCaptureDialog(self.service, assessment, self)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        dialog.finished.connect(lambda _result: self.refresh())
        dialog.destroyed.connect(lambda: setattr(self, "_capture_dialog", None))
        self._capture_dialog = dialog
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def import_capture(self) -> None:
        assessment = self.require_assessment()
        if not assessment:
            return
        path, _filter = QFileDialog.getOpenFileName(
            self,
            "Import authorised capture",
            "",
            "Wireless captures (*.pcap *.pcapng *.cap *.gz);;All files (*)",
        )
        if not path:
            return
        answer = QMessageBox.question(
            self,
            "Confirm authorised capture",
            "Import this capture into the assessment evidence store?\n\n"
            "Only import captures obtained from networks you are authorised to assess. "
            "The file will be hashed and copied into local evidence storage.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.import_button.setEnabled(False)
        self.import_button.setText("Analysing…")
        self.progress.setVisible(True)
        self.notify("Inspecting capture container and 802.11 metadata…")

        def done(capture) -> None:
            self.import_button.setEnabled(True)
            self.import_button.setText("Import capture")
            self.progress.setVisible(False)
            self._selected_id = capture.id
            self.refresh()
            self.notify(
                f"Capture imported: {capture.packet_count:,} packets, integrity "
                f"{capture.integrity}.",
                "success" if capture.integrity == "valid" else "warn",
            )

        def failed(message: str) -> None:
            self.import_button.setEnabled(True)
            self.import_button.setText("Import capture")
            self.progress.setVisible(False)
            self.notify(f"Capture import failed: {message}", "error")
            QMessageBox.warning(self, "Capture import failed", message)

        self.tasks.start(
            lambda: self.service.import_capture(assessment.id, path),
            on_done=done,
            on_error=failed,
        )

    def reanalyze(self) -> None:
        if not self._selected_id:
            return
        capture_id = self._selected_id
        self.reanalyze_button.setEnabled(False)
        self.progress.setVisible(True)
        self.notify("Re-analysing stored capture…")

        def done(capture) -> None:
            self.reanalyze_button.setEnabled(True)
            self.progress.setVisible(False)
            self.refresh()
            self.notify("Capture metadata refreshed.", "success")

        def failed(message: str) -> None:
            self.reanalyze_button.setEnabled(True)
            self.progress.setVisible(False)
            self.notify(f"Re-analysis failed: {message}", "error")

        self.tasks.start(
            lambda: self.service.reanalyze_capture(capture_id),
            on_done=done,
            on_error=failed,
        )

    def export_capture(self) -> None:
        if not self._selected_id:
            return
        capture = next((item for item in self._captures if item.id == self._selected_id), None)
        if not capture:
            return
        path, _filter = QFileDialog.getSaveFileName(
            self,
            "Export capture evidence",
            capture.filename,
            "Capture file (*.pcap *.pcapng *.cap);;All files (*)",
        )
        if not path:
            return
        try:
            target = self.service.export_capture(capture.id, path)
            self.notify(f"Evidence exported to {target.name}.", "success")
        except Exception as exc:                
            QMessageBox.warning(self, "Export failed", str(exc))

    def open_folder(self) -> None:
        folder = self.service.settings.capture_output_dir()
        folder.mkdir(parents=True, exist_ok=True)
        open_path(folder)

