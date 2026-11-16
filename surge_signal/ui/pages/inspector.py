"""Network Inspector: explainable wireless configuration findings."""

from __future__ import annotations

import html

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ...core.domain import Finding, FindingStatus, human_time
from ..widgets import (
    KeyValueRow,
    format_number,
    make_table,
    set_cell,
    set_chip_cell,
    set_column_widths,
    severity_colour,
)
from .base import BasePage


class InspectorPage(BasePage):
    title = "Network Inspector"
    subtitle = (
        "Explainable evaluation of advertised authentication, encryption, PMF and WPS "
        "configuration. Findings are potential risks until reviewed."
    )

    def __init__(self, service, window):
        super().__init__(service, window)
        self._findings: list[Finding] = []
        self._selected_id: int | None = None
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(220)
        self._search_timer.timeout.connect(self.refresh)
        self._build()

    def _build(self) -> None:
        self.run_button = self.add_action("Run inspection", self.run_inspection, primary=True)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(9)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search findings, SSID or BSSID…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(lambda _text: self._search_timer.start())
        toolbar.addWidget(self.search, 1)
        self.severity_filter = QComboBox()
        self.severity_filter.addItem("All severities", "")
        for severity in ("critical", "high", "medium", "low", "info"):
            self.severity_filter.addItem(severity.capitalize(), severity)
        self.severity_filter.currentIndexChanged.connect(lambda _index: self.refresh())
        toolbar.addWidget(self.severity_filter)
        self.count_label = QLabel("0 findings")
        self.count_label.setProperty("role", "small")
        toolbar.addWidget(self.count_label)
        self.content.addLayout(toolbar)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.table = make_table(
            ["Severity", "Status", "Finding", "Network", "BSSID", "Category", "Conf."],
            stretch_column=2,
        )
        set_column_widths(
            self.table, {0: 82, 1: 105, 3: 125, 4: 150, 5: 125, 6: 70}
        )
        self.table.itemSelectionChanged.connect(self._selection_changed)
        splitter.addWidget(self.table)

        self.detail = QWidget()
        self.detail.setObjectName("Card")
        detail_layout = QVBoxLayout(self.detail)
        detail_layout.setContentsMargins(18, 15, 18, 15)
        detail_layout.setSpacing(8)
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(2)
        self.detail_title = QLabel("Select a finding")
        self.detail_title.setProperty("role", "h2")
        self.detail_title.setWordWrap(True)
        title_box.addWidget(self.detail_title)
        self.detail_meta = QLabel(
            "Run an inspection, then choose a finding to read its technical rationale."
        )
        self.detail_meta.setProperty("role", "small")
        self.detail_meta.setWordWrap(True)
        title_box.addWidget(self.detail_meta)
        header.addLayout(title_box, 1)
        self.verify_button = QPushButton("Mark verified")
        self.verify_button.setEnabled(False)
        self.verify_button.clicked.connect(lambda: self._set_status(FindingStatus.VERIFIED))
        self.observe_button = QPushButton("Mark observation")
        self.observe_button.setEnabled(False)
        self.observe_button.clicked.connect(lambda: self._set_status(FindingStatus.OBSERVATION))
        header.addWidget(self.verify_button)
        header.addWidget(self.observe_button)
        detail_layout.addLayout(header)
        self.detail_rows = {
            "network": KeyValueRow("Affected network", "—"),
            "rule": KeyValueRow("Rule / confidence", "—"),
            "created": KeyValueRow("Recorded", "—"),
        }
        for row in self.detail_rows.values():
            detail_layout.addWidget(row)
        self.detail_text = QTextBrowser()
        self.detail_text.setOpenExternalLinks(False)
        self.detail_text.setFrameShape(QFrame.Shape.NoFrame)
        self.detail_text.setStyleSheet(
            "QTextBrowser{background:transparent;border:none;color:#d8d8d8;font-size:12px;}"
        )
        detail_layout.addWidget(self.detail_text, 1)
        splitter.addWidget(self.detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([380, 300])
        self.content.addWidget(splitter, 1)

    def refresh(self) -> None:
        assessment = self.current_assessment()
        self.run_button.setEnabled(assessment is not None)
        if not assessment:
            self._findings = []
            self.table.clearSpans()
            self.table.setRowCount(1)
            set_cell(self.table, 0, 0, "Create an assessment before inspecting networks.", colour="#a8a8a8")
            self.table.setSpan(0, 0, 1, 7)
            self.count_label.setText("0 findings")
            return
        self._findings = self.service.db.list_findings(
            assessment.id,
            severity=self.severity_filter.currentData() or "",
            search=self.search.text().strip(),
        )
        self.table.clearSpans()
        self.table.setRowCount(0)
        for row, finding in enumerate(self._findings):
            self.table.insertRow(row)
            set_chip_cell(
                self.table,
                row,
                0,
                finding.severity.value.upper(),
                severity_colour(finding.severity.value),
            )
            status_colour = {
                "verified": "#4ade80",
                "potential": "#f5c451",
                "observation": "#a8a8a8",
            }.get(finding.status.value, "#a8a8a8")
            set_chip_cell(self.table, row, 1, finding.status.value.upper(), status_colour)
            set_cell(self.table, row, 2, finding.title, tooltip=finding.explanation)
            set_cell(self.table, row, 3, finding.ssid or "<hidden>")
            set_cell(self.table, row, 4, finding.bssid, mono=True)
            set_cell(self.table, row, 5, finding.category)
            set_cell(self.table, row, 6, finding.confidence)
        self.count_label.setText(f"{format_number(len(self._findings))} findings")
        if not self._findings:
            self.table.setRowCount(1)
            set_cell(
                self.table,
                0,
                0,
                "No findings for this view. Run an inspection to evaluate the "
                "observed network inventory.",
                colour="#a8a8a8",
            )
            self.table.setSpan(0, 0, 1, 7)
            self._clear_detail()
        elif self._selected_id is not None:
            for row, finding in enumerate(self._findings):
                if finding.id == self._selected_id:
                    self.table.selectRow(row)
                    break
        else:
            if self.table.currentRow() < 0:
                self.table.selectRow(0)

    def _selection_changed(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            self._clear_detail()
            return
        row = rows[0].row()
        if row >= len(self._findings):
            return
        finding = self._findings[row]
        self._selected_id = finding.id
        self.detail_title.setText(finding.title)
        self.detail_meta.setText(
            f"{finding.severity.value.upper()}  ·  {finding.status.value.title()}  ·  "
            f"{finding.category}"
        )
        self.detail_rows["network"].set_value(
            f"{finding.ssid or '<hidden>'}  ·  {finding.bssid}"
        )
        self.detail_rows["rule"].set_value(f"{finding.rule_id}  ·  {finding.confidence} confidence")
        self.detail_rows["created"].set_value(human_time(finding.created_at))
        self.verify_button.setEnabled(True)
        self.observe_button.setEnabled(True)
        self.detail_text.setHtml(
            "<style>"
            "h3{color:#ffffff;font-size:12px;margin:10px 0 3px 0;}"
            "p{color:#d8d8d8;line-height:1.55;margin:0 0 6px 0;}"
            ".label{color:#a8a8a8;font-size:10px;text-transform:uppercase;letter-spacing:1px;}"
            ".evidence{background:#333337;border-left:2px solid #f26a21;padding:8px 10px;color:#c8c8c8;}"
            "</style>"
            "<div class='label'>Technical explanation</div>"
            f"<p>{html.escape(finding.explanation)}</p>"
            "<div class='label'>Potential implications</div>"
            f"<p>{html.escape(finding.impact)}</p>"
            "<div class='label'>Recommended remediation</div>"
            f"<p>{html.escape(finding.remediation)}</p>"
            "<div class='label'>Evidence</div>"
            f"<p class='evidence'>{html.escape(finding.evidence)}</p>"
        )

    def _clear_detail(self) -> None:
        self._selected_id = None
        self.detail_title.setText("Select a finding")
        self.detail_meta.setText(
            "Run an inspection, then choose a finding to read its technical rationale."
        )
        for row in self.detail_rows.values():
            row.set_value("—")
        self.detail_text.clear()
        self.verify_button.setEnabled(False)
        self.observe_button.setEnabled(False)

    def run_inspection(self) -> None:
        assessment = self.require_assessment()
        if not assessment:
            return
        if self.service.db.list_networks(assessment.id) == []:
            QMessageBox.information(
                self,
                "No networks to inspect",
                "Run a wireless scan or import an authorised inventory first.",
            )
            return
        if self.service.db.list_findings(assessment.id):
            answer = QMessageBox.question(
                self,
                "Rebuild findings?",
                "Inspecting will rebuild findings for every observed network. "
                "Existing review statuses (verified / observation) will be replaced.\n\n"
                "Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.run_button.setEnabled(False)
        self.run_button.setText("Inspecting…")
        self.notify("Evaluating wireless security configurations…")

        def done(findings) -> None:
            self.run_button.setEnabled(True)
            self.run_button.setText("Run inspection")
            self.refresh()
            self.notify(
                f"Inspection complete: {len(findings)} finding(s) recorded.",
                "success",
            )

        def failed(message: str) -> None:
            self.run_button.setEnabled(True)
            self.run_button.setText("Run inspection")
            self.notify(f"Inspection failed: {message}", "error")
            QMessageBox.warning(self, "Inspection failed", message)

        self.tasks.start(
            lambda: self.service.inspect_assessment(assessment.id),
            on_done=done,
            on_error=failed,
        )

    def _set_status(self, status: FindingStatus) -> None:
        if not self._selected_id:
            return
        try:
            self.service.set_finding_status(self._selected_id, status)
        except Exception as exc:                
            QMessageBox.warning(self, "Review update failed", str(exc))
            return
        self.notify(f"Finding marked {status.value}.", "success")
        self.refresh()

