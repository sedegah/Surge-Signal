"""Reporting Engine UI: PDF, HTML and structured JSON exports."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ...core.domain import human_time
from ..widgets import (
    Card,
    InfoBanner,
    KeyValueRow,
    format_bytes,
    format_number,
    make_table,
    open_path,
    set_cell,
    set_column_widths,
)
from .base import BasePage


class ReportsPage(BasePage):
    title = "Reports"
    subtitle = (
        "Generate a professional assessment report with scope, methodology, inventory, "
        "findings, evidence references and remediation guidance."
    )

    def __init__(self, service, window):
        super().__init__(service, window)
        self._build()

    def _build(self) -> None:
        self.generate_button = self.add_action("Generate reports", self.generate, primary=True)
        self.open_button = self.add_action("Open report", self.open_selected)
        self.folder_button = self.add_action("Open report folder", self.open_folder)

        self.banner = InfoBanner(
            "Reports distinguish verified findings from potential risks and observations. "
            "They are generated from the current assessment evidence at the moment the "
            "export is created."
        )
        self.content.addWidget(self.banner)

        summary = QHBoxLayout()
        summary.setSpacing(14)
        self.assessment_card = Card()
        self.assessment_card.add_title("Report subject")
        self.report_name = QLabel("No assessment selected")
        self.report_name.setProperty("role", "h1")
        self.report_name.setWordWrap(True)
        self.assessment_card.add(self.report_name)
        self.report_org = QLabel("")
        self.report_org.setProperty("role", "muted")
        self.assessment_card.add(self.report_org)
        self.report_rows = {
            "networks": KeyValueRow("Networks", "0"),
            "findings": KeyValueRow("Findings", "0"),
            "severity": KeyValueRow("Severity mix", "—"),
            "captures": KeyValueRow("Captures", "0"),
            "evidence": KeyValueRow("Evidence", "0"),
        }
        for row in self.report_rows.values():
            self.assessment_card.add(row)
        summary.addWidget(self.assessment_card, 1)

        options = Card()
        options.add_title("Export options")
        self.pdf_check = QCheckBox("PDF — professional printable report")
        self.pdf_check.setChecked(True)
        self.html_check = QCheckBox("HTML — self-contained report")
        self.html_check.setChecked(True)
        self.json_check = QCheckBox("JSON — structured findings and integration")
        self.json_check.setChecked(True)
        for box in (self.pdf_check, self.html_check, self.json_check):
            options.add(box)
        options.body.addSpacing(6)
        folder_label = QLabel("OUTPUT FOLDER")
        folder_label.setProperty("role", "tiny")
        options.add(folder_label)
        folder_row = QHBoxLayout()
        self.output_folder = QLabel("")
        self.output_folder.setProperty("role", "small")
        self.output_folder.setWordWrap(True)
        folder_row.addWidget(self.output_folder, 1)
        choose = QPushButton("Change")
        choose.setProperty("variant", "ghost")
        choose.clicked.connect(self.choose_folder)
        folder_row.addWidget(choose)
        options.body.addLayout(folder_row)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        options.add(self.progress)
        self.progress_label = QLabel("")
        self.progress_label.setProperty("role", "small")
        options.add(self.progress_label)
        summary.addWidget(options, 1)
        self.content.addLayout(summary)

        history = Card()
        history.add_title("Generated reports", "Stored locally under the assessment record")
        self.table = make_table(["Format", "Generated", "Size", "File"], stretch_column=3)
        set_column_widths(self.table, {0: 80, 1: 175, 2: 90})
        self.table.itemSelectionChanged.connect(self._selection_changed)
        history.add(self.table)
        self.content.addWidget(history, 1)

    def refresh(self) -> None:
        assessment = self.current_assessment()
        self.generate_button.setEnabled(assessment is not None)
        self.open_button.setEnabled(False)
        self.folder_button.setEnabled(assessment is not None)
        output = self.service.settings.get("report_output_dir", "") or str(self.service.paths.reports)
        self.output_folder.setText(output)
        if not assessment:
            self.report_name.setText("No assessment selected")
            self.report_org.setText("Create an assessment to generate reports.")
            for row in self.report_rows.values():
                row.set_value("—")
            self.table.setRowCount(0)
            return
        counts = self.service.db.finding_counts(assessment.id)
        self.report_name.setText(assessment.name)
        self.report_org.setText(f"{assessment.organisation or 'No organisation'} · {assessment.id}")
        self.report_rows["networks"].set_value(format_number(self.service.db.network_count(assessment.id)))
        self.report_rows["findings"].set_value(format_number(sum(counts.values())))
        self.report_rows["severity"].set_value(
            " · ".join(f"{key[:1].upper()}{counts[key]}" for key in ("critical", "high", "medium", "low", "info"))
        )
        self.report_rows["captures"].set_value(format_number(len(self.service.db.list_captures(assessment.id))))
        self.report_rows["evidence"].set_value(format_number(len(self.service.db.list_evidence(assessment.id))))
        self._fill_history(assessment.id)

    def _fill_history(self, assessment_id: str) -> None:
        reports = self.service.db.list_reports(assessment_id)
        self.table.clearSpans()
        self.table.setRowCount(0)
        for row, report in enumerate(reports):
            self.table.insertRow(row)
            set_cell(self.table, row, 0, report["format"].upper())
            set_cell(self.table, row, 1, human_time(report["generated_at"]), colour="#a8a8a8")
            path = Path(report["path"])
            try:
                size = format_bytes(path.stat().st_size)
            except OSError:
                size = "missing"
            set_cell(self.table, row, 2, size)
            set_cell(self.table, row, 3, report["path"], tooltip=report["sha256"], mono=True)
        if not reports:
            self.table.setRowCount(1)
            set_cell(self.table, 0, 0, "No reports generated for this assessment.", colour="#a8a8a8")
            self.table.setSpan(0, 0, 1, 4)
        self.open_button.setEnabled(False)

    def _selection_changed(self) -> None:
        self.open_button.setEnabled(bool(self.table.selectionModel().selectedRows()))

    def choose_folder(self) -> None:
        folder = QFileDialog.getExistingDirectory(
            self, "Select report output folder", self.output_folder.text()
        )
        if folder:
            self.service.settings.set("report_output_dir", folder)
            self.output_folder.setText(folder)

    def generate(self) -> None:
        assessment = self.require_assessment()
        if not assessment:
            return
        formats = []
        if self.pdf_check.isChecked():
            formats.append("pdf")
        if self.html_check.isChecked():
            formats.append("html")
        if self.json_check.isChecked():
            formats.append("json")
        if not formats:
            QMessageBox.information(self, "Select a format", "Choose at least one report format.")
            return
        output = Path(self.output_folder.text())
        try:
            output.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            QMessageBox.warning(self, "Output folder unavailable", str(exc))
            return
        self.service.settings.set("report_output_dir", str(output))
        self.generate_button.setEnabled(False)
        self.generate_button.setText("Generating…")
        self.progress.setRange(0, 0)
        self.progress_label.setText("Rendering report(s)…")
        self.notify("Generating assessment report…")

        def done(items) -> None:
            self.generate_button.setEnabled(True)
            self.generate_button.setText("Generate reports")
            self.progress.setRange(0, 1)
            self.progress.setValue(1)
            self.progress_label.setText(f"{len(items)} report(s) generated")
            self.refresh()
            names = ", ".join(Path(item.path).name for item in items)
            self.notify(f"Reports generated: {names}", "success")
            QMessageBox.information(
                self,
                "Reports generated",
                "The following report(s) were created:\n\n" + "\n".join(item.path for item in items),
            )

        def failed(message: str) -> None:
            self.generate_button.setEnabled(True)
            self.generate_button.setText("Generate reports")
            self.progress.setRange(0, 1)
            self.progress.setValue(0)
            self.progress_label.setText("")
            self.notify(f"Report generation failed: {message}", "error")
            QMessageBox.warning(self, "Report generation failed", message)

        self.tasks.start(
            lambda: self.service.generate_reports(assessment.id, formats, output),
            on_done=done,
            on_error=failed,
        )

    def open_selected(self) -> None:
        assessment = self.current_assessment()
        if not assessment:
            return
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        reports = self.service.db.list_reports(assessment.id)
        row = rows[0].row()
        if row >= len(reports):
            return
        path = Path(reports[row]["path"])
        if not path.exists():
            QMessageBox.warning(self, "Report missing", f"The report file is missing:\n{path}")
            return
        open_path(path)

    def open_folder(self) -> None:
        path = Path(self.output_folder.text())
        path.mkdir(parents=True, exist_ok=True)
        open_path(path)

