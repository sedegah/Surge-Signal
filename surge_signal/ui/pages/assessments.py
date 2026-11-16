"""Assessments workspace: scope, evidence and audit trail."""

from __future__ import annotations

import html
from pathlib import Path

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QAbstractItemView,
)

from ...core.domain import Assessment, AssessmentStatus, human_time
from ...core.services import SurgeError
from ..widgets import (
    Card,
    Chip,
    EmptyState,
    InfoBanner,
    KeyValueRow,
    format_bytes,
    make_table,
    open_path,
    set_cell,
    set_chip_cell,
    set_column_widths,
)
from .base import BasePage


class AssessmentDialog(QDialog):
    def __init__(self, parent: QWidget | None = None, assessment: Assessment | None = None):
        super().__init__(parent)
        self.assessment = assessment
        self.setWindowTitle("Edit assessment" if assessment else "Create assessment")
        self.setModal(True)
        self.setMinimumWidth(620)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(11)
        title = QLabel("Assessment workspace")
        title.setProperty("role", "h2")
        layout.addWidget(title)
        note = QLabel(
            "Define the authorised scope before discovery, capture import or password "
            "auditing. BSSIDs listed here are the only targets the auditor will accept."
        )
        note.setProperty("role", "small")
        note.setWordWrap(True)
        layout.addWidget(note)
        form = QFormLayout()
        form.setSpacing(9)
        self.name = QLineEdit(assessment.name if assessment else "")
        self.name.setPlaceholderText("e.g. Lab wireless assessment — November")
        self.organisation = QLineEdit(assessment.organisation if assessment else "")
        self.organisation.setPlaceholderText("Authorising organisation or laboratory")
        self.tester = QLineEdit(assessment.tester if assessment else "")
        self.tester.setPlaceholderText("Assigned tester")
        self.scope = QTextEdit()
        self.scope.setFixedHeight(76)
        self.scope.setPlaceholderText("Scope statement, authorisation reference and exclusions")
        if assessment:
            self.scope.setPlainText(assessment.scope)
        self.targets = QTextEdit()
        self.targets.setFixedHeight(88)
        self.targets.setPlaceholderText("One BSSID or SSID per line\nAA:BB:CC:DD:EE:FF\nLab-Network")
        if assessment:
            self.targets.setPlainText("\n".join(assessment.permitted_targets))
        self.status = QComboBox()
        for status in AssessmentStatus:
            self.status.addItem(status.value.title(), status.value)
        if assessment:
            index = self.status.findData(assessment.status.value)
            if index >= 0:
                self.status.setCurrentIndex(index)
        date_row = QHBoxLayout()
        self.start_date = QLineEdit(assessment.start_date if assessment else "")
        self.start_date.setPlaceholderText("YYYY-MM-DD")
        self.end_date = QLineEdit(assessment.end_date if assessment else "")
        self.end_date.setPlaceholderText("YYYY-MM-DD (optional)")
        date_row.addWidget(self.start_date)
        date_row.addWidget(QLabel("to"))
        date_row.addWidget(self.end_date)
        date_holder = QWidget()
        date_holder.setLayout(date_row)
        self.notes = QTextEdit()
        self.notes.setFixedHeight(70)
        self.notes.setPlaceholderText("Internal notes; do not store credentials")
        if assessment:
            self.notes.setPlainText(assessment.notes)
        form.addRow("Name *", self.name)
        form.addRow("Organisation", self.organisation)
        form.addRow("Tester", self.tester)
        form.addRow("Status", self.status)
        form.addRow("Dates", date_holder)
        form.addRow("Scope statement", self.scope)
        form.addRow("Permitted targets", self.targets)
        form.addRow("Notes", self.notes)
        layout.addLayout(form)
        warning = QLabel(
            "Only assess networks you own or have explicit written authorisation to "
            "test. Active disruptive testing is excluded from this release."
        )
        warning.setProperty("role", "warning")
        warning.setWordWrap(True)
        layout.addWidget(warning)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Save
        )
        buttons.button(QDialogButtonBox.StandardButton.Save).setProperty("variant", "primary")
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self._accept)
        layout.addWidget(buttons)

    def _accept(self) -> None:
        if not self.name.text().strip():
            QMessageBox.warning(self, "Name required", "Enter an assessment name.")
            return
        for value in (self.start_date.text().strip(), self.end_date.text().strip()):
            if value and len(value) != 10:
                QMessageBox.warning(
                    self, "Invalid date", "Use ISO dates in the form YYYY-MM-DD."
                )
                return
        self.accept()

    def values(self) -> dict:
        return {
            "name": self.name.text().strip(),
            "organisation": self.organisation.text().strip(),
            "tester": self.tester.text().strip(),
            "scope": self.scope.toPlainText().strip(),
            "targets": [line.strip() for line in self.targets.toPlainText().splitlines() if line.strip()],
            "status": AssessmentStatus(self.status.currentData()),
            "start_date": self.start_date.text().strip(),
            "end_date": self.end_date.text().strip(),
            "notes": self.notes.toPlainText().strip(),
        }


class AssessmentsPage(BasePage):
    title = "Assessments"
    subtitle = (
        "Authorised assessment workspaces: scope, permitted targets, evidence, findings "
        "and a persistent audit trail."
    )
    assessments_changed = Signal(str)

    def __init__(self, service, window):
        super().__init__(service, window)
        self._assessments: list[Assessment] = []
        self._selected_id: str | None = None
        self._build()

    def _build(self) -> None:
        self.new_button = self.add_action("New assessment", self.open_create_dialog, primary=True)
        splitter = QSplitter()
        splitter.setChildrenCollapsible(False)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 8, 0)
        left_layout.setSpacing(8)
        label = QLabel("WORKSPACES")
        label.setProperty("role", "tiny")
        left_layout.addWidget(label)
        self.list = QListWidget()
        self.list.setAlternatingRowColors(False)
        self.list.setSpacing(2)
        self.list.currentRowChanged.connect(self._list_selected)
        left_layout.addWidget(self.list, 1)
        self.empty_label = QLabel("No assessments yet. Create one to begin.")
        self.empty_label.setProperty("role", "small")
        self.empty_label.setWordWrap(True)
        left_layout.addWidget(self.empty_label)
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(10, 0, 0, 0)
        self.detail_stack = QTabWidget()
        self.detail_stack.addTab(self._build_overview_tab(), "Overview")
        self.detail_stack.addTab(self._build_evidence_tab(), "Evidence")
        self.detail_stack.addTab(self._build_audit_tab(), "Audit trail")
        right_layout.addWidget(self.detail_stack)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([290, 900])
        self.content.addWidget(splitter, 1)

    def _build_overview_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        self.overview_name = QLabel("Select an assessment")
        self.overview_name.setProperty("role", "h1")
        self.overview_name.setWordWrap(True)
        title_box.addWidget(self.overview_name)
        self.overview_org = QLabel("")
        self.overview_org.setProperty("role", "muted")
        title_box.addWidget(self.overview_org)
        header.addLayout(title_box, 1)
        self.overview_status = Chip("DRAFT", "#6cb6ff")
        header.addWidget(self.overview_status)
        self.edit_button = QPushButton("Edit")
        self.edit_button.clicked.connect(self.edit_selected)
        header.addWidget(self.edit_button)
        layout.addLayout(header)
        self.overview_rows = {
            "id": KeyValueRow("Assessment ID", "—"),
            "tester": KeyValueRow("Tester", "—"),
            "dates": KeyValueRow("Dates", "—"),
            "targets": KeyValueRow("Permitted targets", "—"),
            "created": KeyValueRow("Created", "—"),
            "updated": KeyValueRow("Updated", "—"),
        }
        for row in self.overview_rows.values():
            layout.addWidget(row)
        scope_label = QLabel("SCOPE STATEMENT")
        scope_label.setProperty("role", "tiny")
        layout.addWidget(scope_label)
        self.scope_view = QLabel("—")
        self.scope_view.setWordWrap(True)
        self.scope_view.setProperty("role", "muted")
        self.scope_view.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        layout.addWidget(self.scope_view)
        targets_label = QLabel("PERMITTED TARGETS")
        targets_label.setProperty("role", "tiny")
        layout.addWidget(targets_label)
        self.targets_view = QListWidget()
        self.targets_view.setMaximumHeight(120)
        self.targets_view.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        layout.addWidget(self.targets_view)
        notes_label = QLabel("NOTES")
        notes_label.setProperty("role", "tiny")
        layout.addWidget(notes_label)
        self.notes_view = QTextBrowser()
        self.notes_view.setFrameShape(QFrame.Shape.NoFrame)
        self.notes_view.setMaximumHeight(90)
        self.notes_view.setStyleSheet(
            "QTextBrowser{background:transparent;border:none;color:#c8c8c8;font-size:11px;}"
        )
        layout.addWidget(self.notes_view)
        actions = QHBoxLayout()
        self.activate_button = QPushButton("Mark active")
        self.activate_button.setProperty("variant", "primary")
        self.activate_button.clicked.connect(lambda: self.change_status(AssessmentStatus.ACTIVE))
        self.complete_button = QPushButton("Mark complete")
        self.complete_button.clicked.connect(lambda: self.change_status(AssessmentStatus.COMPLETE))
        self.archive_button = QPushButton("Archive")
        self.archive_button.setProperty("variant", "danger")
        self.archive_button.clicked.connect(lambda: self.change_status(AssessmentStatus.ARCHIVED))
        actions.addWidget(self.activate_button)
        actions.addWidget(self.complete_button)
        actions.addWidget(self.archive_button)
        actions.addStretch(1)
        layout.addLayout(actions)
        layout.addStretch(1)
        return widget

    def _build_evidence_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(9)
        banner = InfoBanner(
            "Captures imported into this assessment are registered automatically. "
            "Additional evidence can be attached; each file is copied and SHA-256 hashed."
        )
        layout.addWidget(banner)
        toolbar = QHBoxLayout()
        self.attach_button = QPushButton("Attach evidence")
        self.attach_button.setProperty("variant", "primary")
        self.attach_button.clicked.connect(self.attach_evidence)
        toolbar.addWidget(self.attach_button)
        self.open_evidence_button = QPushButton("Open")
        self.open_evidence_button.clicked.connect(self.open_evidence)
        toolbar.addWidget(self.open_evidence_button)
        self.remove_evidence_button = QPushButton("Remove record")
        self.remove_evidence_button.setProperty("variant", "danger")
        self.remove_evidence_button.clicked.connect(self.remove_evidence)
        toolbar.addWidget(self.remove_evidence_button)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)
        self.evidence_table = make_table(
            ["Label", "Kind", "Size", "SHA-256", "Added"], stretch_column=0
        )
        set_column_widths(self.evidence_table, {1: 95, 2: 85, 3: 190, 4: 145})
        layout.addWidget(self.evidence_table, 1)
        return widget

    def _build_audit_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(9)
        note = QLabel(
            "Persistent record of significant operations. Passwords and recovered "
            "passphrases never appear in this trail."
        )
        note.setProperty("role", "small")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.audit_table = make_table(["Timestamp", "Action", "Detail", "Actor"], stretch_column=2)
        set_column_widths(self.audit_table, {0: 175, 1: 170, 3: 100})
        layout.addWidget(self.audit_table, 1)
        return widget

    def open_create_dialog(self) -> None:
        self._open_dialog(None)

    def edit_selected(self) -> None:
        assessment = self._selected_assessment()
        if assessment:
            self._open_dialog(assessment)

    def _open_dialog(self, assessment: Assessment | None) -> None:
        dialog = AssessmentDialog(self, assessment)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        values = dialog.values()
        try:
            if assessment:
                assessment.name = values["name"]
                assessment.organisation = values["organisation"]
                assessment.tester = values["tester"]
                assessment.scope = values["scope"]
                assessment.permitted_targets = values["targets"]
                assessment.status = values["status"]
                assessment.start_date = values["start_date"]
                assessment.end_date = values["end_date"]
                assessment.notes = values["notes"]
                self.service.update_assessment(assessment)
                selected_id = assessment.id
                self.notify("Assessment updated.", "success")
            else:
                created = self.service.create_assessment(
                    name=values["name"],
                    organisation=values["organisation"],
                    scope=values["scope"],
                    permitted_targets=values["targets"],
                    tester=values["tester"],
                    status=values["status"],
                    start_date=values["start_date"],
                    end_date=values["end_date"],
                    notes=values["notes"],
                )
                selected_id = created.id
                self._selected_id = selected_id
                self.notify("Assessment workspace created.", "success")
        except (SurgeError, ValueError) as exc:
            QMessageBox.warning(self, "Assessment could not be saved", str(exc))
            return
        self.assessments_changed.emit(selected_id)

    def refresh(self) -> None:
        previous = self._selected_id
        self._assessments = self.service.db.list_assessments(include_archived=True)
        self.list.blockSignals(True)
        self.list.clear()
        for assessment in self._assessments:
            item = QListWidgetItem(
                f"{assessment.name}\n{assessment.organisation or 'No organisation'} · "
                f"{assessment.status.value.upper()}"
            )
            item.setData(256, assessment.id)
            item.setToolTip(f"{assessment.id}\n{assessment.scope or 'No scope recorded'}")
            item.setSizeHint(QSize(0, 56))
            self.list.addItem(item)
        self.list.blockSignals(False)
        self.empty_label.setVisible(not self._assessments)
        if not self._assessments:
            self._selected_id = None
            self._render(None)
            return
        target_id = previous or (self.current_assessment().id if self.current_assessment() else "")
        row = next(
            (index for index, item in enumerate(self._assessments) if item.id == target_id),
            0,
        )
        self.list.setCurrentRow(row)
        self._selected_id = self._assessments[row].id
        self._render(self._assessments[row])

    def _list_selected(self, row: int) -> None:
        if 0 <= row < len(self._assessments):
            self._selected_id = self._assessments[row].id
            self._render(self._assessments[row])

    def _selected_assessment(self) -> Assessment | None:
        return next((item for item in self._assessments if item.id == self._selected_id), None)

    def _render(self, assessment: Assessment | None) -> None:
        enabled = assessment is not None
        for widget in (
            self.edit_button,
            self.activate_button,
            self.complete_button,
            self.archive_button,
            self.attach_button,
        ):
            widget.setEnabled(enabled)
        if not assessment:
            self.overview_name.setText("No assessment selected")
            self.overview_org.setText("Create an assessment to begin.")
            self.overview_status.setText("NONE")
            for row in self.overview_rows.values():
                row.set_value("—")
            self.scope_view.setText("—")
            self.targets_view.clear()
            self.notes_view.clear()
            self.evidence_table.setRowCount(0)
            self.audit_table.setRowCount(0)
            return
        self.overview_name.setText(assessment.name)
        self.overview_org.setText(assessment.organisation or "No organisation recorded")
        colours = {
            "draft": "#6cb6ff",
            "active": "#4ade80",
            "complete": "#a8a8a8",
            "archived": "#a8a8a8",
        }
        self.overview_status.setText(assessment.status.value.upper())
        self.overview_status.set_colour(colours.get(assessment.status.value, "#a8a8a8"))
        self.overview_rows["id"].set_value(assessment.id)
        self.overview_rows["tester"].set_value(assessment.tester or "Not recorded")
        self.overview_rows["dates"].set_value(
            f"{assessment.start_date or '—'} → {assessment.end_date or 'in progress'}"
        )
        self.overview_rows["targets"].set_value(f"{assessment.target_count} target(s)")
        self.overview_rows["created"].set_value(human_time(assessment.created_at))
        self.overview_rows["updated"].set_value(human_time(assessment.updated_at))
        self.scope_view.setText(assessment.scope or "No scope statement recorded.")
        self.targets_view.clear()
        for target in assessment.permitted_targets:
            self.targets_view.addItem(target)
        if not assessment.permitted_targets:
            self.targets_view.addItem("No permitted targets — offline auditing is blocked.")
        self.notes_view.setPlainText(assessment.notes or "No internal notes.")
        self.activate_button.setEnabled(assessment.status is not AssessmentStatus.ACTIVE)
        self.complete_button.setEnabled(assessment.status is AssessmentStatus.ACTIVE)
        self.archive_button.setEnabled(assessment.status is not AssessmentStatus.ARCHIVED)
        self._fill_evidence(assessment)
        self._fill_audit(assessment)

    def _fill_evidence(self, assessment: Assessment) -> None:
        evidence = self.service.db.list_evidence(assessment.id)
        self.evidence_table.clearSpans()
        self.evidence_table.setRowCount(0)
        for row, item in enumerate(evidence):
            self.evidence_table.insertRow(row)
            set_cell(self.evidence_table, row, 0, item.label)
            set_cell(self.evidence_table, row, 1, item.kind)
            try:
                size = Path(item.path).stat().st_size
            except OSError:
                size = 0
            set_cell(self.evidence_table, row, 2, format_bytes(size))
            set_cell(self.evidence_table, row, 3, item.sha256[:20] + "…", mono=True)
            set_cell(self.evidence_table, row, 4, human_time(item.added_at), colour="#a8a8a8")
        if not evidence:
            self.evidence_table.setRowCount(1)
            set_cell(self.evidence_table, 0, 0, "No evidence registered.", colour="#a8a8a8")
            self.evidence_table.setSpan(0, 0, 1, 5)

    def _fill_audit(self, assessment: Assessment) -> None:
        events = self.service.db.list_audit_events(assessment.id, limit=200)
        self.audit_table.clearSpans()
        self.audit_table.setRowCount(0)
        for row, event in enumerate(events):
            self.audit_table.insertRow(row)
            set_cell(self.audit_table, row, 0, human_time(event.timestamp), colour="#a8a8a8")
            set_cell(self.audit_table, row, 1, event.action)
            set_cell(self.audit_table, row, 2, event.detail, tooltip=event.detail)
            set_cell(self.audit_table, row, 3, event.actor)
        if not events:
            self.audit_table.setRowCount(1)
            set_cell(self.audit_table, 0, 0, "No audit events recorded.", colour="#a8a8a8")
            self.audit_table.setSpan(0, 0, 1, 4)

    def change_status(self, status: AssessmentStatus) -> None:
        assessment = self._selected_assessment()
        if not assessment:
            return
        if status is AssessmentStatus.ARCHIVED:
            answer = QMessageBox.question(
                self,
                "Archive assessment",
                "Archive this assessment? It will be removed from the active workspace "
                "selector but retained with its evidence and audit trail.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        try:
            self.service.set_assessment_status(assessment.id, status)
        except Exception as exc:                
            QMessageBox.warning(self, "Status update failed", str(exc))
            return
        self.notify(f"Assessment marked {status.value}.", "success")
        self.assessments_changed.emit(assessment.id)

    def attach_evidence(self) -> None:
        assessment = self._selected_assessment()
        if not assessment:
            return
        path, _filter = QFileDialog.getOpenFileName(self, "Attach evidence")
        if not path:
            return
        try:
            evidence = self.service.attach_evidence(
                assessment.id,
                path,
                Path(path).name,
                "Evidence attached from the assessment workspace.",
            )
        except Exception as exc:                
            QMessageBox.warning(self, "Evidence could not be attached", str(exc))
            return
        self.refresh()
        self.notify(f"Evidence attached: {evidence.label}.", "success")

    def open_evidence(self) -> None:
        assessment = self._selected_assessment()
        if not assessment:
            return
        rows = self.evidence_table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.information(self, "Select evidence", "Select an evidence row to open.")
            return
        evidence = self.service.db.list_evidence(assessment.id)
        row = rows[0].row()
        if row >= len(evidence):
            return
        path = Path(evidence[row].path)
        if not path.exists():
            QMessageBox.warning(self, "Evidence missing", f"The file is missing:\n{path}")
            return
        open_path(path)

    def remove_evidence(self) -> None:
        assessment = self._selected_assessment()
        if not assessment:
            return
        rows = self.evidence_table.selectionModel().selectedRows()
        if not rows:
            return
        evidence = self.service.db.list_evidence(assessment.id)
        row = rows[0].row()
        if row >= len(evidence):
            return
        answer = QMessageBox.question(
            self,
            "Remove evidence record",
            f"Remove the evidence record '{evidence[row].label}'?\n\nThe stored file "
            "will remain on disk.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.service.remove_evidence(evidence[row].id)
        self.refresh()
        self.notify("Evidence record removed.", "success")


