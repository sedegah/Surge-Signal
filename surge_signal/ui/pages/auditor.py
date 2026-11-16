"""Password Security Auditor: strength evaluation and controlled offline audits."""

from __future__ import annotations

import html
import threading
import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ...core.domain import (
    AuditStatus,
    PasswordAuditResult,
    human_time,
    normalize_bssid,
    valid_bssid,
)
from ...audit.password_audit import evaluate_password
from ..kali_terminal import KaliTerminalDialog
from ..widgets import (
    Card,
    Chip,
    ConfirmAuditDialog,
    InfoBanner,
    KeyValueRow,
    Meter,
    format_number,
    make_table,
    set_cell,
    set_chip_cell,
    set_column_widths,
)
from .base import BasePage


class AuditorPage(BasePage):
    title = "Password Auditor"
    subtitle = (
        "Evaluate credential strength and run offline WPA/WPA2 verification against "
        "authorised laboratory captures. Recovered values are masked and never stored."
    )

    def __init__(self, service, window):
        super().__init__(service, window)
        self._captures = []
        self._wordlists: list[dict] = []
        self._prepared = None
        self._prepared_assessment = ""
        self._stop_event = threading.Event()
        self._started_at = 0.0
        self._mode = "idle"
        self._build()
        self.kali_button = self.add_action(
            "Kali terminal / Aircrack",
            self.open_kali_terminal,
        )
        self.kali_button.setToolTip(
            "Authenticate to Kali, install the lab tools and run Aircrack-ng against "
            "an authorised capture."
        )

    def _build(self) -> None:
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_strength_tab(), "Strength assessment")
        self.tabs.addTab(self._build_audit_tab(), "Offline audit")
        self.content.addWidget(self.tabs, 1)

                                                                                 
    def _build_strength_tab(self) -> QWidget:
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        input_card = Card()
        input_card.add_title("Evaluate a candidate", "Runs entirely in memory")
        note = QLabel(
            "Assess a password against length, entropy and predictable-pattern "
            "heuristics. Nothing is transmitted, logged or written to the database."
        )
        note.setProperty("role", "small")
        note.setWordWrap(True)
        input_card.add(note)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Enter a candidate passphrase")
        self.password_input.returnPressed.connect(self.evaluate_strength)
        input_card.add(self.password_input)
        controls = QHBoxLayout()
        self.show_password = QCheckBox("Show")
        self.show_password.toggled.connect(
            lambda checked: self.password_input.setEchoMode(
                QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
            )
        )
        controls.addWidget(self.show_password)
        controls.addStretch(1)
        clear = QPushButton("Clear")
        clear.setProperty("variant", "ghost")
        clear.clicked.connect(self.clear_strength)
        controls.addWidget(clear)
        evaluate = QPushButton("Evaluate strength")
        evaluate.setProperty("variant", "primary")
        evaluate.clicked.connect(self.evaluate_strength)
        controls.addWidget(evaluate)
        input_card.body.addLayout(controls)
        input_card.body.addStretch(1)
        layout.addWidget(input_card, 2)

        result_card = Card()
        result_card.add_title("Strength result", "Policy target: 12+ mixed characters")
        self.strength_score = QLabel("Not evaluated")
        self.strength_score.setProperty("role", "h1")
        result_card.add(self.strength_score)
        self.strength_meter = Meter()
        result_card.add(self.strength_meter)
        self.strength_summary = QLabel(
            "Enter a candidate to receive an entropy estimate and actionable guidance."
        )
        self.strength_summary.setProperty("role", "small")
        self.strength_summary.setWordWrap(True)
        result_card.add(self.strength_summary)
        self.strength_rows = {
            "length": KeyValueRow("Length", "—"),
            "entropy": KeyValueRow("Estimated entropy", "—"),
            "policy": KeyValueRow("Policy compliance", "—"),
            "time": KeyValueRow("Pessimistic offline estimate", "—"),
        }
        for row in self.strength_rows.values():
            result_card.add(row)
        self.strength_details = QTextBrowser()
        self.strength_details.setOpenExternalLinks(False)
        self.strength_details.setFrameShape(QFrame.Shape.NoFrame)
        self.strength_details.setStyleSheet(
            "QTextBrowser{background:transparent;border:none;color:#d8d8d8;font-size:12px;}"
        )
        result_card.add(self.strength_details, 1)
        layout.addWidget(result_card, 3)
        return widget

    def evaluate_strength(self) -> None:
        candidate = self.password_input.text()
        result = evaluate_password(candidate)
        colours = ["#ff6b7a", "#ff8a5b", "#f5c451", "#6cb6ff", "#4ade80"]
        colour = colours[result.score]
        self.strength_score.setText(f"{result.label}  ·  {result.score}/4")
        self.strength_score.setStyleSheet(f"color:{colour};")
        self.strength_meter.set_score(result.score)
        self.strength_summary.setText(
            "No candidate entered." if not candidate else
            ("Passes the target policy." if result.policy_compliant else
             "Does not meet the target policy; see guidance below.")
        )
        self.strength_rows["length"].set_value(
            f"{result.length} characters" if result.length else "—"
        )
        self.strength_rows["entropy"].set_value(f"{result.entropy_bits} bits")
        self.strength_rows["policy"].set_value(
            "Compliant" if result.policy_compliant else "Not compliant"
        )
        self.strength_rows["time"].set_value(result.estimated_offline_crack_time or "—")
        issues = "".join(f"<li>{html.escape(item)}</li>" for item in result.issues)
        recs = "".join(f"<li>{html.escape(item)}</li>" for item in result.recommendations)
        self.strength_details.setHtml(
            "<style>h4{color:#ffffff;margin:9px 0 3px 0;font-size:11px;}"
            "li{color:#d8d8d8;margin:2px 0;}p{color:#a8a8a8;}</style>"
            + ("<h4>Detected weaknesses</h4><ul>" + issues + "</ul>" if issues else "<p>No obvious weakness detected.</p>")
            + ("<h4>Recommendations</h4><ul>" + recs + "</ul>" if recs else "")
        )

    def clear_strength(self) -> None:
        self.password_input.clear()
        self.show_password.setChecked(False)
        self.strength_score.setText("Not evaluated")
        self.strength_score.setStyleSheet("")
        self.strength_meter.set_score(0)
        self.strength_summary.setText(
            "Enter a candidate to receive an entropy estimate and actionable guidance."
        )
        for row in self.strength_rows.values():
            row.set_value("—")
        self.strength_details.clear()

                                                                                 
    def _build_audit_tab(self) -> QWidget:
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        warning = InfoBanner(
            "Offline laboratory audit only. The capture must contain a complete WPA "
            "msg1/msg2 handshake for an explicitly permitted BSSID. No frames are "
            "transmitted and no third-party network is contacted.",
            level="warn",
        )
        layout.addWidget(warning)

        form_card = Card(padding=15, spacing=10)
        form = QGridLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(8)
        form.addWidget(self._field_label("Capture"), 0, 0)
        self.capture_combo = QComboBox()
        self.capture_combo.currentIndexChanged.connect(self._capture_changed)
        form.addWidget(self.capture_combo, 1, 0, 1, 3)
        form.addWidget(self._field_label("Target BSSID"), 2, 0)
        self.bssid_input = QLineEdit()
        self.bssid_input.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        self.bssid_input.textChanged.connect(self._scope_changed)
        form.addWidget(self.bssid_input, 3, 0)
        self.scope_chip = Chip("SCOPE UNKNOWN", "#a8a8a8")
        form.addWidget(self.scope_chip, 3, 1)
        self.handshake_label = QLabel("Select a capture")
        self.handshake_label.setProperty("role", "small")
        form.addWidget(self.handshake_label, 3, 2)
        form.addWidget(self._field_label("Method"), 4, 0)
        self.method_combo = QComboBox()
        self.method_combo.addItem("Local WPA2 verifier (recommended)", "local")
        self.method_combo.addItem("Aircrack-ng in Kali (large lists)", "aircrack")
        form.addWidget(self.method_combo, 5, 0)
        form.addWidget(self._field_label("Length policy"), 4, 1)
        length_policy = QHBoxLayout()
        self.min_length = QSpinBox()
        self.min_length.setRange(8, 63)
        self.min_length.setValue(8)
        self.max_length = QSpinBox()
        self.max_length.setRange(8, 63)
        self.max_length.setValue(63)
        length_policy.addWidget(self.min_length)
        length_policy.addWidget(QLabel("–"))
        length_policy.addWidget(self.max_length)
        length_holder = QWidget()
        length_holder.setLayout(length_policy)
        form.addWidget(length_holder, 5, 1)
        form.addWidget(self._field_label("Candidate cap"), 4, 2)
        self.candidate_cap = QSpinBox()
        self.candidate_cap.setRange(1, 5_000_000)
        self.candidate_cap.setValue(100_000)
        self.candidate_cap.setSingleStep(10_000)
        form.addWidget(self.candidate_cap, 5, 2)
        form_card.body.addLayout(form)
        layout.addWidget(form_card)

        wordlist_card = Card(padding=15, spacing=8)
        wordlist_card.add_title(
            "Source wordlists", "Selected lists are merged by category priority"
        )
        open_library = QPushButton("Manage wordlists →")
        open_library.setProperty("variant", "link")
        open_library.clicked.connect(lambda: self.window.navigate("wordlists"))
        wordlist_card.add_header_widget(open_library)
        self.wordlist_table = make_table(
            ["Use", "List", "Category", "Lines", "Lengths"], stretch_column=1
        )
        set_column_widths(self.wordlist_table, {0: 55, 2: 145, 3: 85, 4: 85})
        self.wordlist_table.setMaximumHeight(205)
        wordlist_card.add(self.wordlist_table)
        self.prepare_status = QLabel("No candidate list prepared.")
        self.prepare_status.setProperty("role", "small")
        self.prepare_status.setWordWrap(True)
        wordlist_card.add(self.prepare_status)
        actions = QHBoxLayout()
        self.prepare_button = QPushButton("Prepare candidate list")
        self.prepare_button.clicked.connect(self.prepare_candidates)
        actions.addWidget(self.prepare_button)
        self.audit_button = QPushButton("Run authorised audit")
        self.audit_button.setProperty("variant", "primary")
        self.audit_button.setEnabled(False)
        self.audit_button.clicked.connect(self.run_audit)
        actions.addWidget(self.audit_button)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setProperty("variant", "danger")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_audit)
        actions.addWidget(self.stop_button)
        actions.addStretch(1)
        wordlist_card.body.addLayout(actions)
        layout.addWidget(wordlist_card)

        progress_card = Card(padding=14, spacing=7)
        progress_header = QHBoxLayout()
        self.progress_title = QLabel("Ready")
        self.progress_title.setProperty("role", "h3")
        progress_header.addWidget(self.progress_title)
        progress_header.addStretch(1)
        self.progress_eta = QLabel("")
        self.progress_eta.setProperty("role", "small")
        progress_header.addWidget(self.progress_eta)
        progress_card.body.addLayout(progress_header)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        progress_card.add(self.progress)
        layout.addWidget(progress_card)

        result_card = Card(padding=15, spacing=7)
        result_card.add_title("Latest result")
        self.result_title = QLabel("No audit has been run in this session.")
        self.result_title.setProperty("role", "h2")
        result_card.add(self.result_title)
        self.result_detail = QLabel(
            "Results show whether an authorised capture matched a candidate. Recovered "
            "values are masked and are not written to the database."
        )
        self.result_detail.setProperty("role", "small")
        self.result_detail.setWordWrap(True)
        result_card.add(self.result_detail)
        self.result_rows = {
            "status": KeyValueRow("Status", "—"),
            "engine": KeyValueRow("Engine", "—"),
            "tested": KeyValueRow("Candidates tested", "—"),
            "elapsed": KeyValueRow("Elapsed", "—"),
            "masked": KeyValueRow("Masked match", "—"),
        }
        for row in self.result_rows.values():
            result_card.add(row)
        layout.addWidget(result_card)

        history_card = Card(padding=15, spacing=7)
        history_card.add_title("Audit history", "No plaintext secrets are stored")
        self.history_table = make_table(
            ["Started", "Method", "Status", "Candidates", "Result"], stretch_column=4
        )
        set_column_widths(self.history_table, {0: 150, 1: 120, 2: 105, 3: 100})
        self.history_table.setMaximumHeight(170)
        history_card.add(self.history_table)
        layout.addWidget(history_card)
        layout.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(inner)
        return scroll

    @staticmethod
    def _field_label(text: str) -> QLabel:
        label = QLabel(text)
        label.setProperty("role", "small")
        return label

    def refresh(self) -> None:
        assessment = self.current_assessment()
        self.prepare_button.setEnabled(assessment is not None)
        self.audit_button.setEnabled(
            assessment is not None
            and self._prepared is not None
            and self._prepared_assessment == assessment.id
        )
        if not assessment:
            self.capture_combo.clear()
            self.wordlist_table.setRowCount(0)
            self.history_table.setRowCount(0)
            return
        if self._prepared_assessment and self._prepared_assessment != assessment.id:
            self._prepared = None
        if self._prepared is not None and not Path(self._prepared.path).is_file():
            self._prepared = None
            self.prepare_status.setText("The prepared candidate file is no longer available; prepare it again.")
        self._captures = self.service.db.list_captures(assessment.id)
        self._fill_captures()
        self._wordlists = self.service.wordlist_records(include_prepared=True)
        self._fill_wordlists()
        self._fill_history(assessment.id)
        self._scope_changed()
        self.candidate_cap.setValue(
            max(1, self.service.settings.get_int("wordlist_max_candidates", 100_000))
        )

    def _fill_captures(self) -> None:
        selected = self.capture_combo.currentData()
        self.capture_combo.blockSignals(True)
        self.capture_combo.clear()
        for capture in self._captures:
            handshakes = capture.metadata.get("handshakes", [])
            complete = sum(1 for item in handshakes if item.get("complete"))
            label = (
                f"{capture.filename}  ·  {capture.bssid or 'no BSSID'}  ·  "
                f"{complete} complete handshake(s)"
            )
            self.capture_combo.addItem(label, capture.id)
        if not self._captures:
            self.capture_combo.addItem("No captures imported", None)
        if selected is not None:
            index = self.capture_combo.findData(selected)
            if index >= 0:
                self.capture_combo.setCurrentIndex(index)
        self.capture_combo.blockSignals(False)
        self._capture_changed()

    def _capture_changed(self) -> None:
        capture_id = self.capture_combo.currentData()
        capture = next((item for item in self._captures if item.id == capture_id), None)
        if not capture:
            self.bssid_input.setText("")
            self.handshake_label.setText("No capture selected")
            return
        self.bssid_input.setText(capture.bssid or "")
        handshakes = [
            item for item in capture.metadata.get("handshakes", []) if item.get("complete")
        ]
        if handshakes:
            self.handshake_label.setText(
                f"{len(handshakes)} complete handshake(s) · {capture.format.upper()}"
            )
            self.handshake_label.setStyleSheet("color:#4ade80;")
        else:
            self.handshake_label.setText("No complete msg1/msg2 handshake detected")
            self.handshake_label.setStyleSheet("color:#f5c451;")

    def _scope_changed(self) -> None:
        assessment = self.current_assessment()
        bssid = normalize_bssid(self.bssid_input.text())
        if not assessment or not valid_bssid(bssid):
            self.scope_chip.setText("SCOPE UNKNOWN")
            self.scope_chip.set_colour("#a8a8a8")
            return
        if assessment.target_is_permitted(bssid):
            self.scope_chip.setText("IN SCOPE")
            self.scope_chip.set_colour("#4ade80")
        else:
            self.scope_chip.setText("NOT PERMITTED")
            self.scope_chip.set_colour("#ff6b7a")

    def _fill_wordlists(self) -> None:
        checked = set(self.selected_wordlist_ids())
        self.wordlist_table.clearSpans()
        self.wordlist_table.setRowCount(0)
        for row, record in enumerate(self._wordlists):
            self.wordlist_table.insertRow(row)
            item = QTableWidgetItem()
            item.setFlags(
                Qt.ItemFlag.ItemIsUserCheckable
                | Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
            )
            item.setCheckState(
                Qt.CheckState.Checked if int(record["id"]) in checked else Qt.CheckState.Unchecked
            )
            self.wordlist_table.setItem(row, 0, item)
            name = record["name"] + ("  · prepared" if record.get("is_prepared") else "")
            set_cell(self.wordlist_table, row, 1, name, tooltip=record.get("description", ""))
            set_cell(self.wordlist_table, row, 2, record.get("category_label", record.get("category", "")))
            set_cell(self.wordlist_table, row, 3, format_number(record.get("line_count")))
            set_cell(
                self.wordlist_table,
                row,
                4,
                f"{record.get('min_length') or '?'}–{record.get('max_length') or '?'}",
            )
        if not self._wordlists:
            self.wordlist_table.setRowCount(1)
            set_cell(self.wordlist_table, 0, 0, "No wordlists installed", colour="#a8a8a8")
            self.wordlist_table.setSpan(0, 0, 1, 5)

    def selected_wordlist_ids(self) -> list[int]:
        ids: list[int] = []
        for row in range(self.wordlist_table.rowCount()):
            item = self.wordlist_table.item(row, 0)
            if item and item.checkState() == Qt.CheckState.Checked:
                if row < len(self._wordlists):
                    ids.append(int(self._wordlists[row]["id"]))
        return ids

    def select_wordlists(self, ids: list[int]) -> None:
        self.refresh()
        wanted = {int(item) for item in ids}
        self.tabs.setCurrentIndex(1)
        for row, record in enumerate(self._wordlists):
            item = self.wordlist_table.item(row, 0)
            if item:
                item.setCheckState(
                    Qt.CheckState.Checked if int(record["id"]) in wanted else Qt.CheckState.Unchecked
                )

    def _fill_history(self, assessment_id: str) -> None:
        audits = self.service.db.list_password_audits(assessment_id)
        self.history_table.setRowCount(0)
        for row, audit in enumerate(audits):
            self.history_table.insertRow(row)
            set_cell(self.history_table, row, 0, human_time(audit.get("started_at")), colour="#a8a8a8")
            set_cell(self.history_table, row, 1, audit.get("engine", ""))
            set_chip_cell(
                self.history_table,
                row,
                2,
                str(audit.get("status", "")).upper(),
                "#4ade80" if audit.get("status") == "completed" else "#ff6b7a",
            )
            set_cell(self.history_table, row, 3, format_number(audit.get("candidates_tested")))
            set_cell(
                self.history_table,
                row,
                4,
                "Match (masked) " + (audit.get("masked_secret") or "") if audit.get("recovered") else "No match",
                tooltip=audit.get("detail", ""),
            )

    def prepare_candidates(self) -> None:
        assessment = self.require_assessment()
        if not assessment:
            return
        ids = self.selected_wordlist_ids()
        if not ids:
            QMessageBox.information(
                self,
                "Select wordlists",
                "Check at least one source list. Install lists from the Wordlist Library "
                "if none are available.",
            )
            return
        min_len = self.min_length.value()
        max_len = self.max_length.value()
        if min_len > max_len:
            QMessageBox.warning(self, "Invalid length policy", "Minimum length exceeds maximum length.")
            return
        cap = self.candidate_cap.value()
        self._stop_event = threading.Event()
        self.prepare_button.setEnabled(False)
        self.audit_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress_title.setText("Preparing candidates")
        self._started_at = time.monotonic()
        self._mode = "prepare"
        self.notify("Merging, filtering and deduplicating selected wordlists…")

        def progress_cb(value) -> None:
            scanned, total, accepted, source = value
            self.progress.setRange(0, max(1, total))
            self.progress.setValue(min(scanned, total))
            elapsed = max(0.01, time.monotonic() - self._started_at)
            rate = scanned / elapsed if elapsed else 0
            remaining = max(0, total - scanned)
            eta = f" · ETA {remaining / rate:.0f}s" if rate > 0 and remaining else ""
            self.progress_eta.setText(
                f"{format_number(scanned)} scanned · {format_number(accepted)} accepted · "
                f"{rate:,.0f}/s{eta}"
            )

        def done(prepared) -> None:
            self._prepared = prepared
            self._prepared_assessment = assessment.id
            self.prepare_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.audit_button.setEnabled(True)
            self.progress.setRange(0, max(1, prepared.candidate_count))
            self.progress.setValue(prepared.candidate_count)
            self.progress_title.setText("Candidate list ready")
            self.progress_eta.setText(
                f"{format_number(prepared.candidate_count)} unique candidates"
                + (" · cap reached" if prepared.truncated else "")
            )
            self.prepare_status.setText(
                f"Prepared {format_number(prepared.candidate_count)} candidates from "
                f"{len(prepared.source_lists)} list(s). Saved as {Path(prepared.path).name}. "
                f"SHA-256 {prepared.sha256[:16]}…"
            )
            self.notify(
                f"Candidate list ready: {prepared.candidate_count:,} unique candidates.",
                "success",
            )

        def failed(message: str) -> None:
            self.prepare_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.audit_button.setEnabled(self._prepared is not None)
            self.progress_title.setText("Preparation failed")
            self.progress_eta.setText("")
            self.notify(f"Candidate preparation failed: {message}", "error")
            QMessageBox.warning(self, "Candidate preparation failed", message)

        self.tasks.start(
            lambda progress_cb: self.service.prepare_wordlist(
                ids,
                min_length=min_len,
                max_length=max_len,
                max_candidates=cap,
                progress=lambda a, b, c, d: progress_cb((a, b, c, d)),
                stop_event=self._stop_event,
            ),
            on_done=done,
            on_error=failed,
            on_progress=progress_cb,
            with_progress=True,
        )

    def run_audit(self) -> None:
        assessment = self.require_assessment()
        if not assessment:
            return
        if self._prepared is None or self._prepared_assessment != assessment.id:
            QMessageBox.information(
                self,
                "Prepare candidates first",
                "Prepare a deduplicated candidate list from the selected wordlists before "
                "running the audit.",
            )
            return
        capture_id = self.capture_combo.currentData()
        capture = next((item for item in self._captures if item.id == capture_id), None)
        if not capture:
            QMessageBox.information(self, "Capture required", "Import and select an authorised capture.")
            return
        bssid = normalize_bssid(self.bssid_input.text())
        if not valid_bssid(bssid):
            QMessageBox.warning(self, "BSSID required", "Enter the capture's target BSSID.")
            return
        if not assessment.target_is_permitted(bssid, capture.ssid):
            QMessageBox.warning(
                self,
                "Target outside scope",
                f"BSSID {bssid} is not listed in the permitted targets for this "
                "assessment. Offline auditing is blocked.",
            )
            return
        if assessment.status.value != "active":
            QMessageBox.warning(
                self,
                "Assessment is not active",
                "Mark the assessment Active in the Assessments workspace before running "
                "an offline password audit.",
            )
            return
        candidates = self._prepared.candidate_count
        dialog = ConfirmAuditDialog(
            assessment.name,
            assessment.id,
            bssid,
            capture.ssid,
            candidates,
            self,
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        method = self.method_combo.currentData()
        self._stop_event = threading.Event()
        self.audit_button.setEnabled(False)
        self.prepare_button.setEnabled(False)
        self.stop_button.setEnabled(method == "local")
        self.progress.setRange(0, max(1, candidates))
        self.progress.setValue(0)
        self.progress_title.setText("Offline audit running")
        self.progress_eta.setText("Initialising…")
        self._started_at = time.monotonic()
        self._mode = "audit"
        self.notify(
            "Running authorised offline audit. No network traffic will be generated.",
            "info",
        )

        def progress_cb(value) -> None:
            tested, limit = value
            self.progress.setRange(0, max(1, limit))
            self.progress.setValue(tested)
            elapsed = max(0.01, time.monotonic() - self._started_at)
            rate = tested / elapsed if elapsed else 0
            remaining = max(0, limit - tested)
            eta = f" · ETA {remaining / rate:.0f}s" if rate > 0 and remaining else ""
            self.progress_eta.setText(
                f"{format_number(tested)} / {format_number(limit)} · {rate:,.1f}/s{eta}"
            )

        def done(result: PasswordAuditResult) -> None:
            self._finish_audit(result)
            self._fill_history(assessment.id)

        def failed(message: str) -> None:
            self.audit_button.setEnabled(True)
            self.prepare_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.progress_title.setText("Audit failed")
            self.progress_eta.setText("")
            self.notify(f"Audit failed: {message}", "error")
            QMessageBox.warning(self, "Audit failed", message)

        if method == "local":
            self.tasks.start(
                lambda progress_cb: self.service.run_local_audit(
                    assessment.id,
                    capture.id,
                    self._prepared.path,
                    bssid=bssid,
                    confirmed=True,
                    lab_attestation=True,
                    max_candidates=candidates,
                    progress=lambda a, b: progress_cb((a, b)),
                    stop_event=self._stop_event,
                ),
                on_done=done,
                on_error=failed,
                on_progress=progress_cb,
                with_progress=True,
            )
        else:
            self.tasks.start(
                lambda: self.service.run_aircrack_audit(
                    assessment.id,
                    capture.id,
                    self._prepared.path,
                    bssid=bssid,
                    confirmed=True,
                    lab_attestation=True,
                ),
                on_done=done,
                on_error=failed,
            )

    def stop_audit(self) -> None:
        self._stop_event.set()
        self.stop_button.setEnabled(False)
        self.progress_title.setText("Stopping after the current candidate…")
        self.notify("Cancellation requested; the current candidate will finish first.", "warn")

    def _finish_audit(self, result: PasswordAuditResult) -> None:
        self.audit_button.setEnabled(True)
        self.prepare_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        if result.status is AuditStatus.COMPLETED:
            self.progress.setValue(self.progress.maximum())
        self.progress_title.setText(
            {
                AuditStatus.COMPLETED: "Audit complete",
                AuditStatus.FAILED: "Audit failed",
                AuditStatus.CANCELLED: "Audit cancelled",
            }.get(result.status, "Audit finished")
        )
        self.progress_eta.setText("")
        if result.recovered:
            self.result_title.setText("Authorised offline match recovered")
            self.result_title.setStyleSheet("color:#4ade80;")
        elif result.status is AuditStatus.COMPLETED:
            self.result_title.setText("No candidate matched")
            self.result_title.setStyleSheet("color:#f5c451;")
        else:
            self.result_title.setText(result.status.value.title())
            self.result_title.setStyleSheet("color:#ff6b7a;")
        self.result_detail.setText(result.detail)
        self.result_rows["status"].set_value(result.status.value.title())
        self.result_rows["engine"].set_value(result.engine)
        self.result_rows["tested"].set_value(
            f"{format_number(result.candidates_tested)}"
        )
        self.result_rows["elapsed"].set_value(f"{result.elapsed_seconds:.1f} seconds")
        self.result_rows["masked"].set_value(result.masked_secret or "—")
        level = "warn" if result.recovered else "success" if result.status is AuditStatus.COMPLETED else "error"
        self.notify(self.result_title.text(), level)

    def refresh_after_external_change(self) -> None:
        self.refresh()

    def open_kali_terminal(self) -> None:
        assessment = self.require_assessment()
        if not assessment:
            return
        existing = getattr(self, "_kali_dialog", None)
        if existing is not None and existing.isVisible():
            existing.raise_()
            existing.activateWindow()
            return
        dialog = KaliTerminalDialog(self.service, assessment, self)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        dialog.destroyed.connect(lambda: setattr(self, "_kali_dialog", None))
        self._kali_dialog = dialog
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        self.refresh()

