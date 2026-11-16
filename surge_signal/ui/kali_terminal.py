"""Guided Kali terminal for tool installation and authorised Aircrack-ng audits."""

from __future__ import annotations

import re
import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..core.domain import (
    Assessment,
    AssessmentStatus,
    AuditStatus,
    PasswordAuditResult,
    human_time,
    mask_secret,
    normalize_bssid,
    valid_bssid,
)
from ..audit.password_audit import parse_aircrack_secret
from ..core.services import SurgeService
from .live_capture import KaliCaptureDialog
from .widgets import Chip, InfoBanner, SudoPasswordDialog, TaskRunner

ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


class KaliTerminalDialog(QDialog):
    def __init__(self, service: SurgeService, assessment: Assessment, parent=None):
        super().__init__(parent)
        self.service = service
        self.assessment = assessment
        self.tasks = TaskRunner(self, max_threads=1)
        self._captures = service.db.list_captures(assessment.id)
        self._wordlists = service.wordlist_records(include_prepared=True)
        self._secret = ""
        self._setWindow()
        self._build()
        self._append("SURGE Signal Kali research terminal")
        self._append("Guided, authorised laboratory workflow. No commands are sent to a third-party network.")
        self._append("1) Authenticate and install tools  2) Select capture and wordlist  3) Run Aircrack-ng.")
        self._check_tools(silent=True)

    def _setWindow(self) -> None:
        self.setWindowTitle("Kali terminal — Aircrack-ng (authorised lab)")
        self.setModal(False)
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.resize(1020, 760)
        self.setMinimumSize(860, 620)

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 12)
        outer.setSpacing(9)

        header = QHBoxLayout()
        title = QLabel("Kali research terminal")
        title.setProperty("role", "h1")
        header.addWidget(title)
        header.addStretch(1)
        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.reject)
        header.addWidget(self.close_button)
        outer.addLayout(header)

        subtitle = QLabel(
            f"Assessment: {self.assessment.name} ({self.assessment.id})  ·  "
            "Aircrack-ng uses an existing authorised capture. No live frame injection."
        )
        subtitle.setProperty("role", "small")
        subtitle.setWordWrap(True)
        outer.addWidget(subtitle)
        outer.addWidget(
            InfoBanner(
                "Password auditing is restricted to the active assessment scope. "
                "Viewing or copying a recovered passphrase is a one-time in-memory "
                "operation; the database stores only a masked result.",
                level="warn",
            )
        )

        auth = QFrame()
        auth.setObjectName("Card")
        auth_layout = QGridLayout(auth)
        auth_layout.setContentsMargins(12, 10, 12, 10)
        auth_layout.setHorizontalSpacing(8)
        auth_layout.setVerticalSpacing(5)
        auth_label = QLabel("Kali account password")
        auth_label.setProperty("role", "small")
        auth_layout.addWidget(auth_label, 0, 0)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Used only for sudo; never stored")
        auth_layout.addWidget(self.password, 1, 0, 1, 2)
        self.install_button = QPushButton("Authenticate & check tools")
        self.install_button.setProperty("variant", "primary")
        self.install_button.clicked.connect(self.install_tools)
        auth_layout.addWidget(self.install_button, 1, 2)
        self.check_button = QPushButton("Check tools")
        self.check_button.clicked.connect(self.check_tools)
        auth_layout.addWidget(self.check_button, 1, 3)
        self.tool_status = QLabel("Tool status not checked.")
        self.tool_status.setProperty("role", "small")
        self.tool_status.setWordWrap(True)
        auth_layout.addWidget(self.tool_status, 2, 0, 1, 4)
        note = QLabel(
            "Checks the fixed lab toolkit inside Kali and installs only packages that "
            "are missing: aircrack-ng, iw, wireless-tools, wordlists and tshark. "
            "Wireshark GUI is optional; tshark provides the command-line capture tooling."
        )
        note.setProperty("role", "tiny")
        note.setWordWrap(True)
        auth_layout.addWidget(note, 3, 0, 1, 4)
        outer.addWidget(auth)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        outer.addWidget(self.progress)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMaximumBlockCount(5000)
        self.output.setFont(QFont("Consolas", 9))
        self.output.setStyleSheet(
            "QPlainTextEdit{background:#1e1e1e;color:#f0f0f0;border:1px solid #55555a;"
            "border-radius:0px;padding:6px;}"
        )
        outer.addWidget(self.output, 2)

        crack = QFrame()
        crack.setObjectName("Card")
        grid = QGridLayout(crack)
        grid.setContentsMargins(12, 10, 12, 10)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(6)
        grid.addWidget(self._caption("Capture"), 0, 0)
        self.capture_combo = QComboBox()
        grid.addWidget(self.capture_combo, 1, 0, 1, 2)
        grid.addWidget(self._caption("Wordlist"), 0, 2)
        self.wordlist_combo = QComboBox()
        for record in self._wordlists:
            self.wordlist_combo.addItem(
                f"{record['name']}  ({record.get('line_count', 0):,} lines)",
                record["path"],
            )
        if not self._wordlists:
            self.wordlist_combo.addItem("No managed wordlist installed", "")
        grid.addWidget(self.wordlist_combo, 1, 2)
        self.browse_wordlist_button = QPushButton("Browse…")
        self.browse_wordlist_button.clicked.connect(self._browse_wordlist)
        grid.addWidget(self.browse_wordlist_button, 1, 3)
        self.all_wordlists = QCheckBox(
            "Run all installed wordlists (merge, filter and deduplicate first)"
        )
        self.all_wordlists.toggled.connect(self._all_wordlists_toggled)
        grid.addWidget(self.all_wordlists, 2, 2, 1, 2)
        self.authorised = QCheckBox(
            "I confirm this capture is from my own or an explicitly authorised laboratory network."
        )
        grid.addWidget(self.authorised, 4, 0, 1, 4)
        actions = QHBoxLayout()
        self.capture_now_button = QPushButton("Capture handshake now")
        self.capture_now_button.clicked.connect(self.open_live_capture)
        actions.addWidget(self.capture_now_button)
        self.run_button = QPushButton("Run Aircrack-ng")
        self.run_button.setProperty("variant", "primary")
        self.run_button.clicked.connect(self.run_aircrack)
        actions.addWidget(self.run_button)
        self.copy_button = QPushButton("Copy recovered password")
        self.copy_button.setEnabled(False)
        self.copy_button.clicked.connect(self.copy_secret)
        actions.addWidget(self.copy_button)
        self.clear_secret_button = QPushButton("Clear password from memory")
        self.clear_secret_button.setEnabled(False)
        self.clear_secret_button.clicked.connect(self.clear_secret)
        actions.addWidget(self.clear_secret_button)
        actions.addStretch(1)
        grid.addLayout(actions, 5, 0, 1, 4)
        outer.addWidget(crack)

        for capture in self._captures:
            complete = sum(
                1 for item in capture.metadata.get("handshakes", []) if item.get("complete")
            )
            self.capture_combo.addItem(
                f"{capture.filename}  ·  {capture.bssid or 'no BSSID'}  ·  {complete} handshake(s)",
                capture.id,
            )
        if not self._captures:
            self.capture_combo.addItem("No capture imported for this assessment", None)

    def _reload_captures(self) -> None:
        self._captures = self.service.db.list_captures(self.assessment.id)
        current = self.capture_combo.currentData()
        self.capture_combo.blockSignals(True)
        self.capture_combo.clear()
        for capture in self._captures:
            complete = sum(
                1 for item in capture.metadata.get("handshakes", []) if item.get("complete")
            )
            self.capture_combo.addItem(
                f"{capture.filename}  ·  {capture.bssid or 'no BSSID'}  ·  {complete} handshake(s)",
                capture.id,
            )
        if not self._captures:
            self.capture_combo.addItem("No capture imported for this assessment", None)
        if current is not None:
            index = self.capture_combo.findData(current)
            if index >= 0:
                self.capture_combo.setCurrentIndex(index)
        self.capture_combo.blockSignals(False)
        if self._captures:
            self._append(
                f"Capture ready: {self._captures[0].filename}. You can run Aircrack-ng now."
            )

    def open_live_capture(self) -> None:
        existing = getattr(self, "_capture_dialog", None)
        if existing is not None and existing.isVisible():
            existing.raise_()
            existing.activateWindow()
            return
        dialog = KaliCaptureDialog(self.service, self.assessment, self)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        dialog.capture_imported.connect(self._reload_captures)
        dialog.destroyed.connect(lambda: setattr(self, "_capture_dialog", None))
        self._capture_dialog = dialog
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    @staticmethod
    def _caption(text: str) -> QLabel:
        label = QLabel(text)
        label.setProperty("role", "small")
        return label

    def append(self, text: str) -> None:
        clean = ANSI_RE.sub("", text or "")
        self.output.appendPlainText(clean)
        self.output.verticalScrollBar().setValue(self.output.verticalScrollBar().maximum())

    def _append(self, text: str) -> None:
        self.append(f"{time.strftime('%H:%M:%S')}  {text}")

    def _browse_wordlist(self) -> None:
        path, _filter = QFileDialog.getOpenFileName(
            self, "Select authorised wordlist", "", "Wordlists (*.txt *.lst *.dic *.csv);;All files (*)"
        )
        if path:
            self.wordlist_combo.addItem(path, path)
            self.wordlist_combo.setCurrentIndex(self.wordlist_combo.count() - 1)

    def _all_wordlists_toggled(self, checked: bool) -> None:
        self.wordlist_combo.setEnabled(not checked)
        self.browse_wordlist_button.setEnabled(not checked)
        if checked:
            sources = [r for r in self._wordlists if not r.get("is_prepared")]
            if not sources:
                sources = list(self._wordlists)
            total = sum(int(r.get("line_count") or 0) for r in sources)
            self._append(
                f"Run-all selected: {len(sources)} source list(s), {total:,} candidates "
                "before de-duplication and length filtering."
            )

    def check_tools(self) -> None:
        self._check_tools(silent=False)

    def _check_tools(self, silent: bool = False) -> None:
        self.check_button.setEnabled(False)
        self.tool_status.setText("Checking Kali tools…")
        if not silent:
            self._append("Checking research environment and installed tools…")

        def done(status) -> None:
            self.check_button.setEnabled(True)
            self.tool_status.setText(
                f"{status.label} · {status.environment or 'Kali'} · "
                f"aircrack={'yes' if status.aircrack else 'no'} · "
                f"tshark={'yes' if status.tshark else 'no'}"
            )
            self._append(
                f"Environment: {status.environment or 'unknown'} · user {status.username or 'unknown'} "
                f"· kernel {status.kernel or 'unknown'}"
            )
            if status.detail:
                self._append(status.detail)

        def failed(message: str) -> None:
            self.check_button.setEnabled(True)
            self.tool_status.setText("Environment unavailable")
            self._append(f"Environment check failed: {message}")

        self.tasks.start(self.service.research_status, on_done=done, on_error=failed)

    def install_tools(self) -> None:
        password = self.password.text()
        if not password:
            QMessageBox.information(
                self,
                "Kali password required",
                "Enter the Kali account password. It is used only for sudo and is not stored.",
            )
            return
        self.password.clear()
        self.install_button.setEnabled(False)
        self.install_button.setText("Checking…")
        self.progress.setRange(0, 0)
        self._append("Checking installed Kali tools; missing packages only will be installed.")
        secret = [password]

        def task():
            try:
                return self.service.connector.ensure_kali_tools(secret[0])
            finally:
                secret[0] = ""

        def done(result) -> None:
            self.install_button.setEnabled(True)
            self.install_button.setText("Authenticate & check tools")
            self.progress.setRange(0, 1)
            self.progress.setValue(1)
            if result.already_installed:
                self._append(
                    "All required tools are already installed. No packages were changed."
                )
                self.tool_status.setText(
                    "Kali tools ready · aircrack-ng, airmon-ng, airodump-ng, iw, timeout, tshark"
                )
            else:
                self._append("Missing tools: " + ", ".join(result.missing))
                if result.update is not None:
                    self._append(f"apt-get update exit: {result.update.returncode}")
                    if result.update.stdout.strip():
                        self.append(result.update.stdout.strip())
                    if result.update.stderr.strip():
                        self.append(result.update.stderr.strip())
                if result.install is not None:
                    self._append(f"apt-get install exit: {result.install.returncode}")
                    if result.install.stdout.strip():
                        self.append(result.install.stdout.strip()[-12000:])
                    if result.install.stderr.strip():
                        self.append(result.install.stderr.strip())
                    if result.install.returncode == 0:
                        self._append("Missing tools installed. They will not be reinstalled next time.")
                    else:
                        self._append("Tool installation failed. Review the output above.")
            self._check_tools(silent=True)
            self.progress.setValue(1)

        def failed(message: str) -> None:
            self.install_button.setEnabled(True)
            self.install_button.setText("Authenticate & check tools")
            self.progress.setRange(0, 1)
            self.progress.setValue(0)
            self._append(f"Tool check failed: {message}")
            QMessageBox.warning(self, "Kali tool check failed", message)

        self.tasks.start(task, on_done=done, on_error=failed)

    def run_aircrack(self) -> None:
        capture_id = self.capture_combo.currentData()
        capture = next((item for item in self._captures if item.id == capture_id), None)
        if not capture:
            self._append("No capture yet — opening Live Capture so you can record one.")
            self.open_live_capture()
            return
        bssid = capture.bssid or ""
        running_all = self.all_wordlists.isChecked()
        source_records = []
        wordlist = ""
        if running_all:
            source_records = [r for r in self._wordlists if not r.get("is_prepared")]
            if not source_records:
                source_records = list(self._wordlists)
            if not source_records:
                QMessageBox.information(
                    self, "Wordlists required", "Install or import at least one wordlist first."
                )
                return
            candidate_count = sum(int(r.get("line_count") or 0) for r in source_records)
        else:
            wordlist = self.wordlist_combo.currentData() or ""
            if not wordlist:
                QMessageBox.information(self, "Wordlist required", "Select an authorised wordlist.")
                return
            candidate_count = 0
            for record in self._wordlists:
                if record["path"] == wordlist:
                    candidate_count = int(record.get("line_count") or 0)
                    break
        if not self.authorised.isChecked():
            QMessageBox.information(
                self,
                "Authorisation required",
                "Confirm that this capture is from your own or an explicitly authorised laboratory network.",
            )
            return
        from .widgets import ConfirmAuditDialog

        confirm = ConfirmAuditDialog(
            self.assessment.name,
            self.assessment.id,
            bssid or "Aircrack-selected network",
            capture.ssid,
            candidate_count,
            self,
        )
        if confirm.exec() != QDialog.DialogCode.Accepted:
            return
        password_dialog = SudoPasswordDialog("Aircrack-ng offline audit in Kali", self)
        if password_dialog.exec() != QDialog.DialogCode.Accepted:
            return
        password = password_dialog.password_value
        password_dialog.password_value = ""
        secret = [password]

        def execute(wordlist_path: str, wordlist_label: str) -> None:
            self.run_button.setEnabled(False)
            self.run_button.setText("Aircrack-ng running…")
            self.progress.setRange(0, 0)
            self._append(f"Running aircrack-ng against {capture.filename}.")
            self._append(f"Target: {bssid or 'first network in the authorised capture'}")
            self._append(f"Wordlist source: {wordlist_label}")
            started = time.monotonic()

            def task():
                try:
                    return self.service.connector.run_aircrack_privileged(
                        wordlist_path,
                        capture.stored_path,
                        bssid,
                        secret[0],
                        timeout=900,
                    )
                finally:
                    secret[0] = ""

            def done(command) -> None:
                self.run_button.setEnabled(True)
                self.run_button.setText("Run Aircrack-ng")
                self.progress.setRange(0, 1)
                self.progress.setValue(1)
                output = ANSI_RE.sub("", (command.stdout or "") + "\n" + (command.stderr or ""))
                self.append(output.strip())
                recovered, found, detail = parse_aircrack_secret(output)
                tested_match = re.search(r"(\d+)\s+keys tested", output, re.IGNORECASE)
                tested = int(tested_match.group(1)) if tested_match else 0
                if recovered:
                    self._secret = found
                    self.copy_button.setEnabled(True)
                    self.clear_secret_button.setEnabled(True)
                    self._append("=" * 64)
                    self._append(f"RECOVERED PASSPHRASE (in memory only): {found}")
                    self._append(f"Masked value for the assessment record: {mask_secret(found)}")
                    self._append("This value is NOT written to the database. Copy it only if authorised.")
                    self._append("=" * 64)
                    self.tool_status.setText(
                        "Aircrack-ng recovered a passphrase. Review the terminal output."
                    )
                else:
                    self._append(detail)
                    self.tool_status.setText(detail)
                result = PasswordAuditResult(
                    status=AuditStatus.COMPLETED if command.ok else AuditStatus.FAILED,
                    method="aircrack-terminal",
                    candidates_tested=tested,
                    recovered=recovered,
                    masked_secret=mask_secret(found) if recovered else "",
                    elapsed_seconds=round(time.monotonic() - started, 2),
                    detail=detail,
                    engine="aircrack-ng",
                )
                self.service.record_kali_aircrack_result(
                    self.assessment.id, capture.id, wordlist_label, result
                )
                self.progress.setValue(1)

            def failed(message: str) -> None:
                self.run_button.setEnabled(True)
                self.run_button.setText("Run Aircrack-ng")
                self.progress.setRange(0, 1)
                self.progress.setValue(0)
                self._append(f"Aircrack-ng failed: {message}")
                self.service.record_kali_aircrack_result(
                    self.assessment.id,
                    capture.id,
                    wordlist_label,
                    PasswordAuditResult(
                        status=AuditStatus.FAILED,
                        method="aircrack-terminal",
                        detail=message,
                        engine="aircrack-ng",
                    ),
                )
                QMessageBox.warning(self, "Aircrack-ng failed", message)

            self.tasks.start(task, on_done=done, on_error=failed)

        if not running_all:
            execute(wordlist, str(wordlist))
            return

        wordlist_ids = [int(record["id"]) for record in source_records]
        self.run_button.setEnabled(False)
        self.run_button.setText("Preparing merged wordlist…")
        self.progress.setRange(0, 0)
        self._append(
            f"Preparing all {len(source_records)} wordlists: filtering WPA lengths and "
            "removing duplicates before Aircrack-ng starts."
        )
        limit = self.service.settings.get_int("wordlist_max_candidates", 1_000_000)

        def prepare_progress(value) -> None:
            scanned, total, accepted, source = value
            self.tool_status.setText(
                f"Preparing wordlists: {scanned:,} scanned · {accepted:,} unique "
                f"· current {source}"
            )

        def prepared(result) -> None:
            self._append(
                f"Merged candidate list ready: {result.candidate_count:,} unique candidates "
                f"from {len(result.source_lists)} list(s)."
            )
            execute(result.path, f"All wordlists (merged, {result.candidate_count:,} candidates)")

        def prepare_failed(message: str) -> None:
            self.run_button.setEnabled(True)
            self.run_button.setText("Run Aircrack-ng")
            self.progress.setRange(0, 1)
            self.progress.setValue(0)
            self._append(f"Wordlist preparation failed: {message}")
            QMessageBox.warning(self, "Wordlist preparation failed", message)

        self.tasks.start(
            lambda progress_cb: self.service.prepare_wordlist(
                wordlist_ids,
                max_candidates=limit,
                progress=lambda a, b, c, d: progress_cb((a, b, c, d)),
            ),
            on_done=prepared,
            on_error=prepare_failed,
            on_progress=prepare_progress,
            with_progress=True,
        )

    def copy_secret(self) -> None:
        if not self._secret:
            return
        QGuiApplication.clipboard().setText(self._secret)
        self._append("Recovered password copied to the Windows clipboard (not persisted).")

    def clear_secret(self) -> None:
        self._secret = ""
        self.copy_button.setEnabled(False)
        self.clear_secret_button.setEnabled(False)
        self._append("Recovered password cleared from application memory.")

    def closeEvent(self, event) -> None:              
        self._secret = ""
        self.tasks.shutdown()
        super().closeEvent(event)
