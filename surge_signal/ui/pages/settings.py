"""Application and research-environment settings."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import Qt

from ...core.branding import APP_NAME, APP_VERSION, PRODUCT_DESCRIPTION
from ..widgets import BrandBanner, Card, InfoBanner, KeyValueRow, open_path
from .base import BasePage


class SettingsPage(BasePage):
    title = "Settings"
    subtitle = (
        "Research transport, storage and safety limits. Linux passwords are never "
        "requested here and are never persisted."
    )

    def __init__(self, service, window):
        super().__init__(service, window)
        self._build()
        self._loaded = False

    def _build(self) -> None:
        self.save_button = self.add_action("Save settings", self.save, primary=True)
        self.test_button = self.add_action("Test Kali connection", self.test_connection)
        self.add_action("Check database", self.check_database)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        body = QWidget()
        columns = QHBoxLayout(body)
        columns.setContentsMargins(0, 0, 8, 0)
        columns.setSpacing(14)
        left = QVBoxLayout()
        right = QVBoxLayout()
        left.setSpacing(14)
        right.setSpacing(14)
        columns.addLayout(left, 1)
        columns.addLayout(right, 1)

        research = Card()
        research.add_title("Kali research environment")
        research_note = QLabel(
            "WSL2 is useful for offline tooling but is not assumed to provide direct "
            "monitor-mode access. Use the Kali VM with USB passthrough or a separate "
            "research host for radio-level work."
        )
        research_note.setProperty("role", "small")
        research_note.setWordWrap(True)
        research.add(research_note)
        form = QFormLayout()
        form.setSpacing(9)
        self.mode = QComboBox()
        self.mode.addItem("Linux / Kali (native)", "native")
        self.mode.addItem("WSL2", "wsl")
        self.mode.addItem("SSH (key authentication)", "ssh")
        self.mode.addItem("Manual shared folder", "manual")
        self.mode.currentIndexChanged.connect(lambda _index: self._mode_changed())
        self.wsl_distro = QLineEdit()
        self.wsl_distro.setPlaceholderText("kali-linux")
        self.ssh_host = QLineEdit()
        self.ssh_host.setPlaceholderText("192.168.56.10 or hostname")
        self.ssh_user = QLineEdit()
        self.ssh_user.setPlaceholderText("kali username")
        self.kali_share = QLineEdit()
        self.kali_share.setPlaceholderText(r"C:\SurgeSignalShare")
        self.kali_linux_share = QLineEdit()
        self.kali_linux_share.setPlaceholderText("/mnt/surge")
        self.aircrack = QLineEdit()
        self.aircrack.setPlaceholderText("aircrack-ng")
        self.tshark = QLineEdit()
        self.tshark.setPlaceholderText("tshark")
        self.sudo_timeout = QSpinBox()
        self.sudo_timeout.setRange(15, 900)
        self.sudo_timeout.setSuffix(" s")
        form.addRow("Transport", self.mode)
        form.addRow("WSL distribution", self.wsl_distro)
        form.addRow("SSH host", self.ssh_host)
        form.addRow("SSH user", self.ssh_user)
        form.addRow("Windows share", self.kali_share)
        form.addRow("Linux share mount", self.kali_linux_share)
        form.addRow("aircrack-ng command", self.aircrack)
        form.addRow("tshark command", self.tshark)
        form.addRow("sudo timeout", self.sudo_timeout)
        research.body.addLayout(form)
        self.env_result = QLabel("Not checked")
        self.env_result.setProperty("role", "small")
        self.env_result.setWordWrap(True)
        research.add(self.env_result)
        left.addWidget(research)

        security = Card()
        security.add_title("Authentication and safety")
        security_text = QLabel(
            "Privileged operations prompt for the Linux account password when needed. "
            "The password is passed to sudo over standard input only — never through "
            "command-line arguments, environment variables, logs or SQLite. Native sudo "
            "policy and timeout remain in control. This release excludes deauthentication, "
            "rogue access points, injection and automated attacks."
        )
        security_text.setWordWrap(True)
        security_text.setProperty("role", "muted")
        security.add(security_text)
        left.addWidget(security)
        left.addStretch(1)

        application = Card()
        application.add_title("Application and operator")
        app_form = QFormLayout()
        app_form.setSpacing(9)
        self.operator = QLineEdit()
        self.operator.setPlaceholderText("Default tester name")
        self.auto_scan = QCheckBox(
            "Automatically discover nearby Wi-Fi when an assessment opens"
        )
        self.auto_interval = QSpinBox()
        self.auto_interval.setRange(20, 600)
        self.auto_interval.setSuffix(" s")
        self.max_local = QSpinBox()
        self.max_local.setRange(100, 5_000_000)
        self.max_local.setSingleStep(10_000)
        self.max_local.setSuffix(" candidates")
        self.wordlist_min = QSpinBox()
        self.wordlist_min.setRange(8, 63)
        self.wordlist_max = QSpinBox()
        self.wordlist_max.setRange(8, 63)
        self.wordlist_cap = QSpinBox()
        self.wordlist_cap.setRange(1, 5_000_000)
        self.wordlist_cap.setSingleStep(10_000)
        self.wordlist_cap.setSuffix(" candidates")
        self.prune_keep = QSpinBox()
        self.prune_keep.setRange(0, 100)
        self.prune_keep.setSuffix(" prepared files")
        self.report_dir = QLineEdit()
        self.report_dir.setPlaceholderText(str(self.service.paths.reports))
        self.capture_dir = QLineEdit()
        self.capture_dir.setPlaceholderText(str(self.service.settings.capture_output_dir()))
        capture_browse = QPushButton("Browse…")
        capture_browse.clicked.connect(self._browse_capture_dir)
        capture_holder = QHBoxLayout()
        capture_holder.addWidget(self.capture_dir, 1)
        capture_holder.addWidget(capture_browse)
        capture_widget = QWidget()
        capture_widget.setLayout(capture_holder)
        app_form.addRow("Default operator", self.operator)
        app_form.addRow("Auto-discovery", self.auto_scan)
        app_form.addRow("Refresh interval", self.auto_interval)
        app_form.addRow("Local verifier cap", self.max_local)
        app_form.addRow("WPA min length", self.wordlist_min)
        app_form.addRow("WPA max length", self.wordlist_max)
        app_form.addRow("Prepared list cap", self.wordlist_cap)
        app_form.addRow("Retain prepared", self.prune_keep)
        app_form.addRow("Capture output", capture_widget)
        app_form.addRow("Report output", self.report_dir)
        application.body.addLayout(app_form)
        right.addWidget(application)

        storage = Card()
        storage.add_title("Local storage")
        self.path_rows = {
            "home": KeyValueRow("Data directory", str(self.service.paths.home)),
            "db": KeyValueRow("Database", str(self.service.paths.database)),
            "evidence": KeyValueRow("Evidence", str(self.service.paths.evidence)),
            "wordlists": KeyValueRow("Wordlists", str(self.service.paths.wordlists)),
            "reports": KeyValueRow("Reports", str(self.service.paths.reports)),
        }
        for row in self.path_rows.values():
            storage.add(row)
        actions = QHBoxLayout()
        open_data = QPushButton("Open data folder")
        open_data.clicked.connect(lambda: open_path(self.service.paths.home))
        open_wordlists = QPushButton("Open wordlists")
        open_wordlists.clicked.connect(lambda: open_path(self.service.paths.wordlists))
        actions.addWidget(open_data)
        actions.addWidget(open_wordlists)
        actions.addStretch(1)
        storage.body.addLayout(actions)
        right.addWidget(storage)

        integrity = Card()
        integrity.add_title("Data integrity")
        self.integrity_label = QLabel(
            "Run a SQLite integrity and foreign-key check to verify assessment records."
        )
        self.integrity_label.setProperty("role", "small")
        self.integrity_label.setWordWrap(True)
        integrity.add(self.integrity_label)
        right.addWidget(integrity)

        about = Card()
        about.add_title("About", f"{APP_NAME} {APP_VERSION}")
        about.add(BrandBanner(height=150))
        about_text = QLabel(PRODUCT_DESCRIPTION)
        about_text.setWordWrap(True)
        about_text.setProperty("role", "muted")
        about.add(about_text)
        rights = QLabel(
            "For authorised security assessment only. You are responsible for obtaining "
            "written permission before testing any wireless network."
        )
        rights.setWordWrap(True)
        rights.setProperty("role", "warning")
        about.add(rights)
        right.addWidget(about)
        right.addStretch(1)

        scroll.setWidget(body)
        self.content.addWidget(scroll, 1)

    def on_show(self) -> None:
        if not self._loaded:
            self._loaded = True
            self.load()
        self.refresh()

    def refresh(self) -> None:
        pass

    def load(self) -> None:
        s = self.service.settings
        index = self.mode.findData(s.get("research_mode", "wsl"))
        self.mode.setCurrentIndex(max(0, index))
        self.wsl_distro.setText(s.get("wsl_distro", "kali-linux"))
        self.ssh_host.setText(s.get("ssh_host", ""))
        self.ssh_user.setText(s.get("ssh_user", ""))
        self.kali_share.setText(s.get("kali_share", ""))
        self.kali_linux_share.setText(s.get("kali_linux_share", "/mnt/surge"))
        self.aircrack.setText(s.get("aircrack_path", "aircrack-ng"))
        self.tshark.setText(s.get("tshark_path", "tshark"))
        self.sudo_timeout.setValue(s.get_int("sudo_timeout_seconds", 120))
        self.operator.setText(s.get("operator_name", ""))
        self.auto_scan.setChecked(s.get_bool("auto_scan_on_open", True))
        self.auto_interval.setValue(s.get_int("auto_scan_interval_seconds", 45))
        self.max_local.setValue(s.get_int("max_local_candidates", 100_000))
        self.wordlist_min.setValue(s.get_int("wordlist_include_min", 8))
        self.wordlist_max.setValue(s.get_int("wordlist_include_max", 63))
        self.wordlist_cap.setValue(s.get_int("wordlist_max_candidates", 1_000_000))
        self.prune_keep.setValue(s.get_int("wordlist_prune_keep", 10))
        self.report_dir.setText(s.get("report_output_dir", str(self.service.paths.reports)))
        self.capture_dir.setText(s.capture_output_dir().__str__())
        self._mode_changed()

    def _browse_capture_dir(self) -> None:
        folder = QFileDialog.getExistingDirectory(
            self, "Select capture output folder", self.capture_dir.text()
        )
        if folder:
            self.capture_dir.setText(folder)

    def _mode_changed(self) -> None:
        mode = self.mode.currentData()
        self.wsl_distro.setEnabled(mode == "wsl")
        self.ssh_host.setEnabled(mode == "ssh")
        self.ssh_user.setEnabled(mode == "ssh")

    def save(self) -> bool:
        if self.wordlist_min.value() > self.wordlist_max.value():
            QMessageBox.warning(
                self, "Invalid length policy", "Minimum WPA length exceeds maximum length."
            )
            return False
        s = self.service.settings
        s.set("research_mode", self.mode.currentData())
        s.set("wsl_distro", self.wsl_distro.text().strip() or "kali-linux")
        s.set("ssh_host", self.ssh_host.text().strip())
        s.set("ssh_user", self.ssh_user.text().strip())
        s.set("kali_share", self.kali_share.text().strip())
        s.set("kali_linux_share", self.kali_linux_share.text().strip() or "/mnt/surge")
        s.set("aircrack_path", self.aircrack.text().strip() or "aircrack-ng")
        s.set("tshark_path", self.tshark.text().strip() or "tshark")
        s.set("sudo_timeout_seconds", self.sudo_timeout.value())
        s.set("operator_name", self.operator.text().strip())
        s.set("auto_scan_on_open", self.auto_scan.isChecked())
        s.set("auto_scan_interval_seconds", self.auto_interval.value())
        s.set("max_local_candidates", self.max_local.value())
        s.set("wordlist_include_min", self.wordlist_min.value())
        s.set("wordlist_include_max", self.wordlist_max.value())
        s.set("wordlist_max_candidates", self.wordlist_cap.value())
        s.set("wordlist_prune_keep", self.prune_keep.value())
        s.set("report_output_dir", self.report_dir.text().strip())
        s.set("capture_output_dir", self.capture_dir.text().strip())
        self.notify("Settings saved.", "success")
        return True

    def test_connection(self) -> None:
        if not self.save():
            return
        self.test_button.setEnabled(False)
        self.test_button.setText("Testing…")
        self.env_result.setText("Checking the configured research environment…")

        def done(status) -> None:
            self.test_button.setEnabled(True)
            self.test_button.setText("Test Kali connection")
            detail = f"{status.mode.upper()} · {status.label}\n{status.detail}"
            if status.environment:
                detail = f"{status.environment} · user {status.username or 'unknown'} · kernel {status.kernel}\n{detail}"
            if status.guidance:
                detail += "\n• " + "\n• ".join(status.guidance)
            self.env_result.setText(detail)
            self.window.set_environment_status(
                bool(status.available and status.aircrack),
                f"{status.mode.upper()} · {'ready' if status.available else 'unavailable'}",
            )
            self.notify(status.label, "success" if status.available else "warn")

        def failed(message: str) -> None:
            self.test_button.setEnabled(True)
            self.test_button.setText("Test Kali connection")
            self.env_result.setText(message)
            self.notify(f"Connection test failed: {message}", "error")

        self.tasks.start(self.service.research_status, on_done=done, on_error=failed)

    def check_database(self) -> None:
        self.tasks.start(
            self.service.integrity_check,
            on_done=self._integrity_done,
            on_error=lambda message: self.integrity_label.setText(message),
        )

    def _integrity_done(self, result) -> None:
        ok, detail = result
        self.integrity_label.setText(detail)
        self.integrity_label.setStyleSheet("color:#4ade80;" if ok else "color:#ff9bad;")
        self.notify(detail, "success" if ok else "error")


