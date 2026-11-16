"""Guided passive monitor-mode capture through Kali tools."""

from __future__ import annotations

import re
import time
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
)

from ..core.domain import Assessment, AssessmentStatus, normalize_bssid, valid_bssid
from ..core.services import SurgeService
from .widgets import Chip, InfoBanner, TaskRunner

ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


class KaliCaptureDialog(QDialog):
    """Passive, time-bounded capture using aircrack-ng's airodump-ng.

    No deauthentication or injection is performed. If no handshake arrives, the
    operator can reconnect a client to the authorised lab network and try again.
    """

    capture_imported = Signal()

    def __init__(self, service: SurgeService, assessment: Assessment, parent=None):
        super().__init__(parent)
        self.service = service
        self.assessment = assessment
        self.tasks = TaskRunner(self, max_threads=1)
        self._networks = service.db.list_networks(assessment.id)
        self._monitor_interface = ""
        self.setWindowTitle("Kali live capture — authorised laboratory")
        self.setModal(False)
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.resize(900, 700)
        self._build()
        self._populate_networks()

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 12)
        outer.setSpacing(9)
        title = QLabel("Capture a WPA handshake from Kali")
        title.setProperty("role", "h1")
        outer.addWidget(title)
        subtitle = QLabel(
            f"Assessment: {self.assessment.name} ({self.assessment.id})  ·  "
            "Passive monitor-mode capture only. No deauthentication or injection."
        )
        subtitle.setProperty("role", "small")
        subtitle.setWordWrap(True)
        outer.addWidget(subtitle)
        outer.addWidget(
            InfoBanner(
                "This requires a Kali VM or host with USB passthrough and an adapter "
                "that supports monitor mode. The internal Realtek RTL8822CE is usually "
                "a client-only adapter. WSL2 cannot capture the internal radio.",
                level="warn",
            )
        )

        auth = QFrame()
        auth.setObjectName("Card")
        auth_grid = QGridLayout(auth)
        auth_grid.setContentsMargins(12, 10, 12, 10)
        auth_grid.setHorizontalSpacing(8)
        auth_grid.setVerticalSpacing(5)
        auth_grid.addWidget(self._caption("Kali password"), 0, 0)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Used only for sudo; never stored")
        auth_grid.addWidget(self.password, 1, 0, 1, 2)
        self.detect_button = QPushButton("Detect adapters")
        self.detect_button.setProperty("variant", "primary")
        self.detect_button.clicked.connect(self.detect_adapters)
        auth_grid.addWidget(self.detect_button, 1, 2)
        self.adapter_combo = QComboBox()
        self.adapter_combo.setMinimumWidth(260)
        self.adapter_combo.setPlaceholderText("Detect an adapter first")
        auth_grid.addWidget(self._caption("Wireless adapter"), 2, 0)
        auth_grid.addWidget(self.adapter_combo, 3, 0)
        self.monitor_button = QPushButton("Enable monitor mode")
        self.monitor_button.clicked.connect(self.enable_monitor)
        auth_grid.addWidget(self.monitor_button, 3, 1)
        self.monitor_label = QLabel("Monitor interface: not configured")
        self.monitor_label.setProperty("role", "small")
        auth_grid.addWidget(self.monitor_label, 3, 2)
        outer.addWidget(auth)

        target = QFrame()
        target.setObjectName("Card")
        target_grid = QGridLayout(target)
        target_grid.setContentsMargins(12, 10, 12, 10)
        target_grid.setHorizontalSpacing(8)
        target_grid.setVerticalSpacing(5)
        target_grid.addWidget(self._caption("Nearby authorised network"), 0, 0)
        self.bssid = QComboBox()
        self.bssid.setEditable(True)
        self.bssid.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.bssid.lineEdit().setPlaceholderText("Select a scanned network or enter a BSSID")
        self.bssid.currentTextChanged.connect(self._target_changed)
        target_grid.addWidget(self.bssid, 1, 0, 1, 3)
        target_grid.addWidget(self._caption("Channel"), 2, 0)
        self.channel = QSpinBox()
        self.channel.setRange(1, 233)
        self.channel.setValue(6)
        target_grid.addWidget(self.channel, 3, 0)
        target_grid.addWidget(self._caption("Capture duration"), 2, 1)
        self.duration = QSpinBox()
        self.duration.setRange(30, 900)
        self.duration.setValue(180)
        self.duration.setSuffix(" seconds")
        target_grid.addWidget(self.duration, 3, 1)
        target_grid.addWidget(self._caption("Scope"), 2, 2)
        self.scope_chip = Chip("SCOPE UNKNOWN", "#a8a8a8")
        target_grid.addWidget(self.scope_chip, 3, 2)
        self.scope_note = QLabel(
            "Select the network you own or are authorised to capture. No pre-approval "
            "list is required."
        )
        self.scope_note.setProperty("role", "small")
        self.scope_note.setWordWrap(True)
        target_grid.addWidget(self.scope_note, 4, 0, 1, 3)
        self.authorised = QCheckBox(
            "I confirm this is my own or an explicitly authorised laboratory network."
        )
        self.authorised.toggled.connect(self._target_changed)
        target_grid.addWidget(self.authorised, 5, 0, 1, 3)
        outer.addWidget(target)

        actions = QHBoxLayout()
        self.capture_button = QPushButton("Start passive capture")
        self.capture_button.setProperty("variant", "primary")
        self.capture_button.setEnabled(False)
        self.capture_button.clicked.connect(self.start_capture)
        actions.addWidget(self.capture_button)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        actions.addWidget(self.progress, 1)
        close = QPushButton("Close")
        close.clicked.connect(self.reject)
        actions.addWidget(close)
        outer.addLayout(actions)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMaximumBlockCount(3000)
        self.output.setStyleSheet(
            "QPlainTextEdit{background:#1e1e1e;color:#f0f0f0;border:1px solid #55555a;"
            "border-radius:0px;padding:6px;font-family:Consolas,monospace;}"
        )
        outer.addWidget(self.output, 1)

    @staticmethod
    def _caption(text: str) -> QLabel:
        label = QLabel(text)
        label.setProperty("role", "small")
        return label

    def _append(self, text: str) -> None:
        self.output.appendPlainText(ANSI_RE.sub("", f"{time.strftime('%H:%M:%S')}  {text}"))
        self.output.verticalScrollBar().setValue(self.output.verticalScrollBar().maximum())

    def _populate_networks(self) -> None:
        self.bssid.blockSignals(True)
        self.bssid.clear()
        self.bssid.addItem("Select a nearby network…", None)
        for network in self._networks:
            self.bssid.addItem(
                f"{network.display_ssid}  ·  {network.bssid}  ·  Ch {network.channel or '—'}"
                f" / {network.band}  ·  {network.signal_dbm or '—'} dBm",
                network.bssid,
            )
        self.bssid.blockSignals(False)
        self._target_changed()

    def _current_bssid(self) -> str:
        data = self.bssid.currentData()
        if data:
            return normalize_bssid(str(data))
        match = re.search(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", self.bssid.currentText())
        return normalize_bssid(match.group(0)) if match else ""

    def _target_changed(self) -> None:
        bssid = self._current_bssid()
        network = next((n for n in self._networks if n.bssid == bssid), None)
        if network and network.channel:
            self.channel.setValue(network.channel)
        if not valid_bssid(bssid):
            self.scope_chip.setText("SELECT A NETWORK")
            self.scope_chip.set_colour("#a8a8a8")
        else:
            self.scope_chip.setText("TARGET SELECTED")
            self.scope_chip.set_colour("#4ade80")
        self.capture_button.setEnabled(
            bool(self._monitor_interface)
            and valid_bssid(bssid)
            and self.authorised.isChecked()
        )

    def _password(self) -> str:
        value = self.password.text()
        if not value:
            QMessageBox.information(
                self,
                "Kali password required",
                "Enter the Kali account password. It is used only for sudo and is not stored.",
            )
        return value

    def detect_adapters(self) -> None:
        password = self._password()
        if not password:
            return
        self.detect_button.setEnabled(False)
        self.detect_button.setText("Detecting…")
        self.progress.setRange(0, 0)
        self._append("Reading wireless interfaces from Kali…")
        secret = [password]

        def task():
            try:
                result = self.service.connector.run_privileged(["iw", "dev"], secret[0])
                return result
            finally:
                secret[0] = ""

        def done(result) -> None:
            self.detect_button.setEnabled(True)
            self.detect_button.setText("Detect adapters")
            self.progress.setRange(0, 1)
            self.progress.setValue(1)
            output = ANSI_RE.sub("", result.stdout or "") + ANSI_RE.sub("", result.stderr or "")
            self._append(output.strip() or "No output.")
            self.adapter_combo.clear()
            clean_listing = ANSI_RE.sub("", output)
            for block in re.split(r"(?=^Interface\s+)", clean_listing, flags=re.MULTILINE)[1:]:
                first = block.splitlines()[0]
                name = first.split(None, 1)[1].strip()
                                                                             
                if not re.search(r"^\s*type\s+(managed|monitor|AP|mesh|P2P)", block, re.M):
                    continue
                self.adapter_combo.addItem(name, name)
            if self.adapter_combo.count() == 0:
                self._append(
                    "No wireless interface was reported by iw dev. In WSL this usually "
                    "means the Windows PCIe Wi-Fi card is not passed through; attach a "
                    "USB adapter with usbipd or use a Kali VM."
                )
                QMessageBox.warning(
                    self,
                    "No adapter found",
                    "Kali did not report a wireless interface. Attach/pass through a "
                    "supported USB adapter and confirm it appears in lsusb and iw dev.",
                )
            else:
                self._append(f"Found {self.adapter_combo.count()} interface(s).")

        def failed(message: str) -> None:
            self.detect_button.setEnabled(True)
            self.detect_button.setText("Detect adapters")
            self.progress.setRange(0, 1)
            self.progress.setValue(0)
            self._append(f"Adapter detection failed: {message}")
            QMessageBox.warning(self, "Adapter detection failed", message)

        self.tasks.start(task, on_done=done, on_error=failed)

    def enable_monitor(self) -> None:
        password = self._password()
        if not password:
            return
        interface = self.adapter_combo.currentData()
        if not interface:
            QMessageBox.information(self, "Adapter required", "Detect and select an adapter first.")
            return
        self.monitor_button.setEnabled(False)
        self.monitor_button.setText("Enabling…")
        self.progress.setRange(0, 0)
        self._append(f"Enabling monitor mode on {interface}…")
        secret = [password]

        def task():
            try:
                start = self.service.connector.run_privileged(
                    ["airmon-ng", "start", interface], secret[0], timeout=120
                )
                listing = self.service.connector.run_privileged(
                    ["iw", "dev"], secret[0], timeout=60
                )
                return start, listing
            finally:
                secret[0] = ""

        def done(payload) -> None:
            start, listing = payload
            self.monitor_button.setEnabled(True)
            self.monitor_button.setText("Enable monitor mode")
            self.progress.setRange(0, 1)
            self.progress.setValue(1)
            output = ANSI_RE.sub("", (start.stdout or "") + "\n" + (start.stderr or ""))
            self._append(output.strip())
            monitor = ""
            for match in re.finditer(r"Interface\s+(\S+)", ANSI_RE.sub("", listing.stdout or "")):
                name = match.group(1)
                if "mon" in name.lower():
                    monitor = name
            if not monitor:
                match = re.search(
                    r"monitor mode.*?on\s+(?:\[[^\]]+\])?(\w+)",
                    output,
                    re.IGNORECASE | re.DOTALL,
                )
                if match:
                    monitor = match.group(1)
            if not monitor:
                self._append(
                    "Monitor mode could not be confirmed. Review the airmon-ng output; "
                    "the adapter may not support monitor mode."
                )
                QMessageBox.warning(
                    self,
                    "Monitor mode not confirmed",
                    "airmon-ng did not report a monitor interface. Check that the adapter "
                    "supports monitor mode and is visible in Kali.",
                )
                return
            self._monitor_interface = monitor
            self.monitor_label.setText(f"Monitor interface: {monitor}")
            self._append(f"Monitor interface ready: {monitor}")
            self._target_changed()
        def failed(message: str) -> None:
            self.monitor_button.setEnabled(True)
            self.monitor_button.setText("Enable monitor mode")
            self.progress.setRange(0, 1)
            self.progress.setValue(0)
            self._append(f"Monitor mode failed: {message}")
            QMessageBox.warning(self, "Monitor mode failed", message)

        self.tasks.start(task, on_done=done, on_error=failed)

    def start_capture(self) -> None:
        if not self._monitor_interface:
            QMessageBox.information(self, "Monitor mode required", "Enable monitor mode first.")
            return
        bssid = self._current_bssid()
        if not valid_bssid(bssid):
            QMessageBox.warning(self, "Select a network", "Choose the network to capture.")
            return
        if not self.authorised.isChecked():
            QMessageBox.information(self, "Authorisation required", "Confirm authorised laboratory use.")
            return
        password = self._password()
        if not password:
            return
        channel = self.channel.value()
        duration = self.duration.value()
        capture_dir = self.service.settings.capture_output_dir()
        capture_dir.mkdir(parents=True, exist_ok=True)
        stem = f"live-{time.strftime('%Y%m%d-%H%M%S')}"
        windows_stem = capture_dir / stem
        linux_stem = self.service.connector.to_linux_path(windows_stem)
        secret = [password]
        self.capture_button.setEnabled(False)
        self.progress.setRange(0, 0)
        self._append(f"Capture files will be kept in: {capture_dir}")
        self._append(
            f"Passive capture: {duration}s on channel {channel} for {bssid}. "
            "No deauthentication will be sent. Reconnect a client to the lab network "
            "if the handshake does not arrive."
        )

        def task():
            result = None
            try:
                result = self.service.connector.run_privileged(
                    [
                        "timeout",
                        str(duration),
                        "airodump-ng",
                        "--bssid",
                        bssid,
                        "-c",
                        str(channel),
                        "--output-format",
                        "pcap",
                        "-w",
                        linux_stem,
                        self._monitor_interface,
                    ],
                    secret[0],
                    timeout=duration + 60,
                )
                return result
            finally:
                secret[0] = ""
                try:
                    self.service.connector.run_privileged(
                        ["airmon-ng", "stop", self._monitor_interface],
                        password,
                        timeout=60,
                    )
                except Exception:
                    pass

        def done(result) -> None:
            self.capture_button.setEnabled(True)
            self.progress.setRange(0, 1)
            self.progress.setValue(1)
            self._append(ANSI_RE.sub("", (result.stdout or "") + "\n" + (result.stderr or "")).strip())
            self._monitor_interface = ""
            self.monitor_label.setText("Monitor interface: stopped")
            self.capture_button.setEnabled(False)
            cap_files = sorted(capture_dir.glob(f"{stem}*.cap"))
            if not cap_files:
                self._append("No .cap file was produced. Check the monitor interface and permissions.")
                QMessageBox.warning(self, "Capture failed", "No capture file was produced.")
                return
            try:
                capture = self.service.import_capture(self.assessment.id, cap_files[-1])
            except Exception as exc:                
                self._append(f"Capture was recorded but could not be imported: {exc}")
                QMessageBox.warning(self, "Import failed", str(exc))
                return
            complete = sum(
                1 for item in capture.metadata.get("handshakes", []) if item.get("complete")
            )
            self.capture_imported.emit()
            self._append(
                f"Imported {capture.filename}: {capture.packet_count:,} packets, "
                f"{complete} complete handshake(s)."
            )
            self._append(f"Original capture remains at: {cap_files[-1]}")
            if complete:
                QMessageBox.information(
                    self,
                    "Handshake captured",
                    "A complete handshake was captured and imported. You can now run "
                    "Aircrack-ng from the Kali terminal.",
                )
            else:
                QMessageBox.information(
                    self,
                    "Capture imported",
                    "The capture was imported but no complete handshake was found. "
                    "Reconnect a client to the authorised lab network and capture again.",
                )

        def failed(message: str) -> None:
            self.capture_button.setEnabled(True)
            self.progress.setRange(0, 1)
            self.progress.setValue(0)
            self._append(f"Capture failed: {message}")
            QMessageBox.warning(self, "Capture failed", message)

        self.tasks.start(task, on_done=done, on_error=failed)

    def closeEvent(self, event) -> None:              
        if self._monitor_interface:
            password = self.password.text()
            if password:
                try:
                    self.service.connector.run_privileged(
                        ["airmon-ng", "stop", self._monitor_interface],
                        password,
                        timeout=30,
                    )
                except Exception:
                    pass
            self._monitor_interface = ""
        self.tasks.shutdown()
        super().closeEvent(event)
