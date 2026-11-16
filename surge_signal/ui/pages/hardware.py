"""Compact hardware and research-environment diagnostics."""

from __future__ import annotations

import html

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..widgets import (
    Card,
    Chip,
    InfoBanner,
    SudoPasswordDialog,
    make_table,
    set_cell,
    set_chip_cell,
    set_column_widths,
)
from .base import BasePage


class HardwarePage(BasePage):
    title = "Hardware Diagnostics"
    subtitle = (
        "Adapter and research-environment capabilities. Monitor mode and injection are "
        "never inferred from ordinary Wi-Fi connectivity."
    )

    def __init__(self, service, window):
        super().__init__(service, window)
        self._report = None
        self._started = False
        self._build()

    def _build(self) -> None:
        self.diag_button = self.add_action("Run diagnostics", self.run_diagnostics, primary=True)
        self.env_button = self.add_action("Test Kali connection", self.test_research)
        self.sudo_button = self.add_action("Privileged interface scan", self.privileged_scan)
        self.sudo_button.setToolTip(
            "Read-only `iw dev` inventory in Kali through sudo. The password is used "
            "only for this operation and is never stored."
        )

        self.banner = InfoBanner(
            "A capability is shown as validated only when it was actually observed. "
            "Documented driver behaviour is labelled separately; unverified capabilities "
            "remain untested.",
            level="warn",
        )
        self.content.addWidget(self.banner)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(12)

        summary = QHBoxLayout()
        summary.setSpacing(12)

        self.adapter_card = Card(padding=14, spacing=7)
        self.adapter_card.add_title("Primary adapter")
        self.adapter_name = QLabel("Diagnostics not run")
        self.adapter_name.setProperty("role", "h2")
        self.adapter_name.setWordWrap(True)
        self.adapter_card.add(self.adapter_name)
        self.adapter_meta = QLabel("Run diagnostics to inspect the installed adapter.")
        self.adapter_meta.setProperty("role", "small")
        self.adapter_meta.setWordWrap(True)
        self.adapter_card.add(self.adapter_meta)
        self.adapter_detail = QLabel("")
        self.adapter_detail.setWordWrap(True)
        self.adapter_detail.setProperty("role", "muted")
        self.adapter_card.add(self.adapter_detail)
        self.adapter_card.body.addStretch(1)
        summary.addWidget(self.adapter_card, 3)

        self.readiness_card = Card(padding=14, spacing=7)
        self.readiness_card.add_title("Capability summary")
        self.readiness = QLabel("Untested")
        self.readiness.setProperty("role", "h2")
        self.readiness_card.add(self.readiness)
        self.capability_chips = QVBoxLayout()
        self.capability_chips.setSpacing(5)
        self.monitor_chip = self._capability_row("Monitor mode", "UNTESTED")
        self.injection_chip = self._capability_row("Frame injection", "UNTESTED")
        self.capture_chip = self._capability_row("Packet capture", "UNTESTED")
        self.readiness_card.body.addLayout(self.capability_chips)
        self.readiness_note = QLabel(
            "Validated only after capture and injection are tested in the configured "
            "Kali environment."
        )
        self.readiness_note.setProperty("role", "tiny")
        self.readiness_note.setWordWrap(True)
        self.readiness_card.add(self.readiness_note)
        summary.addWidget(self.readiness_card, 2)

        self.kali_card = Card(padding=14, spacing=7)
        self.kali_card.add_title("Kali research environment")
        self.kali_state = QLabel("Not checked")
        self.kali_state.setProperty("role", "h2")
        self.kali_card.add(self.kali_state)
        self.kali_detail = QLabel(
            "Configure WSL or SSH in Settings, then test the connection."
        )
        self.kali_detail.setProperty("role", "small")
        self.kali_detail.setWordWrap(True)
        self.kali_card.add(self.kali_detail)
        self.kali_tools = QLabel("")
        self.kali_tools.setProperty("role", "tiny")
        self.kali_tools.setWordWrap(True)
        self.kali_card.add(self.kali_tools)
        self.kali_last_action = QLabel("")
        self.kali_last_action.setProperty("role", "tiny")
        self.kali_last_action.setWordWrap(True)
        self.kali_card.add(self.kali_last_action)
        self.kali_card.body.addStretch(1)
        summary.addWidget(self.kali_card, 2)
        layout.addLayout(summary)

        caps_card = Card(padding=14, spacing=8)
        caps_card.add_title(
            "Wireless capability matrix",
            "Validated on this host, documented by the driver, or explicitly untested.",
        )
        self.caps_table = make_table(["Capability", "Status", "Finding"], stretch_column=2)
        set_column_widths(self.caps_table, {0: 190, 1: 140})
        self.caps_table.setWordWrap(True)
        self.caps_table.setMinimumHeight(230)
        caps_card.add(self.caps_table)
        layout.addWidget(caps_card)

        notes = QHBoxLayout()
        notes.setSpacing(12)
        self.limitations_card = Card(padding=14, spacing=6)
        self.limitations_card.add_title("Limitations")
        self.warnings_label = QLabel("Run diagnostics to surface adapter limitations.")
        self.warnings_label.setWordWrap(True)
        self.warnings_label.setProperty("role", "muted")
        self.limitations_card.add(self.warnings_label)
        self.limitations_card.body.addStretch(1)
        notes.addWidget(self.limitations_card, 1)

        self.next_card = Card(padding=14, spacing=6)
        self.next_card.add_title("Recommended next step")
        self.recs_label = QLabel("No recommendation yet.")
        self.recs_label.setWordWrap(True)
        self.recs_label.setProperty("role", "muted")
        self.next_card.add(self.recs_label)
        self.next_card.body.addStretch(1)
        notes.addWidget(self.next_card, 1)
        layout.addLayout(notes)
        layout.addStretch(1)
        scroll.setWidget(body)
        self.content.addWidget(scroll, 1)

    def _capability_row(self, name: str, value: str) -> Chip:
        row = QHBoxLayout()
        label = QLabel(name)
        label.setProperty("role", "small")
        label.setFixedWidth(115)
        row.addWidget(label)
        chip = Chip(value, "#a8a8a8")
        row.addWidget(chip)
        row.addStretch(1)
        self.capability_chips.addLayout(row)
        return chip

    def on_show(self) -> None:
        self.refresh()
        if not self._started and not self.window.smoke_test:
            self._started = True
            self.run_diagnostics(silent=True)

    def refresh(self) -> None:
        self.diag_button.setEnabled(True)
        if self._report is not None:
            self._render(self._report)

    def run_diagnostics(self, silent: bool = False) -> None:
        self.diag_button.setEnabled(False)
        self.diag_button.setText("Inspecting…")
        if not silent:
            self.notify("Collecting wireless adapter diagnostics…")

        def done(report) -> None:
            self.diag_button.setEnabled(True)
            self.diag_button.setText("Run diagnostics")
            self._report = report
            self._render(report)
            if not silent:
                self.notify("Hardware diagnostics complete.", "success")

        def failed(message: str) -> None:
            self.diag_button.setEnabled(True)
            self.diag_button.setText("Run diagnostics")
            self.notify(f"Diagnostics failed: {message}", "error")
            if not silent:
                QMessageBox.warning(self, "Diagnostics failed", message)

        self.tasks.start(self.service.diagnose_hardware, on_done=done, on_error=failed)

    def _render(self, report) -> None:
        primary = report.adapters[0] if report.adapters else None
        driver_data = report.driver_data.get("wireless_driver", {}) if report.driver_data else {}
        if primary:
            self.adapter_name.setText(primary.description or primary.name)
            meta = [primary.state or "state unknown", primary.radio_type or "radio unknown"]
            if primary.band:
                meta.append(primary.band)
            if primary.channel:
                meta.append(f"channel {primary.channel}")
            self.adapter_meta.setText("  ·  ".join(meta))
            driver = driver_data.get("driver", "")
            version = driver_data.get("version", "")
            provider = driver_data.get("provider", "")
            bits = [part for part in (driver, version, provider) if part]
            self.adapter_detail.setText(
                ("Driver: " + " · ".join(bits)) if bits else "Windows driver details not reported."
            )
        else:
            self.adapter_name.setText("No wireless adapter detected")
            self.adapter_meta.setText(
                report.warnings[0] if report.warnings else "Enable the adapter and retry."
            )
            self.adapter_detail.setText("")

        self.readiness.setText(report.readiness)
        caps = {cap.name: cap for cap in report.capabilities}
        monitor = caps.get("Monitor mode")
        injection = caps.get("Frame injection")
        capture = caps.get("Packet capture")
        self._set_cap_chip(self.monitor_chip, monitor)
        self._set_cap_chip(self.injection_chip, injection)
        self._set_cap_chip(self.capture_chip, capture)

        self.caps_table.setRowCount(0)
        for row, cap in enumerate(report.capabilities):
            self.caps_table.insertRow(row)
            set_cell(self.caps_table, row, 0, cap.name)
            colour = {
                "good": "#4ade80",
                "warn": "#f5c451",
                "bad": "#ff6b7a",
                "muted": "#a8a8a8",
            }[self._status_style(cap.status)]
            set_chip_cell(self.caps_table, row, 1, cap.status.upper(), colour)
            set_cell(self.caps_table, row, 2, cap.detail, tooltip=cap.detail)
        self.caps_table.resizeRowsToContents()

        self.warnings_label.setText(
            self._bullets(report.warnings[:4]) or "No adapter limitations reported."
        )
        self.recs_label.setText(
            self._bullets(report.recommendations[:2]) or "No recommendation."
        )

    def _set_cap_chip(self, chip: Chip, capability) -> None:
        if capability is None:
            chip.setText("NOT REPORTED")
            chip.set_colour("#a8a8a8")
            return
        colour = {
            "good": "#4ade80",
            "warn": "#f5c451",
            "bad": "#ff6b7a",
            "muted": "#a8a8a8",
        }[self._status_style(capability.status)]
        chip.setText(capability.status.upper())
        chip.set_colour(colour)

    @staticmethod
    def _status_style(status: str) -> str:
        lowered = status.lower()
        if lowered in {"validated", "supported", "documented"}:
            return "good"
        if lowered in {"limited", "conditional", "kernel-dependent"}:
            return "warn"
        if lowered in {"not supported", "unsupported", "blocked"}:
            return "bad"
        return "muted"

    @staticmethod
    def _bullets(items: list[str]) -> str:
        return "<br><br>".join(f"• {html.escape(item)}" for item in items)

    def test_research(self) -> None:
        self.env_button.setEnabled(False)
        self.kali_state.setText("Checking…")
        if not self.window.smoke_test:
            self.notify("Checking the Kali research environment…")

        def done(status) -> None:
            self.env_button.setEnabled(True)
            self.kali_state.setText(status.label)
            detail = status.detail
            if status.environment or status.username:
                detail = (
                    f"{status.environment or 'Kali'} · {status.username or 'unknown user'} · "
                    f"kernel {status.kernel or 'unknown'}\n{detail}"
                )
            self.kali_detail.setText(detail)
            if status.guidance:
                self.kali_tools.setText("• " + "\n• ".join(status.guidance))
            elif status.tools:
                self.kali_tools.setText(
                    "Tools: "
                    + ", ".join(
                        f"{name} {'✓' if ok else '✗'}" for name, ok in status.tools.items()
                    )
                )
            else:
                self.kali_tools.setText("")
            self.window.set_environment_status(
                bool(status.available and status.aircrack),
                f"{status.mode.upper()} · {'ready' if status.available else 'unavailable'}",
            )
            self.notify(status.label, "success" if status.available else "warn")

        def failed(message: str) -> None:
            self.env_button.setEnabled(True)
            self.kali_state.setText("Unavailable")
            self.kali_detail.setText(message)
            self.window.set_environment_status(False, "Unavailable")
            self.notify(f"Environment check failed: {message}", "error")

        self.tasks.start(self.service.research_status, on_done=done, on_error=failed)

    def privileged_scan(self) -> None:
        if self.window.smoke_test:
            return
        dialog = SudoPasswordDialog(
            "Read-only wireless interface inventory (iw dev) in Kali", self
        )
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        password = dialog.password_value
        dialog.password_value = ""
        secret = [password]
        self.sudo_button.setEnabled(False)
        self.sudo_button.setText("Authenticating…")
        self.notify("Running read-only privileged interface diagnostics…")

        def task():
            try:
                return self.service.privileged_interface_diagnostics(secret[0])
            finally:
                secret[0] = ""

        def done(result) -> None:
            self.sudo_button.setEnabled(True)
            self.sudo_button.setText("Privileged interface scan")
            if result.ok:
                self.kali_last_action.setText("Last privileged check: completed successfully.")
                self.notify("Privileged interface diagnostics completed.", "success")
            else:
                self.kali_last_action.setText(
                    "Last privileged check failed: " + (result.stderr.strip() or "unknown error")
                )
                self.notify(
                    result.stderr.strip() or "Privileged diagnostics failed.", "error"
                )

        def failed(message: str) -> None:
            self.sudo_button.setEnabled(True)
            self.sudo_button.setText("Privileged interface scan")
            self.kali_last_action.setText("Last privileged check failed: " + message)
            self.notify(message, "error")

        self.tasks.start(task, on_done=done, on_error=failed)

