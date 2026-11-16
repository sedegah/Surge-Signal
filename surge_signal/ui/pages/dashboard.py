"""Dashboard: workspace overview, posture and environment readiness."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ...core.branding import APP_NAME, SEVERITY_COLORS
from ...core.domain import AssessmentStatus, human_time
from ..widgets import (
    BrandBanner,
    Card,
    Chip,
    EmptyState,
    KeyValueRow,
    SeverityBreakdown,
    StatCard,
    format_number,
    make_table,
    set_cell,
    set_chip_cell,
    set_column_widths,
    severity_colour,
)
from .base import BasePage


class DashboardPage(BasePage):
    title = "Security workspace"
    subtitle = (
        "Authorised wireless assessment overview, current posture and research "
        "environment readiness."
    )

    def __init__(self, service, window):
        super().__init__(service, window)
        self._diagnostics_started = False
        self._research_started = False
        self._build()

    def _build(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(16)

        self.no_assessment = EmptyState(
            "Create your first assessment workspace",
            "SURGE Signal keeps discovery, captures, findings, wordlists and reports "
            "inside an authorised assessment. Start by defining the assessment scope, "
            "organisation and permitted laboratory BSSIDs.",
            "Create assessment",
        )
        self.no_assessment.button.clicked.connect(
            lambda: self.window.open_assessments(create=True)
        )
        self.banner = BrandBanner(height=190)
        layout.addWidget(self.banner)
        layout.addWidget(self.no_assessment)

        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        self.stat_assessments = StatCard("Assessments", "0", "No workspace yet", accent=True)
        self.stat_networks = StatCard("Networks", "0", "Across all assessments")
        self.stat_findings = StatCard("Findings", "0", "Recorded findings")
        self.stat_captures = StatCard("Captures", "0", "Registered evidence")
        self.stat_audits = StatCard("Offline audits", "0", "Completed audits")
        for card in (
            self.stat_assessments,
            self.stat_networks,
            self.stat_findings,
            self.stat_captures,
            self.stat_audits,
        ):
            stats_row.addWidget(card, 1)
        layout.addLayout(stats_row)

        grid = QHBoxLayout()
        grid.setSpacing(14)
        left = QVBoxLayout()
        left.setSpacing(14)
        right = QVBoxLayout()
        right.setSpacing(14)
        grid.addLayout(left, 3)
        grid.addLayout(right, 2)

        self.current_card = Card()
        self.current_card.add_title("Current assessment", "Active engagement context")
        self.current_name = QLabel("No assessment selected")
        self.current_name.setProperty("role", "h1")
        self.current_name.setWordWrap(True)
        self.current_card.add(self.current_name)
        self.current_org = QLabel("")
        self.current_org.setProperty("role", "muted")
        self.current_card.add(self.current_org)
        self.current_rows = {
            "status": KeyValueRow("Status", "—"),
            "scope": KeyValueRow("Scope", "—"),
            "targets": KeyValueRow("Permitted targets", "0"),
            "tester": KeyValueRow("Tester", "—"),
            "dates": KeyValueRow("Assessment dates", "—"),
        }
        for row in self.current_rows.values():
            self.current_card.add(row)
        current_actions = QHBoxLayout()
        open_btn = QPushButton("Open assessment workspace")
        open_btn.clicked.connect(lambda: self.window.navigate("assessments"))
        scan_btn = QPushButton("Scan wireless networks")
        scan_btn.setProperty("variant", "primary")
        scan_btn.clicked.connect(lambda: self.window.navigate("scanner"))
        current_actions.addWidget(open_btn)
        current_actions.addWidget(scan_btn)
        current_actions.addStretch(1)
        self.current_card.body.addLayout(current_actions)
        left.addWidget(self.current_card)

        findings_card = Card()
        findings_card.add_title("Recent security findings", "Highest severity first")
        view_all = QPushButton("Inspect →")
        view_all.setProperty("variant", "link")
        view_all.clicked.connect(lambda: self.window.navigate("inspector"))
        findings_card.add_header_widget(view_all)
        self.findings_table = make_table(
            ["Severity", "Finding", "Network", "Status"], stretch_column=1
        )
        set_column_widths(self.findings_table, {0: 85, 2: 145, 3: 90})
        self.findings_table.setMinimumHeight(210)
        self.findings_table.doubleClicked.connect(lambda _index: self.window.navigate("inspector"))
        findings_card.add(self.findings_table)
        left.addWidget(findings_card, 1)

        posture_card = Card()
        posture_card.add_title("Severity posture", "All recorded findings")
        self.severity_breakdown = SeverityBreakdown()
        posture_card.add(self.severity_breakdown)
        self.posture_note = QLabel("No findings recorded yet.")
        self.posture_note.setProperty("role", "small")
        self.posture_note.setWordWrap(True)
        posture_card.add(self.posture_note)
        right.addWidget(posture_card)

        adapter_card = Card()
        adapter_card.add_title("Hardware readiness", "Never inferred from Wi-Fi connectivity")
        self.adapter_name = QLabel("Diagnostics not run")
        self.adapter_name.setProperty("role", "h3")
        self.adapter_name.setWordWrap(True)
        adapter_card.add(self.adapter_name)
        self.adapter_detail = QLabel(
            "Run adapter diagnostics to inspect driver state, bands and documented "
            "monitor/injection limitations."
        )
        self.adapter_detail.setProperty("role", "small")
        self.adapter_detail.setWordWrap(True)
        adapter_card.add(self.adapter_detail)
        adapter_actions = QHBoxLayout()
        self.diag_button = QPushButton("Run diagnostics")
        self.diag_button.clicked.connect(self.run_diagnostics)
        more = QPushButton("Details")
        more.setProperty("variant", "ghost")
        more.clicked.connect(lambda: self.window.navigate("hardware"))
        adapter_actions.addWidget(self.diag_button)
        adapter_actions.addWidget(more)
        adapter_actions.addStretch(1)
        adapter_card.body.addLayout(adapter_actions)
        right.addWidget(adapter_card)

        research_card = Card()
        research_card.add_title("Kali research environment", "Offline tooling and diagnostics")
        self.research_value = QLabel("Not checked")
        self.research_value.setProperty("role", "h3")
        research_card.add(self.research_value)
        self.research_detail = QLabel(
            "Configure the transport in Settings. WSL2 is not assumed to provide "
            "monitor-mode access to the internal adapter."
        )
        self.research_detail.setProperty("role", "small")
        self.research_detail.setWordWrap(True)
        research_card.add(self.research_detail)
        research_actions = QHBoxLayout()
        self.research_button = QPushButton("Test connection")
        self.research_button.clicked.connect(self.check_research)
        settings_btn = QPushButton("Settings")
        settings_btn.setProperty("variant", "ghost")
        settings_btn.clicked.connect(lambda: self.window.navigate("settings"))
        research_actions.addWidget(self.research_button)
        research_actions.addWidget(settings_btn)
        research_actions.addStretch(1)
        research_card.body.addLayout(research_actions)
        right.addWidget(research_card)

        quick_card = Card()
        quick_card.add_title("Quick actions")
        quick_grid = QGridLayout()
        quick_grid.setSpacing(8)
        quick_actions = [
            ("Import capture", "captures"),
            ("Run inspection", "inspector"),
            ("Wordlist library", "wordlists"),
            ("Generate report", "reports"),
        ]
        for index, (label, key) in enumerate(quick_actions):
            button = QPushButton(label)
            button.clicked.connect(lambda _checked=False, k=key: self.window.navigate(k))
            quick_grid.addWidget(button, index // 2, index % 2)
        quick_card.body.addLayout(quick_grid)
        right.addWidget(quick_card)
        right.addStretch(1)

        self.dashboard_body = QWidget()
        body_layout = QVBoxLayout(self.dashboard_body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.addLayout(grid, 1)

        layout.addWidget(self.dashboard_body)
        scroll.setWidget(content)
        self.content.addWidget(scroll, 1)

    def refresh(self) -> None:
        data = self.service.dashboard()
        stats = data["stats"]
        current = data["current"]
        self.no_assessment.setVisible(current is None)
        self.banner.setVisible(current is None)
        self.dashboard_body.setVisible(current is not None)
        self.stat_assessments.set_value(
            str(stats["assessments"]),
            f"{stats['active_assessments']} active",
        )
        self.stat_networks.set_value(format_number(stats["networks"]), "Across all assessments")
        self.stat_findings.set_value(
            format_number(stats["total_findings"]),
            f"{stats['findings']['critical']} critical · {stats['findings']['high']} high",
        )
        self.stat_captures.set_value(format_number(stats["captures"]), "Registered evidence")
        self.stat_audits.set_value(format_number(stats["audits"]), "Completed offline audits")
        self.severity_breakdown.set_counts(stats["findings"])
        self.posture_note.setText(
            "No findings recorded yet."
            if stats["total_findings"] == 0
            else f"{stats['total_findings']} finding(s) recorded across the workspace. "
            "Review critical and high items first."
        )
        self._fill_current(current)
        self._fill_findings(data["findings"])
        if current and not self._diagnostics_started and not self.window.smoke_test:
            self._diagnostics_started = True
            self.run_diagnostics(silent=True)
        if not self._research_started and not self.window.smoke_test:
            self._research_started = True
            self.check_research(silent=True)

    def _fill_current(self, current) -> None:
        if not current:
            return
        self.current_name.setText(current.name)
        self.current_org.setText(current.organisation or "Organisation not recorded")
        self.current_rows["status"].set_value(current.status.value.title())
        self.current_rows["scope"].set_value(current.scope or "No scope statement recorded")
        self.current_rows["targets"].set_value(
            f"{current.target_count} explicitly permitted target(s)"
        )
        self.current_rows["tester"].set_value(current.tester or "Not recorded")
        self.current_rows["dates"].set_value(
            f"{current.start_date or '—'} to {current.end_date or 'in progress'}"
        )

    def _fill_findings(self, findings) -> None:
        self.findings_table.setRowCount(0)
        for row, finding in enumerate(findings):
            self.findings_table.insertRow(row)
            set_chip_cell(
                self.findings_table,
                row,
                0,
                finding.severity.value.upper(),
                severity_colour(finding.severity.value),
            )
            set_cell(self.findings_table, row, 1, finding.title, tooltip=finding.rule_id)
            set_cell(
                self.findings_table,
                row,
                2,
                finding.ssid or "<hidden>",
                tooltip=f"{finding.ssid}\n{finding.bssid}",
            )
            set_cell(
                self.findings_table,
                row,
                3,
                finding.status.value.title(),
                colour="#f5c451" if finding.status.value == "potential" else None,
            )
        if not findings:
            self.findings_table.setRowCount(1)
            set_cell(self.findings_table, 0, 0, "No findings yet", colour="#a8a8a8")
            self.findings_table.setSpan(0, 0, 1, 4)

    def run_diagnostics(self, silent: bool = False) -> None:
        if not silent:
            self.diag_button.setEnabled(False)
            self.diag_button.setText("Checking…")
            self.notify("Inspecting wireless hardware…")

        def done(report) -> None:
            self.diag_button.setEnabled(True)
            self.diag_button.setText("Run diagnostics")
            primary = report.adapters[0] if report.adapters else None
            if primary:
                self.adapter_name.setText(primary.description or primary.name)
                caps = {cap.name: cap for cap in report.capabilities}
                monitor = caps.get("Monitor mode")
                self.adapter_detail.setText(
                    f"{report.readiness}\n"
                    f"Monitor: {monitor.status if monitor else 'untested'} · "
                    f"Host RAM: {report.host.ram_gb or '—'} GB"
                )
            else:
                self.adapter_name.setText("No wireless adapter detected")
                self.adapter_detail.setText(
                    report.warnings[0] if report.warnings else "Hardware could not be assessed."
                )
            if not silent:
                self.notify("Hardware diagnostics complete.", "success")

        def failed(message: str) -> None:
            self.diag_button.setEnabled(True)
            self.diag_button.setText("Run diagnostics")
            self.adapter_name.setText("Diagnostics failed")
            self.adapter_detail.setText(message)
            if not silent:
                self.notify(f"Hardware diagnostics failed: {message}", "error")

        self.tasks.start(self.service.diagnose_hardware, on_done=done, on_error=failed)

    def check_research(self, silent: bool = False) -> None:
        if not silent:
            self.research_button.setEnabled(False)
            self.research_button.setText("Checking…")
        self.research_value.setText("Checking…")

        def done(status) -> None:
            self.research_button.setEnabled(True)
            self.research_button.setText("Test connection")
            self.research_value.setText(status.label)
            detail = status.detail
            if status.username or status.environment:
                detail = (
                    f"{status.environment or 'Kali'} · {status.username or 'user'} · "
                    f"{detail}"
                )
            self.research_detail.setText(detail)
            self.window.set_environment_status(
                bool(status.available and status.aircrack),
                f"{status.mode.upper()} · {'ready' if status.available else 'unavailable'}",
            )
            if not silent:
                self.notify(status.label, "success" if status.available else "warn")

        def failed(message: str) -> None:
            self.research_button.setEnabled(True)
            self.research_button.setText("Test connection")
            self.research_value.setText("Unavailable")
            self.research_detail.setText(message)
            self.window.set_environment_status(False, "Unavailable")
            if not silent:
                self.notify(f"Research environment: {message}", "warn")

        self.tasks.start(self.service.research_status, on_done=done, on_error=failed)

