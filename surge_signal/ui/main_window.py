"""Main application shell and navigation."""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QDateTime, QSize, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QKeySequence, QPixmap, QShortcut
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ..core.branding import APP_NAME, APP_VERSION, BUILD_NAME, TAGLINE
from ..core.assets import icon_png
from ..core.config import AppPaths
from ..core.domain import Assessment, AssessmentStatus
from ..core.services import SurgeService
from .pages.assessments import AssessmentsPage
from .pages.auditor import AuditorPage
from .pages.captures import CapturesPage
from .pages.dashboard import DashboardPage
from .pages.hardware import HardwarePage
from .pages.inspector import InspectorPage
from .pages.reports import ReportsPage
from .pages.scanner import ScannerPage
from .pages.settings import SettingsPage
from .pages.wordlists import WordlistsPage
from .theme import COLOURS
from .widgets import Chip, LogoWidget, TaskRunner, open_path


NAV_ITEMS = [
    ("dashboard", "", "Dashboard"),
    ("scanner", "", "Wireless Scanner"),
    ("inspector", "", "Network Inspector"),
    ("hardware", "", "Hardware Diagnostics"),
    ("captures", "", "Capture Manager"),
    ("auditor", "", "Password Auditor"),
    ("wordlists", "", "Wordlists"),
    ("assessments", "", "Assessments"),
    ("reports", "", "Reports"),
    ("settings", "", "Settings"),
]


class MainWindow(QMainWindow):
    assessmentChanged = Signal(str)

    def __init__(self, service: SurgeService, paths: AppPaths, *, smoke_test: bool = False):
        super().__init__()
        self.service = service
        self.paths = paths
        self.smoke_test = smoke_test
        self._assessments: dict[str, Assessment] = {}
        self._current: Assessment | None = None
        self._toast_timer = QTimer(self)
        self._toast_timer.setSingleShot(True)
        self._toast_timer.timeout.connect(self._hide_toast)
        self.auto_tasks = TaskRunner(self, max_threads=1)
        self._auto_scan_running = False

        self.setWindowTitle(f"{APP_NAME} — {TAGLINE}")
        self.resize(1480, 940)
        self.setMinimumSize(1180, 720)

        shell = QWidget()
        shell.setObjectName("AppShell")
        shell_layout = QHBoxLayout(shell)
        shell_layout.setContentsMargins(0, 0, 0, 0)
        shell_layout.setSpacing(0)
        self.setCentralWidget(shell)
        self._build_menu()

        shell_layout.addWidget(self._build_sidebar())
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        right_layout.addWidget(self._build_topbar())
        self.stack = QStackedWidget()
        self.stack.setContentsMargins(0, 0, 0, 0)
        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(16, 12, 16, 10)
        container_layout.addWidget(self.stack)
        right_layout.addWidget(container, 1)
        right_layout.addWidget(self._build_clock_bar())
        shell_layout.addWidget(right, 1)

        self._build_toast()

        self.pages = {
            "dashboard": DashboardPage(service, self),
            "scanner": ScannerPage(service, self),
            "inspector": InspectorPage(service, self),
            "hardware": HardwarePage(service, self),
            "captures": CapturesPage(service, self),
            "auditor": AuditorPage(service, self),
            "wordlists": WordlistsPage(service, self),
            "assessments": AssessmentsPage(service, self),
            "reports": ReportsPage(service, self),
            "settings": SettingsPage(service, self),
        }
        for key, _icon, _label in NAV_ITEMS:
            self.stack.addWidget(self.pages[key])
        self.pages["assessments"].assessments_changed.connect(self.reload_assessments)

        self._shortcuts()
        self._ensure_default_workspace()
        self.reload_assessments()
        self.navigate("dashboard")
        QTimer.singleShot(1200, self.auto_discover)

    def _ensure_default_workspace(self) -> None:
        if self.smoke_test:
            return
        if self.service.db.list_assessments(include_archived=True):
            return
        try:
            assessment = self.service.create_assessment(
                name="Local Wireless Workspace",
                organisation="Local",
                scope=(
                    "Automatically created local workspace for passive Wi-Fi discovery. "
                    "Add the authorised scope and permitted BSSIDs before any active or "
                    "offline password assessment."
                ),
                permitted_targets=[],
                tester=self.service.settings.get("operator_name", ""),
                status=AssessmentStatus.DRAFT,
            )
            self.service.settings.set("last_assessment_id", assessment.id)
        except Exception:
                                                                               
                                            
            pass

    def _build_menu(self) -> None:
        menu = self.menuBar()

        file_menu = menu.addMenu("&File")
        new_assessment = QAction("&New assessment…", self)
        new_assessment.setShortcut(QKeySequence.New)
        new_assessment.triggered.connect(lambda: self.open_assessments(create=True))
        file_menu.addAction(new_assessment)
        import_capture = QAction("&Import capture…", self)
        import_capture.triggered.connect(self._menu_import_capture)
        file_menu.addAction(import_capture)
        generate_reports = QAction("&Generate reports…", self)
        generate_reports.triggered.connect(self._menu_generate_reports)
        file_menu.addAction(generate_reports)
        file_menu.addSeparator()
        exit_action = QAction("E&xit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        assessment_menu = menu.addMenu("&Assessment")
        discover = QAction("Run &wireless discovery", self)
        discover.setShortcut(QKeySequence("F5"))
        discover.triggered.connect(self._menu_discover)
        assessment_menu.addAction(discover)
        inspect = QAction("&Run network inspection", self)
        inspect.triggered.connect(self._menu_inspect)
        assessment_menu.addAction(inspect)
        assessment_menu.addSeparator()
        wordlists = QAction("&Wordlist library", self)
        wordlists.triggered.connect(lambda: self.navigate("wordlists"))
        assessment_menu.addAction(wordlists)
        assessments = QAction("Open &assessment workspace", self)
        assessments.triggered.connect(lambda: self.navigate("assessments"))
        assessment_menu.addAction(assessments)

        tools_menu = menu.addMenu("&Tools")
        kali_terminal = QAction("&Kali terminal / Aircrack…", self)
        kali_terminal.triggered.connect(self._menu_kali_terminal)
        tools_menu.addAction(kali_terminal)
        hardware = QAction("&Hardware diagnostics", self)
        hardware.triggered.connect(self._menu_hardware)
        tools_menu.addAction(hardware)
        kali = QAction("&Test Kali connection", self)
        kali.triggered.connect(self._menu_test_kali)
        tools_menu.addAction(kali)
        tools_menu.addSeparator()
        settings = QAction("&Settings", self)
        settings.triggered.connect(lambda: self.navigate("settings"))
        tools_menu.addAction(settings)

        help_menu = menu.addMenu("&Help")
        guide = QAction("&User guide", self)
        guide.triggered.connect(self._menu_help)
        help_menu.addAction(guide)
        about = QAction("&About SURGE Signal", self)
        about.triggered.connect(self._menu_about)
        help_menu.addAction(about)

    def _menu_import_capture(self) -> None:
        self.navigate("captures")
        self.pages["captures"].import_capture()

    def _menu_generate_reports(self) -> None:
        self.navigate("reports")
        self.pages["reports"].generate()

    def _menu_discover(self) -> None:
        self.navigate("scanner")
        self.pages["scanner"].scan()

    def _menu_inspect(self) -> None:
        self.navigate("inspector")
        self.pages["inspector"].run_inspection()

    def _menu_hardware(self) -> None:
        self.navigate("hardware")
        self.pages["hardware"].run_diagnostics()

    def _menu_kali_terminal(self) -> None:
        self.navigate("auditor")
        self.pages["auditor"].open_kali_terminal()

    def _menu_test_kali(self) -> None:
        self.navigate("settings")
        self.pages["settings"].test_connection()

    def _menu_help(self) -> None:
        candidates = [
            Path(sys.executable).resolve().parent / "docs" / "USER_GUIDE.md",
            Path(__file__).resolve().parents[2] / "docs" / "USER_GUIDE.md",
        ]
        for candidate in candidates:
            if candidate.is_file():
                open_path(candidate)
                return
        QMessageBox.information(
            self,
            APP_NAME,
            "The user guide is installed in the application's docs folder.",
        )

    def _menu_about(self) -> None:
        QMessageBox.about(
            self,
            f"About {APP_NAME}",
            f"<h3>{APP_NAME} {APP_VERSION}</h3>"
            f"<p>{TAGLINE}</p>"
            "<p>Authorised Wi-Fi discovery, inspection, capture analysis, controlled "
            "offline WPA/WPA2 assessment and reporting.</p>"
            "<p>For authorised security assessment only.</p>",
        )

                                                                                   
    def auto_discover(self) -> None:
        """Passively discover nearby networks when an assessment is active."""
        if self.smoke_test or self._auto_scan_running:
            return
        assessment = self._current
        if assessment is None or assessment.status is AssessmentStatus.ARCHIVED:
            return
        if not self.service.settings.get_bool("auto_scan_on_open", True):
            return
        self._auto_scan_running = True
        self.notify("Auto-discovery: searching for nearby Wi-Fi networks…")
        self.auto_tasks.start(
            lambda: self.service.scan_windows(assessment.id),
            on_done=self._auto_discover_done,
            on_error=self._auto_discover_failed,
        )

    def _auto_discover_done(self, result) -> None:
        self._auto_scan_running = False
        if result.networks:
            self.notify(
                f"Auto-discovery found {len(result.networks)} network(s).", "success"
            )
        elif result.warnings:
            self.notify(result.warnings[0], "warn")
        page = self.stack.currentWidget()
        if page in (self.pages["scanner"], self.pages["dashboard"]):
            page.refresh()

    def _auto_discover_failed(self, message: str) -> None:
        self._auto_scan_running = False
        self.notify(f"Automatic Wi-Fi discovery failed: {message}", "warn")

                                                                                 
    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(216)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 14, 0, 12)
        layout.setSpacing(2)

        brand_row = QHBoxLayout()
        brand_row.setContentsMargins(16, 0, 12, 16)
        brand_row.setSpacing(8)
        logo = QLabel()
        pixmap = QPixmap(str(icon_png(64)))
        if not pixmap.isNull():
            logo.setPixmap(
                pixmap.scaled(
                    38,
                    38,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )
        logo.setFixedSize(38, 38)
        brand_row.addWidget(logo)
        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        name = QLabel("SURGE")
        name.setProperty("role", "brand")
        sub = QLabel("SIGNAL")
        sub.setProperty("role", "brand-sub")
        brand_text.addWidget(name)
        brand_text.addWidget(sub)
        brand_row.addLayout(brand_text)
        brand_row.addStretch(1)
        layout.addLayout(brand_row)

        workspace = QLabel("WORKSPACE")
        workspace.setProperty("role", "tiny")
        workspace.setContentsMargins(17, 0, 0, 4)
        layout.addWidget(workspace)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.nav_buttons: dict[str, QPushButton] = {}
        for key, icon, label in NAV_ITEMS:
            button = QPushButton(label)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(lambda _checked=False, k=key: self.navigate(k))
            self.nav_group.addButton(button)
            self.nav_buttons[key] = button
            layout.addWidget(button)
        layout.addStretch(1)

        env = QFrame()
        env.setObjectName("Subtle")
        env.setContentsMargins(0, 0, 0, 0)
        env_layout = QVBoxLayout(env)
        env_layout.setContentsMargins(12, 10, 12, 10)
        env_layout.setSpacing(4)
        env_title = QLabel("RESEARCH ENVIRONMENT")
        env_title.setProperty("role", "tiny")
        env_layout.addWidget(env_title)
        env_row = QHBoxLayout()
        self.env_dot = QLabel("●")
        self.env_dot.setStyleSheet("color:#a8a8a8;font-size:9px;")
        self.env_label = QLabel("Not checked")
        self.env_label.setProperty("role", "small")
        env_row.addWidget(self.env_dot)
        env_row.addWidget(self.env_label, 1)
        env_layout.addLayout(env_row)
        env_hint = QLabel("Configure Kali in Settings")
        env_hint.setProperty("role", "tiny")
        env_layout.addWidget(env_hint)
        layout.addWidget(env)
        layout.addSpacing(10)
        version = QLabel(f"v{APP_VERSION}  ·  {BUILD_NAME}")
        version.setProperty("role", "tiny")
        version.setContentsMargins(22, 0, 0, 0)
        layout.addWidget(version)
        return sidebar

    def _build_topbar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("TopBar")
        bar.setFixedHeight(50)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(14, 6, 12, 6)
        layout.setSpacing(8)

        label = QLabel("Assessment:")
        label.setProperty("role", "small")
        label.setFixedWidth(64)
        layout.addWidget(label)
        self.assessment_combo = QComboBox()
        self.assessment_combo.setFixedWidth(390)
        self.assessment_combo.setFixedHeight(30)
        self.assessment_combo.currentIndexChanged.connect(self._assessment_selected)
        layout.addWidget(self.assessment_combo)
        self.assessment_status = Chip("NO ASSESSMENT", "#a8a8a8")
        self.assessment_status.setFixedHeight(24)
        layout.addWidget(self.assessment_status)
        layout.addStretch(1)

        self.new_assessment_button = QPushButton("New assessment")
        self.new_assessment_button.setFixedSize(128, 30)
        self.new_assessment_button.setProperty("variant", "primary")
        self.new_assessment_button.clicked.connect(lambda: self.open_assessments(create=True))
        layout.addWidget(self.new_assessment_button)
        return bar

    def _build_clock_bar(self) -> QFrame:
        bar = QFrame()
        bar.setObjectName("ClockBar")
        bar.setFixedHeight(26)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 0, 12, 0)
        layout.addStretch(1)
        self.clock_label = QLabel("")
        self.clock_label.setProperty("role", "small")
        self.clock_label.setStyleSheet("color:#c9c9c9;")
        layout.addWidget(self.clock_label)
        self.clock_timer = QTimer(self)
        self.clock_timer.setInterval(1000)
        self.clock_timer.timeout.connect(self._update_clock)
        self.clock_timer.start()
        self._update_clock()
        return bar

    def _update_clock(self) -> None:
        self.clock_label.setText(
            QDateTime.currentDateTime().toString("ddd d MMM yyyy   HH:mm:ss")
        )

    def _build_toast(self) -> None:
        self.toast = QFrame(self)
        self.toast.setObjectName("OverlayToast")
        self.toast.setVisible(False)
        self.toast.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        toast_layout = QHBoxLayout(self.toast)
        toast_layout.setContentsMargins(12, 7, 12, 7)
        self.toast_label = QLabel("")
        self.toast_label.setWordWrap(True)
        self.toast_label.setMaximumWidth(560)
        toast_layout.addWidget(self.toast_label)

    def _position_toast(self) -> None:
        if not hasattr(self, "toast"):
            return
        self.toast.adjustSize()
        self.toast.move(
            max(12, self.width() - self.toast.width() - 22),
            max(12, self.height() - self.toast.height() - 18),
        )

    def _hide_toast(self) -> None:
        if hasattr(self, "toast"):
            self.toast.setVisible(False)

    def resizeEvent(self, event) -> None:              
        super().resizeEvent(event)
        if hasattr(self, "toast") and self.toast.isVisible():
            self._position_toast()

    def _shortcuts(self) -> None:
        for index, (key, _icon, _label) in enumerate(NAV_ITEMS, start=1):
            shortcut_index = index if index < 10 else 0
            shortcut = QShortcut(QKeySequence(f"Ctrl+{shortcut_index}"), self)
            shortcut.activated.connect(lambda k=key: self.navigate(k))

                                                                                 
    def notify(self, message: str, level: str = "info") -> None:
        if not message:
            return
        colour = {
            "info": "#f0f0f0",
            "success": "#8ff0bf",
            "warn": "#f5c451",
            "error": "#ff9bad",
        }.get(level, "#f0f0f0")
        border = {
            "info": "#0a84ff",
            "success": "#2f7d55",
            "warn": "#bd9b2f",
            "error": "#a8444e",
        }.get(level, "#0a84ff")
        self.toast_label.setStyleSheet(f"color:{colour};")
        self.toast.setStyleSheet(
            f"QFrame#OverlayToast{{background-color:#333337;"
            f"border:1px solid {border};border-radius:0px;}}"
        )
        self.toast_label.setText(message)
        self._position_toast()
        self.toast.show()
        self.toast.raise_()
        self._toast_timer.start(7000 if level in {"warn", "error"} else 4500)

    def current_assessment(self) -> Assessment | None:
        return self._current

    def reload_assessments(self, select_id: str | None = None) -> None:
        previous = select_id or (self._current.id if self._current else self.service.settings.get("last_assessment_id", ""))
        assessments = self.service.db.list_assessments()
        self._assessments = {item.id: item for item in assessments}
        self.assessment_combo.blockSignals(True)
        self.assessment_combo.clear()
        if not assessments:
            self.assessment_combo.addItem("No assessment — create one to begin", "")
            self.assessment_combo.setEnabled(False)
            self._current = None
            self.assessment_status.setText("NO ASSESSMENT")
            self.assessment_status.set_colour("#a8a8a8")
        else:
            self.assessment_combo.setEnabled(True)
            for assessment in assessments:
                self.assessment_combo.addItem(
                    f"{assessment.name}   ·   {assessment.id}", assessment.id
                )
            index = next(
                (i for i, item in enumerate(assessments) if item.id == previous), 0
            )
            self.assessment_combo.setCurrentIndex(index)
            self._current = assessments[index]
            self.service.settings.set("last_assessment_id", self._current.id)
            self._update_status_chip(self._current)
        self.assessment_combo.blockSignals(False)
        if self._current:
            self.assessmentChanged.emit(self._current.id)
            QTimer.singleShot(900, self.auto_discover)
        self.refresh_current_page()

    def _assessment_selected(self, index: int) -> None:
        assessment_id = self.assessment_combo.itemData(index)
        if not assessment_id:
            return
        self._current = self._assessments.get(assessment_id)
        if self._current:
            self.service.settings.set("last_assessment_id", self._current.id)
            self._update_status_chip(self._current)
            self.assessmentChanged.emit(self._current.id)
            self.refresh_current_page()
            QTimer.singleShot(900, self.auto_discover)

    def _update_status_chip(self, assessment: Assessment | None) -> None:
        if not assessment:
            self.assessment_status.setText("NO ASSESSMENT")
            self.assessment_status.set_colour("#a8a8a8")
            return
        colours = {
            AssessmentStatus.DRAFT: "#6cb6ff",
            AssessmentStatus.ACTIVE: "#4ade80",
            AssessmentStatus.COMPLETE: "#a8a8a8",
            AssessmentStatus.ARCHIVED: "#a8a8a8",
        }
        self.assessment_status.setText(assessment.status.value.upper())
        self.assessment_status.set_colour(colours.get(assessment.status, "#a8a8a8"))

    def navigate(self, key: str) -> None:
        if key not in self.pages:
            return
        self.nav_buttons[key].setChecked(True)
        page = self.pages[key]
        self.stack.setCurrentWidget(page)
        page.on_show()

    def refresh_current_page(self) -> None:
        page = self.stack.currentWidget()
        if page and hasattr(page, "refresh"):
            page.refresh()

    def open_assessments(self, create: bool = False) -> None:
        self.navigate("assessments")
        if create:
            self.pages["assessments"].open_create_dialog()

    def set_environment_status(self, available: bool, text: str) -> None:
        self.env_dot.setStyleSheet(
            f"color:{'#4ade80' if available else '#ff6b7a'};font-size:9px;"
        )
        self.env_label.setText(text)

    def closeEvent(self, event) -> None:              
        self.clock_timer.stop()
        self.auto_tasks.shutdown()
        for page in self.pages.values():
            if hasattr(page, "tasks"):
                page.tasks.shutdown()
        super().closeEvent(event)

