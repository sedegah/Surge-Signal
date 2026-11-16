"""Base page and shared page helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...core.domain import Assessment
from ..widgets import TaskRunner

if TYPE_CHECKING:
    from ...core.services import SurgeService
    from ..main_window import MainWindow


class BasePage(QWidget):
    title = "Page"
    subtitle = ""

    def __init__(self, service: "SurgeService", window: "MainWindow"):
        super().__init__(window)
        self.service = service
        self.window = window
        self.tasks = TaskRunner(self, max_threads=2)
        self._loaded_once = False

        self.outer = QVBoxLayout(self)
        self.outer.setContentsMargins(0, 0, 0, 0)
        self.outer.setSpacing(16)

        header = QHBoxLayout()
        header.setSpacing(16)
        titles = QVBoxLayout()
        titles.setSpacing(3)
        self.title_label = QLabel(self.title)
        self.title_label.setProperty("role", "h1")
        titles.addWidget(self.title_label)
        self.subtitle_label = QLabel(self.subtitle)
        self.subtitle_label.setProperty("role", "muted")
        self.subtitle_label.setWordWrap(True)
        titles.addWidget(self.subtitle_label)
        header.addLayout(titles, 1)
        self.actions = QHBoxLayout()
        self.actions.setSpacing(8)
        header.addLayout(self.actions)
        self.outer.addLayout(header)

        self.content = QVBoxLayout()
        self.content.setSpacing(14)
        self.outer.addLayout(self.content, 1)

    def add_action(
        self,
        text: str,
        callback,
        *,
        primary: bool = False,
        danger: bool = False,
        tooltip: str = "",
    ) -> QPushButton:
        button = QPushButton(text)
        if primary:
            button.setProperty("variant", "primary")
        if danger:
            button.setProperty("variant", "danger")
        if tooltip:
            button.setToolTip(tooltip)
        button.clicked.connect(callback)
        self.actions.addWidget(button)
        return button

    def current_assessment(self) -> Assessment | None:
        return self.window.current_assessment()

    def require_assessment(self) -> Assessment | None:
        assessment = self.current_assessment()
        if assessment is None:
            result = QMessageBox.information(
                self,
                "Assessment required",
                "Create or select an assessment before using this module.\n\n"
                "Every scan, capture, finding and report is associated with an "
                "authorised assessment workspace.",
                QMessageBox.StandardButton.Ok,
            )
            self.window.open_assessments(create=True)
            return None
        return assessment

    def make_scroll(self, widget: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(widget)
        return scroll

    def on_show(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        pass

    def notify(self, message: str, level: str = "info") -> None:
        self.window.notify(message, level)

