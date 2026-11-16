"""Reusable desktop widgets and background-task plumbing."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QObject, QRectF, QRunnable, QSize, Qt, QThreadPool, QUrl, Signal
from PySide6.QtGui import (
    QColor,
    QDesktopServices,
    QFont,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.branding import SEVERITY_COLORS
from ..core.assets import banner_wide_path
from ..core.domain import FindingStatus, Severity

logger = logging.getLogger("surge_signal.ui")


def format_number(value: int | float | None) -> str:
    if value is None:
        return "—"
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def format_bytes(size: int | None) -> str:
    if not size:
        return "0 B"
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def severity_colour(severity: str) -> str:
    return SEVERITY_COLORS.get(str(severity).lower(), "#a8a8a8")


class LogoWidget(QWidget):
    def paintEvent(self, event) -> None:              
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        size = min(self.width(), self.height())
        pixmap = QPixmap(str(banner_wide_path().parent / "surge-signal-256.png"))
        if not pixmap.isNull():
            painter.drawPixmap(0, 0, size, size, pixmap)
            painter.end()
            return
        painter.setBrush(QColor("#f26a21"))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(0, 0, size, size, size * 0.25, size * 0.25)
        painter.setBrush(QColor("#fff4ec"))
        painter.drawEllipse(int(size * 0.40), int(size * 0.57), int(size * 0.19), int(size * 0.19))
        pen = QPen(QColor("#fff4ec"), max(2.0, size * 0.07))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawArc(
            int(size * 0.27), int(size * 0.22), int(size * 0.40), int(size * 0.40),
            45 * 16, 90 * 16,
        )
        painter.drawArc(
            int(size * 0.16), int(size * 0.10), int(size * 0.60), int(size * 0.60),
            45 * 16, 90 * 16,
        )
        painter.end()


class BrandBanner(QWidget):
    """Rounded, cropped presentation of the supplied SURGE Signal banner."""

    def __init__(self, parent: QWidget | None = None, *, height: int = 170):
        super().__init__(parent)
        self._pixmap = QPixmap(str(banner_wide_path()))
        self.setMinimumHeight(height)
        self.setMaximumHeight(height)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def paintEvent(self, event) -> None:              
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        rect = QRectF(self.rect()).adjusted(0, 0, -1, -1)
        path = QPainterPath()
        path.addRoundedRect(rect, 0, 0)
        painter.setClipPath(path)
        painter.fillRect(rect, QColor("#080b11"))
        if not self._pixmap.isNull():
            scaled = self._pixmap.scaled(
                self.size(),
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation,
            )
            x = (self.width() - scaled.width()) // 2
            y = (self.height() - scaled.height()) // 2
            painter.drawPixmap(x, y, scaled)
        painter.setClipping(False)
        painter.setPen(QPen(QColor("#1d2c43"), 1))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(rect, 0, 0)
        painter.end()


class Card(QFrame):
    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        accent: bool = False,
        padding: int = 18,
        spacing: int = 12,
    ):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setProperty("accent", accent)
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(padding, padding, padding, padding)
        self.body.setSpacing(spacing)
        self.header = QHBoxLayout()
        self.header.setSpacing(8)
        self.header.setContentsMargins(0, 0, 0, 0)
        self.body.addLayout(self.header)

    def add_title(self, text: str, subtitle: str | None = None) -> QLabel:
        wrapper = QVBoxLayout()
        wrapper.setSpacing(2)
        title = QLabel(text)
        title.setProperty("role", "h2")
        wrapper.addWidget(title)
        if subtitle:
            caption = QLabel(subtitle)
            caption.setProperty("role", "small")
            caption.setWordWrap(True)
            wrapper.addWidget(caption)
        self.header.addLayout(wrapper)
        self.header.addStretch(1)
        return title

    def add_header_widget(self, widget: QWidget) -> None:
        self.header.addWidget(widget)

    def add(self, widget: QWidget, stretch: int = 0) -> None:
        self.body.addWidget(widget, stretch)


class StatCard(QFrame):
    def __init__(
        self,
        label: str,
        value: str = "0",
        hint: str = "",
        *,
        accent: bool = False,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setMinimumHeight(112)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(3)
        top = QHBoxLayout()
        self.label = QLabel(label.upper())
        self.label.setProperty("role", "tiny")
        top.addWidget(self.label)
        top.addStretch(1)
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {'#f26a21' if accent else '#334867'}; font-size: 9px;")
        top.addWidget(dot)
        layout.addLayout(top)
        self.value_label = QLabel(value)
        self.value_label.setProperty("role", "metric-accent" if accent else "metric")
        layout.addWidget(self.value_label)
        self.hint = QLabel(hint)
        self.hint.setProperty("role", "small")
        self.hint.setWordWrap(True)
        layout.addWidget(self.hint)

    def set_value(self, value: str, hint: str | None = None) -> None:
        self.value_label.setText(value)
        if hint is not None:
            self.hint.setText(hint)


class Chip(QLabel):
    def __init__(self, text: str, colour: str = "#a8a8a8", parent: QWidget | None = None):
        super().__init__(text, parent)
        self.set_colour(colour)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)

    def set_colour(self, colour: str) -> None:
        self.setStyleSheet(
            f"background-color: {colour}1f; color: {colour}; border: 1px solid {colour}55; "
            "border-radius: 0px; padding: 2px 7px; font-size: 10px; font-weight: 600;"
        )


def severity_chip(severity: str) -> Chip:
    return Chip(str(severity).upper(), severity_colour(severity))


def status_chip(status: str) -> Chip:
    colours = {
        "verified": "#4ade80",
        "potential": "#f5c451",
        "observation": "#a8a8a8",
        "active": "#4ade80",
        "draft": "#6cb6ff",
        "complete": "#a8a8a8",
        "archived": "#a8a8a8",
        "valid": "#4ade80",
        "truncated": "#f5c451",
        "invalid": "#ff6b7a",
        "completed": "#4ade80",
        "failed": "#ff6b7a",
        "cancelled": "#a8a8a8",
    }
    labels = {
        "verified": "VERIFIED",
        "potential": "POTENTIAL",
        "observation": "OBSERVATION",
    }
    value = str(status).lower()
    return Chip(labels.get(value, value.upper()), colours.get(value, "#a8a8a8"))


class Meter(QWidget):
    """Compact 0–4 strength meter."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.score = 0
        self.setMinimumHeight(58)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_score(self, score: int) -> None:
        self.score = max(0, min(4, int(score)))
        self.update()

    def paintEvent(self, event) -> None:              
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        colours = ["#ff6b7a", "#ff8a5b", "#f5c451", "#6cb6ff", "#4ade80"]
        gap = 5
        width = (self.width() - gap * 3) / 4
        for index in range(4):
            rect = (index * (width + gap), 10, width, 9)
            colour = QColor(colours[self.score] if index < max(1, self.score) else "#3a3a3d")
            painter.setBrush(colour)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRoundedRect(*[int(value) for value in rect], 0, 0)
        painter.end()


class SeverityBreakdown(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(7)
        self.rows: dict[str, tuple[QLabel, QProgressBar]] = {}
        for severity in ("critical", "high", "medium", "low", "info"):
            row = QHBoxLayout()
            row.setSpacing(8)
            label = QLabel(severity.upper())
            label.setFixedWidth(58)
            label.setStyleSheet(
                f"color:{severity_colour(severity)}; font-size:9px; font-weight:700;"
            )
            bar = QProgressBar()
            bar.setRange(0, 1)
            bar.setValue(0)
            bar.setTextVisible(False)
            bar.setFixedHeight(7)
            bar.setStyleSheet(
                "QProgressBar{background:#e6e6e6;border:none;border-radius:0px;}"
                f"QProgressBar::chunk{{background:{severity_colour(severity)};border-radius:0px;}}"
            )
            count = QLabel("0")
            count.setFixedWidth(24)
            count.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            count.setProperty("role", "small")
            row.addWidget(label)
            row.addWidget(bar, 1)
            row.addWidget(count)
            self.layout.addLayout(row)
            self.rows[severity] = (count, bar)

    def set_counts(self, counts: dict[str, int]) -> None:
        total = max(1, sum(counts.values()))
        for severity, (count, bar) in self.rows.items():
            value = int(counts.get(severity, 0))
            count.setText(str(value))
            bar.setRange(0, total)
            bar.setValue(value)


class InfoBanner(QFrame):
    def __init__(
        self,
        text: str,
        *,
        level: str = "info",
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        colours = {
            "info": ("#6cb6ff", "#152a3a", "#2f5f8a"),
            "warn": ("#f5c451", "#332d18", "#75642c"),
            "error": ("#ff6b7a", "#3a1b1e", "#7a333a"),
            "success": ("#4ade80", "#173328", "#2f6b4f"),
        }
        colour, background, border = colours.get(level, colours["info"])
        self.setStyleSheet(
            f"QFrame#Banner{{background-color:{background};"
            f"border:1px solid {border};border-radius:0px;}}"
        )
        self.setObjectName("Banner")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(11, 9, 11, 9)
        layout.setSpacing(9)
        marker = QLabel("●" if level == "info" else "!")
        marker.setStyleSheet(f"color:{colour};font-weight:800;")
        marker.setFixedWidth(14)
        layout.addWidget(marker, 0, Qt.AlignmentFlag.AlignTop)
        self.label = QLabel(text)
        self.label.setWordWrap(True)
        self.label.setStyleSheet("color:#d8d8d8;")
        layout.addWidget(self.label, 1)

    def setText(self, text: str) -> None:              
        self.label.setText(text)


class EmptyState(QFrame):
    def __init__(
        self,
        title: str,
        body: str,
        action_text: str | None = None,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 30, 28, 30)
        layout.setSpacing(8)
        icon = QLabel("◈")
        icon.setStyleSheet("color:#f26a21;font-size:25px;")
        layout.addWidget(icon)
        heading = QLabel(title)
        heading.setProperty("role", "h2")
        layout.addWidget(heading)
        text = QLabel(body)
        text.setProperty("role", "muted")
        text.setWordWrap(True)
        text.setMaximumWidth(620)
        layout.addWidget(text)
        self.button: QPushButton | None = None
        if action_text:
            self.button = QPushButton(action_text)
            self.button.setProperty("variant", "primary")
            self.button.setFixedWidth(180)
            layout.addSpacing(8)
            layout.addWidget(self.button)
        layout.addStretch(1)


class KeyValueRow(QWidget):
    def __init__(self, label: str, value: str = "—", parent: QWidget | None = None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(12)
        self.key = QLabel(label)
        self.key.setProperty("role", "small")
        self.key.setFixedWidth(138)
        self.value = QLabel(value)
        self.value.setWordWrap(True)
        self.value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.key, 0, Qt.AlignmentFlag.AlignTop)
        layout.addWidget(self.value, 1)

    def set_value(self, value: str) -> None:
        self.value.setText(value)


class LabeledField(QWidget):
    def __init__(
        self,
        label: str,
        widget: QWidget,
        hint: str | None = None,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        text = QLabel(label)
        text.setProperty("role", "small")
        layout.addWidget(text)
        layout.addWidget(widget)
        if hint:
            note = QLabel(hint)
            note.setProperty("role", "tiny")
            note.setWordWrap(True)
            layout.addWidget(note)


def make_table(headers: list[str], *, stretch_column: int = -1) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.setAlternatingRowColors(True)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(32)
    table.horizontalHeader().setHighlightSections(False)
    table.setShowGrid(True)
    table.setWordWrap(False)
    if stretch_column >= 0:
        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setSectionResizeMode(
            stretch_column, QHeaderView.ResizeMode.Stretch
        )
    table.horizontalHeader().setMinimumSectionSize(70)
    return table


def set_column_widths(table: QTableWidget, widths: dict[int, int]) -> None:
    for column, width in widths.items():
        table.setColumnWidth(column, width)


def set_cell(
    table: QTableWidget,
    row: int,
    column: int,
    value: Any,
    *,
    tooltip: str | None = None,
    colour: str | None = None,
    mono: bool = False,
    align: Qt.AlignmentFlag | None = None,
) -> QTableWidgetItem:
    item = QTableWidgetItem("" if value is None else str(value))
    if tooltip:
        item.setToolTip(tooltip)
    if colour:
        item.setForeground(QColor(colour))
    if mono:
        font = QFont("Cascadia Mono")
        font.setPointSize(9)
        item.setFont(font)
    if align:
        item.setTextAlignment(int(align | Qt.AlignmentFlag.AlignVCenter))
    table.setItem(row, column, item)
    return item


def set_chip_cell(table: QTableWidget, row: int, column: int, text: str, colour: str) -> None:
    holder = QWidget()
    layout = QHBoxLayout(holder)
    layout.setContentsMargins(6, 3, 6, 3)
    layout.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    chip = Chip(text, colour)
    layout.addWidget(chip)
    table.setCellWidget(row, column, holder)


def open_path(path: str | Path) -> None:
    QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))


class TaskSignals(QObject):
    finished = Signal(object)
    failed = Signal(str)
    progress = Signal(object)


class BackgroundTask(QRunnable):
    def __init__(self, fn: Callable[..., Any], *, with_progress: bool = False):
        super().__init__()
        self.fn = fn
        self.with_progress = with_progress
        self.signals = TaskSignals()
        self.setAutoDelete(True)

    def run(self) -> None:
        def emit_progress(value: object) -> None:
            try:
                self.signals.progress.emit(value)
            except RuntimeError:
                pass

        try:
            result = self.fn(emit_progress) if self.with_progress else self.fn()
        except Exception as exc:                
            logger.exception("Background task failed")
            try:
                self.signals.failed.emit(str(exc))
            except RuntimeError:
                pass
        else:
            try:
                self.signals.finished.emit(result)
            except RuntimeError:
                pass


class TaskRunner(QObject):
    """Keep QRunnables alive while they execute and marshal results to the UI."""

    def __init__(self, parent: QObject | None = None, max_threads: int = 3):
        super().__init__(parent)
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(max_threads)
        self._tasks: set[BackgroundTask] = set()

    def start(
        self,
        fn: Callable[..., Any],
        *,
        on_done: Callable[[Any], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        on_progress: Callable[[Any], None] | None = None,
        with_progress: bool = False,
    ) -> BackgroundTask:
        task = BackgroundTask(fn, with_progress=with_progress)
        self._tasks.add(task)

        def cleanup() -> None:
            self._tasks.discard(task)

        if on_done:
            task.signals.finished.connect(on_done)
        if on_error:
            task.signals.failed.connect(on_error)
        if on_progress:
            task.signals.progress.connect(on_progress)
        task.signals.finished.connect(lambda _result: cleanup())
        task.signals.failed.connect(lambda _message: cleanup())
        self.pool.start(task)
        return task

    def shutdown(self) -> None:
        self.pool.waitForDone(1500)


class SudoPasswordDialog(QDialog):
    """Protected Linux authentication prompt.

    The password is returned to the caller in memory only. It is never written to
    settings, the database, logs or command-line arguments.
    """

    def __init__(self, operation: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Linux authentication required")
        self.setModal(True)
        self.setMinimumWidth(470)
        self.password_value = ""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(10)
        title = QLabel("Authenticate with sudo")
        title.setProperty("role", "h2")
        layout.addWidget(title)
        body = QLabel(
            f"<b>{operation}</b> requires elevated privileges in the Kali environment.\n\n"
            "Enter your Linux account password. It is sent directly to sudo through "
            "standard input and is not stored by SURGE Signal."
        )
        body.setWordWrap(True)
        body.setProperty("role", "muted")
        layout.addWidget(body)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Linux account password")
        self.password.setClearButtonEnabled(False)
        layout.addWidget(self.password)
        self.error = QLabel("")
        self.error.setProperty("role", "error")
        self.error.setVisible(False)
        layout.addWidget(self.error)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Authenticate")
        buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("variant", "primary")
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self._accept)
        layout.addWidget(buttons)
        self.password.setFocus()
        self.password.returnPressed.connect(self._accept)

    def _accept(self) -> None:
        value = self.password.text()
        if not value:
            self.error.setText("Enter the Linux account password, or cancel the operation.")
            self.error.setVisible(True)
            return
        self.password_value = value
        self.password.clear()
        self.accept()

    def reject(self) -> None:
        self.password.clear()
        self.password_value = ""
        super().reject()


class ConfirmAuditDialog(QDialog):
    """Explicit authorised-lab attestation before an offline password audit."""

    def __init__(
        self,
        assessment_name: str,
        assessment_id: str,
        bssid: str,
        ssid: str,
        candidates: int,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Confirm authorised offline audit")
        self.setModal(True)
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(11)
        title = QLabel("Authorised laboratory audit")
        title.setProperty("role", "h2")
        layout.addWidget(title)
        scope = QFrame()
        scope.setObjectName("Subtle")
        scope_layout = QVBoxLayout(scope)
        scope_layout.setContentsMargins(12, 10, 12, 10)
        for label, value in (
            ("Assessment", f"{assessment_name} ({assessment_id})"),
            ("Target BSSID", bssid),
            ("SSID", ssid or "<hidden / unknown>"),
            ("Candidate budget", f"{candidates:,}"),
        ):
            row = QHBoxLayout()
            key = QLabel(label)
            key.setProperty("role", "small")
            key.setFixedWidth(120)
            val = QLabel(value)
            val.setWordWrap(True)
            row.addWidget(key)
            row.addWidget(val, 1)
            scope_layout.addLayout(row)
        layout.addWidget(scope)
        warning = QLabel(
            "This operation runs entirely offline against a capture already stored in "
            "the assessment. It does not transmit frames or contact any network. Only "
            "proceed if the capture was obtained from a network you are explicitly "
            "authorised to test."
        )
        warning.setWordWrap(True)
        warning.setProperty("role", "warning")
        layout.addWidget(warning)
        self.attestation = QCheckBox(
            "I confirm the capture is from an authorised laboratory network and the "
            "BSSID is within the assessment scope."
        )
        self.scope_confirmation = QCheckBox(
            "I understand this is an offline password-strength assessment, not an "
            "attempt to access a third-party network."
        )
        layout.addWidget(self.attestation)
        layout.addWidget(self.scope_confirmation)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Ok
        )
        self.ok_button = buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.ok_button.setText("Run offline audit")
        self.ok_button.setProperty("variant", "primary")
        self.ok_button.setEnabled(False)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
        self.attestation.toggled.connect(self._update)
        self.scope_confirmation.toggled.connect(self._update)

    def _update(self) -> None:
        self.ok_button.setEnabled(
            self.attestation.isChecked() and self.scope_confirmation.isChecked()
        )

