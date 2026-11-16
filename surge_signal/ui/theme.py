"""High-contrast dark Windows desktop theme for SURGE Signal."""

from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPalette, QPen
from PySide6.QtWidgets import QApplication, QProxyStyle, QStyle

from .. import resources_rc                                          


COLOURS = {
    "bg": "#1b1b1b",
    "panel": "#2d2d30",
    "panel_alt": "#252526",
    "panel_high": "#3a3a3d",
    "border": "#55555a",
    "border_soft": "#444448",
    "text": "#f0f0f0",
    "muted": "#b5b5b5",
    "dim": "#969696",
    "accent": "#0a84ff",
    "accent_hover": "#3b9cff",
    "good": "#4ade80",
    "warn": "#f5c451",
    "bad": "#ff6b7a",
    "info": "#6cb6ff",
}

QSS = """
* {
    font-family: "Segoe UI", Tahoma, Arial, sans-serif;
    font-size: 12px;
    outline: none;
}
QMainWindow, QWidget, QDialog {
    background-color: #1b1b1b;
    color: #f0f0f0;
}
QWidget#AppShell { background-color: #1b1b1b; }
QFrame#Sidebar {
    background-color: #252526;
    border-right: 1px solid #55555a;
}
QFrame#TopBar {
    background-color: #2d2d30;
    border-bottom: 1px solid #55555a;
}
QFrame#ClockBar {
    background-color: #1b1b1b;
    border-top: 1px solid #444448;
}
QFrame#Card, QWidget#Card {
    background-color: #2d2d30;
    border: 1px solid #55555a;
    border-radius: 0px;
}
QFrame#Card[accent="true"], QWidget#Card[accent="true"] {
    background-color: #2d2d30;
    border: 1px solid #6b6b70;
}
QFrame#Subtle {
    background-color: #333337;
    border: 1px solid #55555a;
    border-radius: 0px;
}
QFrame#Divider { background-color: #4a4a4f; max-height: 1px; min-height: 1px; }
QFrame#Toast, QFrame#OverlayToast {
    background-color: #333337;
    border: 1px solid #0a84ff;
    border-radius: 0px;
}
QFrame#Banner { border-radius: 0px; }

QLabel { background: transparent; color: #f0f0f0; }
QLabel[role="brand"] {
    font-family: "Bahnschrift SemiBold", "Segoe UI Semibold", "Segoe UI", sans-serif;
    font-size: 19px;
    font-weight: 700;
    letter-spacing: 3px;
    color: #ffffff;
}
QLabel[role="brand-sub"] {
    font-size: 9px;
    letter-spacing: 2px;
    color: #f26a21;
    font-weight: 700;
}
QLabel[role="h1"] { font-size: 21px; font-weight: 600; color: #ffffff; }
QLabel[role="h2"] { font-size: 14px; font-weight: 600; color: #ffffff; }
QLabel[role="h3"] { font-size: 12px; font-weight: 600; color: #f0f0f0; }
QLabel[role="muted"] { color: #b5b5b5; }
QLabel[role="small"] { color: #b8b8b8; font-size: 11px; }
QLabel[role="tiny"] { color: #9a9a9a; font-size: 10px; }
QLabel[role="mono"] {
    font-family: "Consolas", "Cascadia Mono", monospace;
    color: #d8d8d8;
    font-size: 11px;
}
QLabel[role="metric"] {
    font-family: "Segoe UI Semibold", "Segoe UI", sans-serif;
    font-size: 24px;
    font-weight: 600;
    color: #ffffff;
}
QLabel[role="metric-accent"] {
    font-family: "Segoe UI Semibold", "Segoe UI", sans-serif;
    font-size: 24px;
    font-weight: 600;
    color: #6cb6ff;
}
QLabel[role="pill"] {
    background-color: #3a3a3d;
    border: 1px solid #55555a;
    border-radius: 0px;
    padding: 2px 7px;
    color: #e8e8e8;
    font-size: 10px;
    font-weight: 600;
}
QLabel[role="warning"] {
    color: #ffe7a3;
    background-color: #332d18;
    border: 1px solid #75642c;
    border-radius: 0px;
    padding: 8px 10px;
}
QLabel[role="error"] {
    color: #ffb3ba;
    background-color: #3a1b1e;
    border: 1px solid #7a333a;
    border-radius: 0px;
    padding: 8px 10px;
}
QLabel[role="success"] {
    color: #9af0bd;
    background-color: #173328;
    border: 1px solid #2f6b4f;
    border-radius: 0px;
    padding: 8px 10px;
}

QPushButton {
    background-color: #3a3a3d;
    color: #f0f0f0;
    border: 1px solid #66666b;
    border-radius: 0px;
    padding: 5px 11px;
    min-height: 22px;
    font-weight: 400;
}
QPushButton:hover { background-color: #46464b; border-color: #8a8a90; }
QPushButton:pressed { background-color: #303034; }
QPushButton:disabled {
    background-color: #2a2a2d;
    color: #7d7d82;
    border-color: #3f3f43;
}
QPushButton[variant="primary"] {
    background-color: #0a84ff;
    color: #ffffff;
    border: 1px solid #0a84ff;
    font-weight: 600;
}
QPushButton[variant="primary"]:hover { background-color: #3b9cff; border-color: #3b9cff; }
QPushButton[variant="primary"]:pressed { background-color: #0066cc; }
QPushButton[variant="primary"]:disabled {
    background-color: #27445f;
    color: #9ab5cc;
    border-color: #33546f;
}
QPushButton[variant="danger"] {
    background-color: #3a1b1e;
    color: #ffb3ba;
    border: 1px solid #7a333a;
}
QPushButton[variant="danger"]:hover { background-color: #4a2024; border-color: #a8444e; }
QPushButton[variant="ghost"] {
    background: transparent;
    border: 1px solid transparent;
    color: #d8d8d8;
    padding: 5px 8px;
}
QPushButton[variant="ghost"]:hover { background-color: #3a3a3f; border-color: #55555a; }
QPushButton[variant="link"] {
    background: transparent;
    border: none;
    color: #6cb6ff;
    padding: 0px;
    text-align: left;
    font-weight: 600;
}
QPushButton[variant="link"]:hover { color: #9acbff; text-decoration: underline; }
QPushButton#NavButton {
    background: transparent;
    border: none;
    border-left: 3px solid transparent;
    border-radius: 0px;
    text-align: left;
    padding: 8px 12px 8px 17px;
    color: #d4d4d4;
    font-size: 12px;
    font-weight: 400;
}
QPushButton#NavButton:hover { background-color: #333337; color: #ffffff; }
QPushButton#NavButton:checked {
    background-color: #094771;
    color: #ffffff;
    border-left: 3px solid #0a84ff;
    font-weight: 600;
}

QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDateEdit {
    background-color: #3c3c3c;
    border: 1px solid #66666b;
    border-radius: 0px;
    padding: 5px 7px;
    color: #f5f5f5;
    selection-background-color: #094771;
    selection-color: #ffffff;
    min-height: 20px;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus,
QSpinBox:focus, QDateEdit:focus {
    border: 1px solid #0a84ff;
    background-color: #414146;
}
QLineEdit:disabled, QTextEdit:disabled, QComboBox:disabled, QSpinBox:disabled {
    background-color: #2a2a2d;
    color: #85858a;
    border-color: #444448;
}
QLineEdit[invalid="true"] { border: 1px solid #ff6b7a; }
QComboBox::drop-down {
    border-left: 1px solid #66666b;
    width: 20px;
    background: #45454a;
}
QComboBox::down-arrow {
    image: url(:/assets/chevron-down.png);
    width: 12px;
    height: 8px;
}
QComboBox QAbstractItemView {
    background-color: #2d2d30;
    border: 1px solid #77777d;
    selection-background-color: #094771;
    selection-color: #ffffff;
    color: #f0f0f0;
    padding: 2px;
}
QSpinBox::up-button, QSpinBox::down-button {
    width: 0px; height: 0px; border: none; background: transparent;
}
QCheckBox { color: #f0f0f0; spacing: 7px; }
QCheckBox::indicator, QRadioButton::indicator {
    width: 13px; height: 13px; border-radius: 0px;
    border: 1px solid #9a9a9a; background: #3c3c3c;
}
QCheckBox::indicator:checked { background: #0a84ff; border: 1px solid #0a84ff; }

QTableWidget, QTableView, QTreeWidget, QListWidget {
    background-color: #252526;
    alternate-background-color: #2b2b2e;
    border: 1px solid #55555a;
    border-radius: 0px;
    gridline-color: #48484c;
    color: #f0f0f0;
    selection-background-color: #094771;
    selection-color: #ffffff;
}
QTableWidget::item, QTableView::item {
    padding: 3px 6px;
    border-bottom: 1px solid #3a3a3d;
}
QTableWidget::item:selected, QTableView::item:selected {
    background-color: #094771;
    color: #ffffff;
}
QHeaderView::section {
    background-color: #3a3a3d;
    color: #f0f0f0;
    border: none;
    border-right: 1px solid #55555a;
    border-bottom: 1px solid #66666b;
    padding: 6px;
    font-size: 10px;
    font-weight: 600;
}
QTableCornerButton::section { background: #3a3a3d; border: none; }

QTabWidget::pane {
    border: 1px solid #55555a;
    border-radius: 0px;
    background-color: #252526;
    top: -1px;
}
QTabBar::tab {
    background: #333337;
    color: #d8d8d8;
    border: 1px solid #55555a;
    border-bottom: none;
    padding: 6px 14px;
    margin-right: 1px;
    border-radius: 0px;
}
QTabBar::tab:selected {
    background-color: #252526;
    color: #ffffff;
    border-top: 2px solid #0a84ff;
}
QTabBar::tab:hover { background-color: #3e3e43; }

QProgressBar {
    background-color: #333337;
    border: 1px solid #66666b;
    border-radius: 0px;
    height: 12px;
    text-align: center;
    color: #f0f0f0;
}
QProgressBar::chunk { background-color: #0a84ff; border-radius: 0px; }

QScrollBar:vertical { background: #252526; width: 14px; margin: 0; }
QScrollBar::handle:vertical { background: #5a5a5f; min-height: 24px; border-radius: 0px; }
QScrollBar::handle:vertical:hover { background: #77777d; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 14px; background: #3a3a3d; border: 1px solid #55555a;
}
QScrollBar:horizontal { background: #252526; height: 14px; margin: 0; }
QScrollBar::handle:horizontal { background: #5a5a5f; min-width: 24px; border-radius: 0px; }
QScrollBar::handle:horizontal:hover { background: #77777d; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 14px; background: #3a3a3d; border: 1px solid #55555a;
}

QGroupBox {
    border: 1px solid #55555a;
    border-radius: 0px;
    margin-top: 10px;
    padding: 12px 10px 10px 10px;
    font-weight: 600;
    color: #f0f0f0;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: #f0f0f0;
}
QSplitter::handle { background: #4a4a4f; width: 3px; height: 3px; }

QMenuBar {
    background-color: #2d2d30;
    color: #f0f0f0;
    border-bottom: 1px solid #55555a;
    padding: 1px 4px;
}
QMenuBar::item { padding: 4px 9px; background: transparent; }
QMenuBar::item:selected { background-color: #094771; color: #ffffff; }
QMenu {
    background-color: #2d2d30;
    border: 1px solid #77777d;
    padding: 2px;
    color: #f0f0f0;
}
QMenu::item { padding: 5px 28px 5px 22px; border-radius: 0px; }
QMenu::item:selected { background-color: #094771; color: #ffffff; }
QToolTip {
    background-color: #333337;
    color: #f0f0f0;
    border: 1px solid #77777d;
    padding: 4px;
}
QStatusBar {
    background-color: #1b1b1b;
    color: #d0d0d0;
    border-top: 1px solid #444448;
}
"""


class NativeChevronStyle(QProxyStyle):
    """Fusion style with a visible chevron on combo boxes."""

    def drawPrimitive(self, element, option, painter, widget=None):              
        if element == QStyle.PrimitiveElement.PE_IndicatorArrowDown:
            rect = option.rect
            colour = QColor("#c8c8c8")
            if not (option.state & QStyle.StateFlag.State_Enabled):
                colour = QColor("#77777d")
            pen = QPen(colour, 1.5)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.save()
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            painter.setPen(pen)
            cx = rect.center().x()
            cy = rect.center().y()
            painter.drawLine(QPointF(cx - 4, cy - 2), QPointF(cx, cy + 2))
            painter.drawLine(QPointF(cx, cy + 2), QPointF(cx + 4, cy - 2))
            painter.restore()
            return
        super().drawPrimitive(element, option, painter, widget)


def apply_theme(app: QApplication) -> None:
    app.setStyle(NativeChevronStyle("Fusion"))
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#1b1b1b"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#f0f0f0"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#3c3c3c"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#2b2b2e"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#f0f0f0"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#3a3a3d"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#f0f0f0"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#094771"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#333337"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#f0f0f0"))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#9a9a9a"))
    app.setPalette(palette)
    app.setStyleSheet(QSS)
    font = app.font()
    font.setPointSizeF(9.0)
    app.setFont(font)
