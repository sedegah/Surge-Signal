"""Surge Signal desktop application entry point."""

from __future__ import annotations

import argparse
import logging
import sys
import traceback
from pathlib import Path

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox, QSplashScreen

from .core.branding import APP_NAME, APP_VERSION, BUILD_NAME, TAGLINE
from .core.assets import icon_path, startup_banner_path
from .core.config import AppPaths, Settings, configure_logging
from .core.db import Database
from .audit.research import ResearchConnector
from .core.security_fs import harden_data_directory
from .core.services import SurgeService
from .ui.main_window import MainWindow
from .ui.theme import apply_theme
from .audit.wordlists import WordlistManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} {APP_VERSION}")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Override the per-user data directory (useful for testing).",
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Launch, verify the main window renders, then exit.",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    return parser


def _app_icon() -> QIcon:
    asset = icon_path()
    if asset.is_file():
        return QIcon(str(asset))
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.GlobalColor.transparent)
    from PySide6.QtGui import QPainter, QColor, QPen

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setBrush(QColor("#e8590c"))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawRoundedRect(6, 6, 52, 52, 14, 14)
    painter.setBrush(QColor("#fff4ec"))
    painter.drawEllipse(27, 37, 10, 10)
    pen = QPen(QColor("#fff4ec"), 4)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawArc(20, 17, 24, 24, 45 * 16, 90 * 16)
    painter.drawArc(13, 10, 38, 38, 45 * 16, 90 * 16)
    painter.end()
    return QIcon(pixmap)


def create_application(
    data_dir: Path | None = None, *, smoke_test: bool = False
) -> tuple[QApplication, MainWindow, SurgeService]:
    paths = AppPaths.create(data_dir)
    logger = configure_logging(paths)
    acl_ok, acl_detail = harden_data_directory(paths.home)
    if acl_ok:
        logger.info("%s", acl_detail)
    else:
        logger.warning("Data directory ACL hardening: %s", acl_detail)
    logger.info("Starting %s %s (%s)", APP_NAME, APP_VERSION, BUILD_NAME)

    db = Database(paths.database)
    if sys.platform != "win32":
        try:
            paths.database.chmod(0o600)
        except OSError:
            logger.warning("Database file permissions could not be restricted.")
    settings = Settings(db)
    connector = ResearchConnector(settings, paths, logger=logger)
    service = SurgeService(db, paths, settings, connector, logger=logger)
    capture_dir = settings.capture_output_dir()
    try:
        capture_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        logger.warning("Capture output directory is not writable: %s", capture_dir)
    manager = WordlistManager(db, paths, settings)
    manager.ensure_layout()
    if not (paths.wordlists / "metadata" / "wordlist-index.json").exists():
        manager.write_index()

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("Surge Signal")
    app.setWindowIcon(_app_icon())
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "SurgeSignal.Desktop.1"
            )
        except Exception:
            pass
    apply_theme(app)
    splash = None
    if not smoke_test:
        pixmap = QPixmap(str(startup_banner_path()))
        if not pixmap.isNull():
            splash = QSplashScreen(
                pixmap.scaled(
                    1000,
                    563,
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                ),
                Qt.WindowType.SplashScreen | Qt.WindowType.WindowStaysOnTopHint,
            )
            splash.show()
            app.processEvents()
    window = MainWindow(service, paths, smoke_test=smoke_test)
    window._splash = splash

    def handle_exception(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        logger.error(
            "Unhandled exception: %s",
            "".join(traceback.format_exception(exc_type, exc_value, exc_tb)),
        )
        try:
            QMessageBox.critical(
                window,
                "Unexpected error",
                "SURGE Signal encountered an unexpected error. The operation was stopped "
                "safely and details were written to the application log.\n\n"
                f"{exc_value}",
            )
        except RuntimeError:
                                                           
            pass

    sys.excepthook = handle_exception
    return app, window, service


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        app, window, _service = create_application(args.data_dir, smoke_test=args.smoke_test)
    except Exception as exc:
        logger = logging.getLogger("surge_signal")
        logger.exception("Startup failed")
        app = QApplication.instance() or QApplication(sys.argv)
        QMessageBox.critical(
            None,
            f"{APP_NAME} could not start",
            "The application could not initialise its local data store.\n\n"
            f"{exc}\n\n"
            "Check permissions on your local application data folder, then try again.",
        )
        return 1
    if not args.smoke_test:
        from .ui.terms import TermsDialog, terms_accepted

        if not terms_accepted(_service.settings):
            splash = getattr(window, "_splash", None)
            if splash is not None:
                splash.close()
            terms = TermsDialog(_service.settings, window)
            if terms.exec() != QDialog.DialogCode.Accepted:
                return 0
    window.show()
    splash = getattr(window, "_splash", None)
    if splash is not None:
        QTimer.singleShot(1400, splash.close)
    if args.smoke_test:
        QTimer.singleShot(900, app.quit)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

