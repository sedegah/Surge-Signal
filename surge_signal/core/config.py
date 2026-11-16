"""Application paths, settings and logging.

Settings are stored in SQLite. Secrets are deliberately excluded: the Linux
password is never written to settings, the database or logs.
"""

from __future__ import annotations

import logging
import os
import sys
import tempfile
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


APP_DIR_NAME = "SurgeSignal"


def default_home() -> Path:
    """Return the per-user application data directory."""
    override = os.environ.get("SURGE_SIGNAL_HOME")
    if override:
        return Path(override).expanduser().resolve()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / APP_DIR_NAME
    return Path.home() / f".{APP_DIR_NAME.lower()}"


@dataclass(frozen=True)
class AppPaths:
    home: Path
    database: Path
    evidence: Path
    reports: Path
    captures: Path
    wordlists: Path
    logs: Path
    exchange: Path

    @classmethod
    def create(cls, home: Path | None = None) -> "AppPaths":
        home = Path(home).expanduser().resolve() if home else default_home()
        paths = cls(
            home=home,
            database=home / "surge_signal.core.db",
            evidence=home / "evidence",
            reports=home / "reports",
            captures=home / "captures",
            wordlists=home / "wordlists",
            logs=home / "logs",
            exchange=home / "exchange",
        )
        for directory in (
            paths.home,
            paths.evidence,
            paths.reports,
            paths.captures,
            paths.wordlists,
            paths.logs,
            paths.exchange,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        for category in (
            "common",
            "wifi",
            "default",
            "regional",
            "comprehensive",
            "custom",
            "leaked",
            "prepared",
            "metadata",
        ):
            (paths.wordlists / category).mkdir(parents=True, exist_ok=True)
        return paths


def default_capture_dir() -> Path:
    """Return a visible, user-friendly place for recorded capture files."""
    if sys.platform == "win32":
        profile = Path(os.environ.get("USERPROFILE", str(Path.home())))
        for candidate in (
            profile / "Desktop",
            profile / "OneDrive" / "Desktop",
        ):
            if candidate.is_dir():
                return candidate / "Surge Signal Captures"
        return profile / "Desktop" / "Surge Signal Captures"
    return Path.home() / "Surge Signal Captures"


DEFAULT_SETTINGS: dict[str, str] = {
    "research_mode": "native" if sys.platform != "win32" else "wsl",
    "wsl_distro": "kali-linux",
    "ssh_host": "",
    "ssh_user": "",
    "kali_share": r"C:\SurgeSignalShare",
    "kali_linux_share": "/mnt/surge",
    "aircrack_path": "aircrack-ng",
    "tshark_path": "tshark",
    "sudo_timeout_seconds": "120",
    "wordlist_dir": "",
    "operator_name": "",
    "auto_scan_on_open": "true",
    "auto_scan_interval_seconds": "45",
    "max_local_candidates": "100000",
    "wordlist_include_min": "8",
    "wordlist_include_max": "63",
    "wordlist_max_candidates": "1000000",
    "wordlist_priority_enabled": "true",
    "wordlist_prune_keep": "10",
    "capture_output_dir": "",
    "report_output_dir": "",
    "last_assessment_id": "",
}


class Settings:
    """Typed access to persisted application settings."""

    def __init__(self, db: Any):
        self._db = db

    def get(self, key: str, default: str | None = None) -> str:
        value = self._db.get_setting(key)
        if value is None:
            return DEFAULT_SETTINGS.get(key, default or "")
        return value

    def get_bool(self, key: str, default: bool = False) -> bool:
        raw = self.get(key, "true" if default else "false").strip().lower()
        return raw in {"1", "true", "yes", "on"}

    def get_int(self, key: str, default: int = 0) -> int:
        try:
            return int(self.get(key, str(default)))
        except (TypeError, ValueError):
            return default

    def set(self, key: str, value: str | int | bool) -> None:
        self._db.set_setting(key, str(value))

    def all(self) -> dict[str, str]:
        values = dict(DEFAULT_SETTINGS)
        values.update(self._db.all_settings())
        return values

    def capture_output_dir(self) -> Path:
        configured = self.get("capture_output_dir", "").strip()
        return Path(configured) if configured else default_capture_dir()

    def as_dict(self) -> dict[str, str]:
        return self.all()


_SENSITIVE_MARKERS = (
    "password",
    "passwd",
    "secret",
    "sudo",
    "credential",
    "token",
)


class RedactingFilter(logging.Filter):
    """Defence in depth against accidental credential logging."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        lowered = message.lower()
        if any(f"{marker}=" in lowered for marker in _SENSITIVE_MARKERS):
            record.msg = "[redacted log message containing a sensitive field]"
            record.args = ()
        return True


def configure_logging(paths: AppPaths, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("surge_signal")
    logger.setLevel(level)
    logger.propagate = False
    if logger.handlers:
        return logger

    def make_handler(filename: Path) -> RotatingFileHandler:
        return RotatingFileHandler(
            filename,
            maxBytes=1_500_000,
            backupCount=3,
            encoding="utf-8",
        )

    handler: logging.Handler
    try:
        handler = make_handler(paths.logs / "surge_signal.log")
    except OSError:
                                                                           
                                                                        
        fallback_dir = Path(tempfile.gettempdir()) / "SurgeSignal" / "logs"
        try:
            fallback_dir.mkdir(parents=True, exist_ok=True)
            handler = make_handler(fallback_dir / "surge_signal.log")
        except OSError:
            handler = logging.NullHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)

    try:
        console = logging.StreamHandler()
        console.setLevel(logging.WARNING)
        console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        console.addFilter(RedactingFilter())
        logger.addHandler(console)
    except Exception:
        pass
    return logger

