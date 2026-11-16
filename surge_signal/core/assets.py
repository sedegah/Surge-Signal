"""Locate bundled brand assets in source and frozen builds."""

from __future__ import annotations

import sys
from pathlib import Path


def asset_path(name: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base / "assets" / name


def banner_path() -> Path:
    return asset_path("brand-banner.jpg")


def banner_wide_path() -> Path:
    return asset_path("brand-banner-wide.jpg")


def startup_banner_path() -> Path:
    return asset_path("startup-banner.jpg")


def icon_path() -> Path:
    return asset_path("surge-signal.ico")


def icon_png(size: int = 256) -> Path:
    return asset_path(f"surge-signal-{size}.png")

