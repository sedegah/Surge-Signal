from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from surge_signal.core.config import AppPaths, Settings
from surge_signal.core.db import Database
from surge_signal.audit.research import ResearchConnector
from surge_signal.core.services import SurgeService


@pytest.fixture()
def app_paths(tmp_path: Path) -> AppPaths:
    return AppPaths.create(tmp_path / "SurgeSignalData")


@pytest.fixture()
def db(app_paths: AppPaths) -> Database:
    return Database(app_paths.database)


@pytest.fixture()
def settings(db: Database) -> Settings:
    return Settings(db)


@pytest.fixture()
def service(db: Database, app_paths: AppPaths, settings: Settings) -> SurgeService:
    connector = ResearchConnector(settings, app_paths)
    return SurgeService(db, app_paths, settings, connector)

