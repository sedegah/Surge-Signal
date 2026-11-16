from __future__ import annotations

import json
from pathlib import Path

from surge_signal.audit.wordlists import CATALOG, WordlistManager


def test_catalog_has_curated_entries(app_paths, db, settings) -> None:
    manager = WordlistManager(db, app_paths, settings)
    manager.ensure_layout()
    catalog = manager.catalog()
    assert len(catalog) == len(CATALOG) == 13
    essential = [item for item in catalog if item["essential"]]
    assert len(essential) >= 8
    assert {item["category"] for item in catalog} >= {
        "common",
        "wifi",
        "default",
        "regional",
        "comprehensive",
        "custom",
        "leaked",
    }


def test_import_and_prepare_deduplicate_and_filter(app_paths, db, settings) -> None:
    manager = WordlistManager(db, app_paths, settings)
    manager.ensure_layout()
    first = app_paths.wordlists / "wifi" / "wifi-test.txt"
    first.write_text(
        "short\n"
        "lab-password-one\n"
        "lab-password-one\n"
        "lab-password-two\n"
        + "x" * 80
        + "\n",
        encoding="utf-8",
    )
    second = app_paths.wordlists / "common" / "common-test.txt"
    second.write_text("lab-password-two\ncommon-password\n", encoding="utf-8")
    scan = manager.scan_library()
    assert scan.registered == 2
    records = manager.lists(include_prepared=False)
    ids = [int(item["id"]) for item in records]
    prepared = manager.prepare(ids, min_length=8, max_length=63, max_candidates=100)
    assert prepared.candidate_count == 3
    assert prepared.truncated is False
    lines = Path(prepared.path).read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(set(lines))
    assert "short" not in lines
    assert "x" * 80 not in lines
                                                  
    assert lines.index("lab-password-one") < lines.index("common-password")


def test_candidate_cap_and_index(app_paths, db, settings) -> None:
    manager = WordlistManager(db, app_paths, settings)
    manager.ensure_layout()
    path = app_paths.wordlists / "custom" / "many.txt"
    path.write_text("\n".join(f"candidate-{i}" for i in range(50)), encoding="utf-8")
    manager.scan_library()
    record = manager.lists(include_prepared=False)[0]
    prepared = manager.prepare([int(record["id"])], max_candidates=10)
    assert prepared.candidate_count == 10
    assert prepared.truncated
    index = json.loads(manager.write_index().read_text(encoding="utf-8"))
    assert index["schema"] == "surge-signal.wordlists.v1"
    assert index["catalog"]


def test_create_custom_list(app_paths, db, settings) -> None:
    manager = WordlistManager(db, app_paths, settings)
    manager.ensure_layout()
    record = manager.create_custom_list(
        "lab-context", ["LabNet2026!", "LabNet2026!", "second-candidate"], "Context"
    )
    assert record["line_count"] == 2
    assert Path(record["path"]).is_file()
    assert record["category"] == "custom"

