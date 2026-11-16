"""Curated wordlist library, candidate preparation and prioritisation.

The application does not bundle downloads of third-party lists. It provides a
catalog with provenance, a managed folder library, safe import, per-list
statistics and a prepared-candidate pipeline that filters WPA-compatible
lengths, removes duplicates and orders lists by assessment priority.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import shutil
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from ..core.config import AppPaths, Settings
from ..core.db import Database
from ..core.domain import iso_now
from .password_audit import WordlistInfo, inspect_wordlist


class WordlistError(RuntimeError):
    pass


class WordlistCancelled(WordlistError):
    pass


CATEGORY_LABELS = {
    "wifi": "Wi-Fi specific",
    "default": "Default credentials",
    "common": "Common passwords",
    "regional": "Regional / language",
    "custom": "Custom contextual",
    "comprehensive": "Comprehensive",
    "leaked": "Leaked corpus",
    "prepared": "Prepared audit list",
}

CATEGORY_PRIORITY = {
    "wifi": 10,
    "default": 20,
    "common": 30,
    "regional": 40,
    "custom": 50,
    "comprehensive": 60,
    "leaked": 70,
    "prepared": 0,
}

SUPPORTED_SUFFIXES = {".txt", ".lst", ".dic", ".csv"}
SUPPORTED_ARCHIVES = {".gz"}


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    id: str
    name: str
    category: str
    description: str
    source_url: str
    license_note: str
    approximate_size: str
    essential: bool
    hints: tuple[str, ...]
    guidance: str = "Download from the official source, review its licence and then "
    "import the file into the matching library category."


CATALOG: tuple[CatalogEntry, ...] = (
    CatalogEntry(
        "rockyou",
        "RockYou",
        "common",
        "The long-standing common-password corpus distributed with Kali and used "
        "as a baseline for offline candidate testing.",
        "https://www.kali.org/tools/wordlists/",
        "Kali package / upstream corpus terms; review before redistribution.",
        "~133 MB compressed",
        True,
        ("rockyou",),
        "On Kali, install the `wordlists` package and extract "
        "`/usr/share/wordlists/rockyou.txt.gz`, then import it as Common passwords.",
    ),
    CatalogEntry(
        "seclists",
        "SecLists",
        "comprehensive",
        "A broad maintained collection of security testing lists, including password, "
        "username and default-credential material.",
        "https://github.com/danielmiessler/SecLists",
        "MIT licence for the repository; individual lists may carry additional terms.",
        "Several GB",
        True,
        ("seclists", "10-million", "top-1000000", "darkweb2017"),
        "Import only the specific password files needed for the engagement rather than "
        "the entire repository.",
    ),
    CatalogEntry(
        "weakpass",
        "Weakpass",
        "comprehensive",
        "Large curated password collections intended for authorised password-strength "
        "testing and research.",
        "https://weakpass.com/wordlists",
        "Weakpass terms apply; do not redistribute without permission.",
        "Hundreds of MB to many GB",
        True,
        ("weakpass",),
        "Choose a collection appropriate to the engagement size. Prefer merged, "
        "deduplicated lists over many overlapping downloads.",
    ),
    CatalogEntry(
        "probable-wordlists",
        "Probable-Wordlists",
        "common",
        "Probability-ordered password lists designed to put likely candidates first.",
        "https://github.com/berzerk0/Probable-Wordlists",
        "CC-BY / repository terms; attribution may be required.",
        "Hundreds of MB",
        True,
        ("probable", "realhuman", "dictionary"),
        "Probability ordering is a good fit for the local verifier's candidate cap.",
    ),
    CatalogEntry(
        "crackstation",
        "CrackStation",
        "comprehensive",
        "A large human-only password dictionary assembled from public breach data.",
        "https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm",
        "CrackStation terms apply; review before use.",
        "~700 MB compressed",
        True,
        ("crackstation", "human-only"),
        "Download only for authorised laboratory work and store it in the managed "
        "library rather than an unmanaged desktop folder.",
    ),
    CatalogEntry(
        "wifi-patterns",
        "Wi-Fi password patterns",
        "wifi",
        "Wi-Fi-specific candidates such as router-derived names, common WPA "
        "passphrases and location/SSID patterns.",
        "https://github.com/danielmiessler/SecLists",
        "Review upstream list terms.",
        "Small to tens of MB",
        True,
        ("wifi", "wpa", "wlan"),
        "Curate candidates for the lab SSID and regional context; do not target "
        "third-party networks.",
    ),
    CatalogEntry(
        "default-credentials",
        "Default router credentials",
        "default",
        "Factory-default and vendor-default credentials, useful for laboratory "
        "configuration auditing.",
        "https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials",
        "Review upstream list terms.",
        "Small",
        True,
        ("default", "router", "vendor"),
        "Default lists are most useful as a configuration check; only test equipment "
        "you are authorised to assess.",
    ),
    CatalogEntry(
        "default-wifi-keys",
        "Default Wi-Fi keys",
        "wifi",
        "Known factory WPA keys and vendor-derived patterns for authorised lab gear.",
        "https://github.com/danielmiessler/SecLists",
        "Verify provenance and licence before use.",
        "Small",
        True,
        ("default-wifi", "wifi-key", "wlan-key"),
        "Validate against the exact router model before drawing conclusions.",
    ),
    CatalogEntry(
        "ghana",
        "Ghana contextual passwords",
        "regional",
        "A curated regional list containing approved local names, places, institutions "
        "and common patterns for Ghanaian engagements.",
        "",
        "Organisation-authored; observe privacy and data-protection obligations.",
        "Small, organisation-defined",
        True,
        ("ghana", "accra", "kumasi"),
        "Build from approved, non-sensitive contextual terms and store it in Regional. "
        "Do not include personal data without a lawful basis.",
    ),
    CatalogEntry(
        "west-africa",
        "West Africa contextual passwords",
        "regional",
        "Approved regional names, languages and patterns for West African assessments.",
        "",
        "Organisation-authored; observe privacy and data-protection obligations.",
        "Small, organisation-defined",
        True,
        ("west-africa", "westafrica", "yoruba", "igbo", "hausa", "twi"),
        "Keep lists compartmentalised by engagement and review them before import.",
    ),
    CatalogEntry(
        "language-packs",
        "Language packs",
        "regional",
        "Additional language-specific dictionaries and password transliterations.",
        "https://github.com/danielmiessler/SecLists/tree/master/Passwords",
        "Review the licence of each language pack.",
        "Varies",
        False,
        ("language", "french", "spanish", "arabic", "swahili"),
        "Use only languages relevant to the authorised scope; avoid unnecessary "
        "personal-data collection.",
    ),
    CatalogEntry(
        "custom-contextual",
        "Custom contextual list",
        "custom",
        "Engagement-specific candidates derived from approved site context and "
        "organisation naming conventions.",
        "",
        "Organisation-authored; handle as sensitive assessment material.",
        "Engagement-defined",
        True,
        ("custom", "context"),
        "Create custom lists inside Surge Signal so they remain hashed, associated "
        "with the engagement and easy to review.",
    ),
    CatalogEntry(
        "pwned-passwords",
        "Pwned Passwords corpus",
        "leaked",
        "A previously exposed password corpus used only to check whether an approved "
        "credential has appeared in a breach.",
        "https://haveibeenpwned.com/Passwords",
        "HIBP terms and data-protection obligations apply.",
        "Very large",
        False,
        ("pwned", "hibp", "leaked"),
        "Use a lawful, authorised corpus. Do not import personal data you are not "
        "entitled to process. Prefer the HIBP range API for checking a specific value.",
    ),
)


@dataclass(slots=True)
class ScanResult:
    registered: int = 0
    updated: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)
    lists: list[dict[str, Any]] = field(default_factory=list)
    index_path: str = ""


@dataclass(slots=True)
class PreparedWordlist:
    id: int
    path: str
    candidate_count: int
    scanned_count: int
    source_lists: list[str]
    truncated: bool
    size_bytes: int
    sha256: str
    min_length: int
    max_length: int


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")
    return cleaned[:100] or "wordlist"


def _category_for(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return "custom"
    if len(relative.parts) > 1 and relative.parts[0] in CATEGORY_LABELS:
        return relative.parts[0]
    return "custom"


def _catalog_for(name: str, category: str) -> str:
    lowered = name.lower()
    for entry in CATALOG:
        if entry.category != category:
            continue
        if any(hint in lowered for hint in entry.hints):
            return entry.id
    return ""


class WordlistManager:
    def __init__(self, db: Database, paths: AppPaths, settings: Settings):
        self.db = db
        self.paths = paths
        self.settings = settings
        self.root = paths.wordlists

                                                                                 
    def ensure_layout(self) -> None:
        for category in CATALOG:
            (self.root / category.category).mkdir(parents=True, exist_ok=True)
        (self.root / "metadata").mkdir(parents=True, exist_ok=True)
        (self.root / "prepared").mkdir(parents=True, exist_ok=True)

    def scan_library(
        self,
        progress: Callable[[int, int, str], None] | None = None,
    ) -> ScanResult:
        self.ensure_layout()
        result = ScanResult()
        candidates: list[Path] = []
        for path in self.root.rglob("*"):
            if not path.is_file():
                continue
            relative_parts = path.relative_to(self.root).parts
            if relative_parts and relative_parts[0] == "prepared":
                continue
            if path.suffix.lower() in SUPPORTED_ARCHIVES:
                target = path.with_suffix(".txt")
                if not target.exists():
                    try:
                        self._decompress_gzip(path, target)
                    except WordlistError as exc:
                        result.skipped += 1
                        result.errors.append(f"{path.name}: {exc}")
                        continue
                path = target
            if path.suffix.lower() in SUPPORTED_SUFFIXES:
                candidates.append(path)
        for index, path in enumerate(sorted(candidates), start=1):
            if progress:
                progress(index, len(candidates), path.name)
            try:
                info = inspect_wordlist(path, max_lines=20_000_000)
            except (OSError, ValueError) as exc:
                result.skipped += 1
                result.errors.append(f"{path.name}: {exc}")
                continue
            category = _category_for(path, self.root)
            catalog_id = _catalog_for(info.name, category)
            record_id = self.db.add_wordlist(
                name=info.name,
                path=info.path,
                description=f"{CATEGORY_LABELS.get(category, category)} library list.",
                line_count=info.line_count,
                sha256=info.sha256,
                size_bytes=info.size_bytes,
                category=category,
                source="library",
                priority=CATEGORY_PRIORITY.get(category, 50),
                min_length=info.min_length,
                max_length=info.max_length,
                catalog_id=catalog_id,
            )
            if record_id:
                result.registered += 1
            else:
                result.updated += 1
        result.lists = self.lists(include_prepared=False)
        result.index_path = str(self.write_index())
        return result

    def lists(self, include_prepared: bool = True) -> list[dict[str, Any]]:
        records = self.db.list_wordlists(include_prepared=include_prepared)
        for record in records:
            record["category_label"] = CATEGORY_LABELS.get(
                record.get("category", "custom"), record.get("category", "custom")
            )
            record["exists"] = Path(record["path"]).is_file()
            record["size_label"] = _size_label(int(record.get("size_bytes") or 0))
        return records

    def get(self, wordlist_id: int) -> dict[str, Any]:
        record = self.db.get_wordlist(wordlist_id)
        if not record:
            raise WordlistError("Wordlist record not found.")
        if not Path(record["path"]).is_file():
            raise WordlistError(f"Wordlist file is missing: {record['path']}")
        return record

    def import_file(
        self,
        source_path: Path | str,
        category: str = "custom",
        *,
        description: str = "",
        name: str | None = None,
    ) -> dict[str, Any]:
        self.ensure_layout()
        if category not in CATEGORY_LABELS or category == "prepared":
            raise WordlistError(f"Invalid wordlist category: {category}")
        source = Path(source_path)
        if not source.is_file():
            raise WordlistError(f"Wordlist file not found: {source}")
        suffix = source.suffix.lower()
        if suffix not in SUPPORTED_SUFFIXES and suffix not in SUPPORTED_ARCHIVES:
            raise WordlistError(
                "Unsupported wordlist format. Use .txt, .lst, .dic, .csv or .gz."
            )
        destination_dir = self.root / category
        destination_dir.mkdir(parents=True, exist_ok=True)
        target_name = _safe_name(name or source.stem)
        if suffix in SUPPORTED_ARCHIVES:
            destination = destination_dir / f"{target_name}.txt"
            self._decompress_gzip(source, destination)
        else:
            destination = destination_dir / f"{target_name}{suffix}"
            if destination.exists():
                destination = destination_dir / f"{target_name}-{uuid.uuid4().hex[:6]}{suffix}"
            try:
                shutil.copy2(source, destination)
            except OSError as exc:
                raise WordlistError(f"Wordlist could not be copied: {exc}") from exc
        try:
            info = inspect_wordlist(destination, max_lines=20_000_000)
        except (OSError, ValueError) as exc:
            destination.unlink(missing_ok=True)
            raise WordlistError(str(exc)) from exc
        catalog_id = _catalog_for(info.name, category)
        self.db.add_wordlist(
            name=info.name,
            path=info.path,
            description=description or f"Imported {CATEGORY_LABELS[category]} list.",
            line_count=info.line_count,
            sha256=info.sha256,
            size_bytes=info.size_bytes,
            category=category,
            source="imported",
            priority=CATEGORY_PRIORITY.get(category, 50),
            min_length=info.min_length,
            max_length=info.max_length,
            catalog_id=catalog_id,
        )
        self.write_index()
        self.db.log(
            "wordlist.imported",
            f"Imported {info.name} into {CATEGORY_LABELS[category]} "
            f"({info.line_count:,} candidates, SHA-256 {info.sha256[:16]}…).",
        )
        record = next(
            (item for item in self.db.list_wordlists() if item["path"] == info.path), None
        )
        if not record:
            raise WordlistError("Wordlist was imported but could not be registered.")
        return record

    @staticmethod
    def _decompress_gzip(source: Path, destination: Path) -> None:
        total = 0
        try:
            with gzip.open(source, "rb") as reader, destination.open("wb") as writer:
                while chunk := reader.read(1024 * 1024):
                    total += len(chunk)
                    if total > 2 * 1024 * 1024 * 1024:
                        raise WordlistError("Decompressed wordlist exceeds the 2 GB limit.")
                    writer.write(chunk)
        except (OSError, gzip.BadGzipFile) as exc:
            destination.unlink(missing_ok=True)
            raise WordlistError(f"Compressed wordlist could not be read: {exc}") from exc

    def create_custom_list(
        self, name: str, candidates: Iterable[str], description: str = ""
    ) -> dict[str, Any]:
        self.ensure_layout()
        values: list[str] = []
        seen: set[str] = set()
        for raw in candidates:
            candidate = str(raw).strip("\r\n")
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            values.append(candidate)
        if not values:
            raise WordlistError("At least one candidate is required.")
        path = self.root / "custom" / f"{_safe_name(name)}.txt"
        if path.exists():
            path = self.root / "custom" / f"{_safe_name(name)}-{uuid.uuid4().hex[:6]}.txt"
        path.write_text("\n".join(values) + "\n", encoding="utf-8")
        return self.import_file(
            path,
            "custom",
            description=description or "Custom contextual wordlist created in Surge Signal.",
            name=path.stem,
        )

    def remove(self, wordlist_id: int, *, delete_file: bool = False) -> None:
        path = self.db.remove_wordlist_record(wordlist_id, delete_file=delete_file)
        if path is None:
            raise WordlistError("Wordlist record not found.")
        self.db.log(
            "wordlist.removed",
            f"Removed wordlist record for {Path(path).name}; file deleted={delete_file}.",
        )
        self.write_index()

                                                                                  
    def catalog(self) -> list[dict[str, Any]]:
        records = self.db.list_wordlists(include_prepared=True)
        by_catalog: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            key = str(record.get("catalog_id") or "")
            if key:
                by_catalog.setdefault(key, []).append(record)
        entries: list[dict[str, Any]] = []
        for entry in CATALOG:
            installed = by_catalog.get(entry.id, [])
            entries.append(
                {
                    "id": entry.id,
                    "name": entry.name,
                    "category": entry.category,
                    "category_label": CATEGORY_LABELS.get(entry.category, entry.category),
                    "description": entry.description,
                    "source_url": entry.source_url,
                    "license_note": entry.license_note,
                    "approximate_size": entry.approximate_size,
                    "essential": entry.essential,
                    "guidance": entry.guidance,
                    "installed_count": len(installed),
                    "installed": bool(installed),
                    "installed_lines": sum(int(item.get("line_count") or 0) for item in installed),
                    "installed_files": [Path(item["path"]).name for item in installed],
                }
            )
        return entries

    def write_index(self) -> Path:
        metadata = self.root / "metadata"
        metadata.mkdir(parents=True, exist_ok=True)
        records = self.db.list_wordlists(include_prepared=True)
        payload = {
            "schema": "surge-signal.wordlists.v1",
            "generated_at": iso_now(),
            "root": str(self.root),
            "categories": CATEGORY_LABELS,
            "catalog": self.catalog(),
            "lists": [
                {
                    "name": item["name"],
                    "path": item["path"],
                    "category": item["category"],
                    "priority": item["priority"],
                    "line_count": item["line_count"],
                    "size_bytes": item.get("size_bytes", 0),
                    "min_length": item["min_length"],
                    "max_length": item["max_length"],
                    "sha256": item["sha256"],
                    "is_prepared": bool(item["is_prepared"]),
                }
                for item in records
            ],
        }
        path = metadata / "wordlist-index.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

                                                                                  
    def prepare(
        self,
        wordlist_ids: list[int],
        *,
        min_length: int = 8,
        max_length: int = 63,
        max_candidates: int = 1_000_000,
        progress: Callable[[int, int, int, str], None] | None = None,
        stop_event: threading.Event | None = None,
    ) -> PreparedWordlist:
        if not wordlist_ids:
            raise WordlistError("Select at least one wordlist.")
        if min_length < 1 or max_length > 63 or min_length > max_length:
            raise WordlistError("Candidate length must be within 1–63 characters.")
        if max_candidates < 1:
            raise WordlistError("Candidate cap must be at least 1.")
        records = [self.get(wordlist_id) for wordlist_id in wordlist_ids]
        records.sort(key=lambda item: (int(item.get("priority") or 50), item["name"]))
        total_source_lines = sum(int(item.get("line_count") or 0) for item in records)
        total_estimate = min(total_source_lines, max(max_candidates, 1))
        self.ensure_layout()
        prepared_dir = self.root / "prepared"
        prepared_dir.mkdir(parents=True, exist_ok=True)
        stage_path = prepared_dir / f".stage-{uuid.uuid4().hex}.db"
        connection = sqlite3.connect(stage_path)
        connection.execute("PRAGMA journal_mode = OFF")
        connection.execute("PRAGMA synchronous = OFF")
        connection.execute(
            """CREATE TABLE candidates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                digest BLOB NOT NULL UNIQUE,
                value TEXT NOT NULL,
                source TEXT NOT NULL
            )"""
        )
        connection.commit()
        scanned = 0
        accepted = 0
        invalid = 0
        filtered = 0
        truncated = False
        batch: list[tuple[bytes, str, str]] = []
        cancelled = False
        try:
            for record in records:
                if cancelled or (stop_event and stop_event.is_set()):
                    cancelled = True
                    break
                path = Path(record["path"])
                if not path.is_file():
                    raise WordlistError(f"Wordlist file is missing: {path}")
                opener = gzip.open if path.suffix.lower() == ".gz" else open
                with opener(path, "rb") as handle:                          
                    for raw in handle:
                        if stop_event and stop_event.is_set():
                            cancelled = True
                            break
                        scanned += 1
                        candidate_bytes = raw.rstrip(b"\r\n")
                        if not candidate_bytes:
                            continue
                        try:
                            candidate = candidate_bytes.decode("utf-8")
                        except UnicodeDecodeError:
                            invalid += 1
                            continue
                        if any(
                            ord(char) < 32 and char != "\t" for char in candidate
                        ) or "\x00" in candidate:
                            invalid += 1
                            continue
                        if len(candidate) < min_length or len(candidate) > max_length:
                            filtered += 1
                            continue
                        digest = hashlib.blake2b(
                            candidate_bytes, digest_size=16
                        ).digest()
                        batch.append((digest, candidate, record["name"]))
                        if len(batch) >= 2500:
                            accepted += self._insert_batch(connection, batch, max_candidates - accepted)
                            batch.clear()
                            if progress:
                                progress(scanned, total_estimate, accepted, record["name"])
                            if accepted >= max_candidates:
                                truncated = True
                                cancelled = True
                                break
                if cancelled:
                    break
            if batch and accepted < max_candidates:
                accepted += self._insert_batch(connection, batch, max_candidates - accepted)
            if accepted >= max_candidates and total_source_lines > max_candidates:
                truncated = True
            connection.commit()
            if stop_event and stop_event.is_set():
                cancelled = True
            if cancelled and accepted < max_candidates:
                raise WordlistCancelled("Wordlist preparation cancelled by the operator.")
            if accepted == 0:
                raise WordlistError(
                    "No compatible candidates remained after filtering. Check the "
                    f"{min_length}–{max_length} length policy and the selected files."
                )
            candidate_count = connection.execute(
                "SELECT COUNT(*) FROM candidates"
            ).fetchone()[0]
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            fingerprint = hashlib.sha256(
                ("|".join(str(item["sha256"]) for item in records) + str(time.time())).encode()
            ).hexdigest()[:8]
            destination = prepared_dir / f"surge-prepared-{timestamp}-{fingerprint}.txt"
            digest = hashlib.sha256()
            written = 0
            with destination.open("wb") as output:
                for (value,) in connection.execute(
                    "SELECT value FROM candidates ORDER BY id"
                ):
                    data = (value + "\n").encode("utf-8")
                    output.write(data)
                    digest.update(data)
                    written += 1
            size = destination.stat().st_size
            source_names = [item["name"] for item in records]
            description = (
                f"Merged from {len(records)} list(s): {', '.join(source_names[:5])}"
                + (" …" if len(source_names) > 5 else "")
                + f"; length {min_length}–{max_length}; {invalid} invalid, "
                f"{filtered} length-filtered, {scanned} scanned."
            )
            wordlist_id = self.db.add_wordlist(
                name=destination.name,
                path=str(destination.resolve()),
                description=description,
                line_count=written,
                sha256=digest.hexdigest(),
                size_bytes=size,
                category="prepared",
                source="prepared",
                priority=0,
                min_length=min_length,
                max_length=max_length,
                is_prepared=True,
                generated_from=json.dumps(source_names),
            )
            keep = self.settings.get_int("wordlist_prune_keep", 10)
            if keep > 0:
                self.db.prune_prepared_wordlists(keep=keep)
            self.db.log(
                "wordlist.prepared",
                f"Prepared {written:,} deduplicated candidate(s) from "
                f"{len(records)} list(s); scanned={scanned:,}; truncated={truncated}.",
            )
            return PreparedWordlist(
                id=wordlist_id,
                path=str(destination.resolve()),
                candidate_count=written,
                scanned_count=scanned,
                source_lists=source_names,
                truncated=truncated,
                size_bytes=size,
                sha256=digest.hexdigest(),
                min_length=min_length,
                max_length=max_length,
            )
        finally:
            connection.close()
            stage_path.unlink(missing_ok=True)

    @staticmethod
    def _insert_batch(
        connection: sqlite3.Connection,
        batch: list[tuple[bytes, str, str]],
        remaining: int,
    ) -> int:
        if remaining <= 0:
            return 0
        subset = batch[:remaining]
        before = connection.total_changes
        connection.executemany(
            "INSERT OR IGNORE INTO candidates(digest, value, source) VALUES (?, ?, ?)",
            subset,
        )
        connection.commit()
        return connection.total_changes - before

    def preview_selection(self, wordlist_ids: list[int], min_length: int, max_length: int) -> dict[str, Any]:
        records = [self.get(wordlist_id) for wordlist_id in wordlist_ids]
        estimated = sum(int(item.get("line_count") or 0) for item in records)
        compatible = sum(
            int(item.get("line_count") or 0)
            for item in records
            if not item.get("max_length")
            or int(item["max_length"]) >= min_length
        )
        return {
            "lists": len(records),
            "estimated_lines": estimated,
            "possibly_compatible": compatible,
            "min_length": min_length,
            "max_length": max_length,
        }


def _size_label(size: int) -> str:
    if size >= 1024**3:
        return f"{size / 1024**3:.1f} GB"
    if size >= 1024**2:
        return f"{size / 1024**2:.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def catalog_json() -> str:
    return json.dumps(
        [
            {
                "id": entry.id,
                "name": entry.name,
                "category": entry.category,
                "description": entry.description,
                "source_url": entry.source_url,
                "license": entry.license_note,
                "approximate_size": entry.approximate_size,
            }
            for entry in CATALOG
        ],
        indent=2,
    )

