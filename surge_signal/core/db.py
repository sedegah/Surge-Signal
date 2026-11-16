"""SQLite persistence for Surge Signal.

The database is the local system of record for assessments, observations,
findings, evidence metadata, password-audit outcomes and the audit trail.
Recovered passwords and Linux credentials are intentionally never stored.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from .domain import (
    Assessment,
    AssessmentStatus,
    AuditEvent,
    Capture,
    Evidence,
    Finding,
    FindingStatus,
    NetworkObservation,
    Severity,
    coerce_severity,
    coerce_status,
    iso_now,
    normalize_bssid,
)

SCHEMA_VERSION = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    organisation TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT '',
    permitted_targets TEXT NOT NULL DEFAULT '[]',
    tester TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'draft',
    start_date TEXT NOT NULL DEFAULT '',
    end_date TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS networks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    ssid TEXT NOT NULL DEFAULT '',
    bssid TEXT NOT NULL DEFAULT '',
    signal_dbm INTEGER,
    signal_percent INTEGER,
    channel INTEGER,
    band TEXT NOT NULL DEFAULT 'Unknown',
    standards TEXT NOT NULL DEFAULT '',
    authentication TEXT NOT NULL DEFAULT '',
    encryption TEXT NOT NULL DEFAULT '',
    pmf TEXT NOT NULL DEFAULT 'Unknown',
    wps TEXT NOT NULL DEFAULT 'Unknown',
    hidden INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT 'windows',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    raw_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(assessment_id, bssid, source)
);

CREATE INDEX IF NOT EXISTS idx_networks_assessment
    ON networks(assessment_id, bssid);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    network_id INTEGER REFERENCES networks(id) ON DELETE SET NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    explanation TEXT NOT NULL DEFAULT '',
    impact TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'potential',
    confidence TEXT NOT NULL DEFAULT 'Medium',
    evidence TEXT NOT NULL DEFAULT '',
    bssid TEXT NOT NULL DEFAULT '',
    ssid TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_assessment
    ON findings(assessment_id, severity);

CREATE TABLE IF NOT EXISTS captures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'unknown',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL DEFAULT '',
    packet_count INTEGER NOT NULL DEFAULT 0,
    start_ts TEXT NOT NULL DEFAULT '',
    end_ts TEXT NOT NULL DEFAULT '',
    bssid TEXT NOT NULL DEFAULT '',
    ssid TEXT NOT NULL DEFAULT '',
    link_type TEXT NOT NULL DEFAULT '',
    integrity TEXT NOT NULL DEFAULT 'unknown',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    imported_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'imported'
);

CREATE INDEX IF NOT EXISTS idx_captures_assessment
    ON captures(assessment_id);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    capture_id INTEGER REFERENCES captures(id) ON DELETE SET NULL,
    label TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'file',
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    added_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_assessment
    ON evidence(assessment_id);

CREATE TABLE IF NOT EXISTS password_audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    capture_id INTEGER REFERENCES captures(id) ON DELETE SET NULL,
    method TEXT NOT NULL DEFAULT 'local',
    status TEXT NOT NULL DEFAULT 'queued',
    wordlist_name TEXT NOT NULL DEFAULT '',
    candidates_tested INTEGER NOT NULL DEFAULT 0,
    recovered INTEGER NOT NULL DEFAULT 0,
    matched_index INTEGER,
    masked_secret TEXT NOT NULL DEFAULT '',
    elapsed_seconds REAL NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT '',
    engine TEXT NOT NULL DEFAULT 'local',
    strength_score INTEGER,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audits_assessment
    ON password_audits(assessment_id, started_at);

CREATE TABLE IF NOT EXISTS wordlists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    approved INTEGER NOT NULL DEFAULT 1,
    line_count INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    added_at TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'custom',
    source TEXT NOT NULL DEFAULT 'imported',
    priority INTEGER NOT NULL DEFAULT 50,
    min_length INTEGER NOT NULL DEFAULT 0,
    max_length INTEGER NOT NULL DEFAULT 0,
    catalog_id TEXT NOT NULL DEFAULT '',
    is_prepared INTEGER NOT NULL DEFAULT 0,
    generated_from TEXT NOT NULL DEFAULT '',
    last_scanned TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_wordlists_category
    ON wordlists(category, priority);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    format TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL DEFAULT '',
    generated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id TEXT,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL DEFAULT 'operator',
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_assessment
    ON audit_log(assessment_id, timestamp);
"""


def new_assessment_id() -> str:
    year = datetime.now(timezone.utc).year
    suffix = uuid.uuid4().hex[:6].upper()
    return f"SS-{year}-{suffix}"


def _json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


class Database:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=20)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        with self.transaction() as conn:
            conn.executescript(SCHEMA)
            self._migrate(conn)
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('version', ?)",
                (str(SCHEMA_VERSION),),
            )

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Apply additive migrations for databases created by earlier builds."""
        existing = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(wordlists)").fetchall()
        }
        additions = {
            "line_count": "INTEGER NOT NULL DEFAULT 0",
            "sha256": "TEXT NOT NULL DEFAULT ''",
            "size_bytes": "INTEGER NOT NULL DEFAULT 0",
            "category": "TEXT NOT NULL DEFAULT 'custom'",
            "source": "TEXT NOT NULL DEFAULT 'imported'",
            "priority": "INTEGER NOT NULL DEFAULT 50",
            "min_length": "INTEGER NOT NULL DEFAULT 0",
            "max_length": "INTEGER NOT NULL DEFAULT 0",
            "catalog_id": "TEXT NOT NULL DEFAULT ''",
            "is_prepared": "INTEGER NOT NULL DEFAULT 0",
            "generated_from": "TEXT NOT NULL DEFAULT ''",
            "last_scanned": "TEXT NOT NULL DEFAULT ''",
        }
        for column, definition in additions.items():
            if column not in existing:
                conn.execute(f"ALTER TABLE wordlists ADD COLUMN {column} {definition}")

                                                                                 
    def get_setting(self, key: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_setting(self, key: str, value: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def all_settings(self) -> dict[str, str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {row["key"]: row["value"] for row in rows}

                                                                                 
    @staticmethod
    def _assessment_from_row(row: sqlite3.Row) -> Assessment:
        try:
            status = AssessmentStatus(row["status"])
        except ValueError:
            status = AssessmentStatus.DRAFT
        return Assessment(
            id=row["id"],
            name=row["name"],
            organisation=row["organisation"],
            scope=row["scope"],
            permitted_targets=_json_loads(row["permitted_targets"], []),
            tester=row["tester"],
            status=status,
            start_date=row["start_date"],
            end_date=row["end_date"],
            notes=row["notes"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def create_assessment(self, assessment: Assessment) -> Assessment:
        assessment.id = assessment.id or new_assessment_id()
        now = iso_now()
        assessment.created_at = assessment.created_at or now
        assessment.updated_at = now
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO assessments
                (id, name, organisation, scope, permitted_targets, tester, status,
                 start_date, end_date, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    assessment.id,
                    assessment.name.strip(),
                    assessment.organisation.strip(),
                    assessment.scope.strip(),
                    json.dumps(assessment.permitted_targets, ensure_ascii=False),
                    assessment.tester.strip(),
                    assessment.status.value,
                    assessment.start_date,
                    assessment.end_date,
                    assessment.notes,
                    assessment.created_at,
                    assessment.updated_at,
                ),
            )
        return assessment

    def update_assessment(self, assessment: Assessment) -> None:
        assessment.updated_at = iso_now()
        with self.transaction() as conn:
            conn.execute(
                """UPDATE assessments SET name=?, organisation=?, scope=?,
                permitted_targets=?, tester=?, status=?, start_date=?, end_date=?,
                notes=?, updated_at=? WHERE id=?""",
                (
                    assessment.name.strip(),
                    assessment.organisation.strip(),
                    assessment.scope.strip(),
                    json.dumps(assessment.permitted_targets, ensure_ascii=False),
                    assessment.tester.strip(),
                    assessment.status.value,
                    assessment.start_date,
                    assessment.end_date,
                    assessment.notes,
                    assessment.updated_at,
                    assessment.id,
                ),
            )

    def get_assessment(self, assessment_id: str) -> Assessment | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM assessments WHERE id=?", (assessment_id,)
            ).fetchone()
        return self._assessment_from_row(row) if row else None

    def list_assessments(self, include_archived: bool = False) -> list[Assessment]:
        sql = "SELECT * FROM assessments"
        params: tuple[Any, ...] = ()
        if not include_archived:
            sql += " WHERE status != ?"
            params = (AssessmentStatus.ARCHIVED.value,)
        sql += " ORDER BY updated_at DESC, created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._assessment_from_row(row) for row in rows]

    def delete_assessment(self, assessment_id: str) -> None:
        with self.transaction() as conn:
            conn.execute("DELETE FROM assessments WHERE id=?", (assessment_id,))

                                                                                   
    @staticmethod
    def _network_from_row(row: sqlite3.Row) -> NetworkObservation:
        return NetworkObservation(
            id=row["id"],
            assessment_id=row["assessment_id"],
            ssid=row["ssid"],
            bssid=row["bssid"],
            signal_dbm=row["signal_dbm"],
            signal_percent=row["signal_percent"],
            channel=row["channel"],
            band=row["band"],
            standards=row["standards"],
            authentication=row["authentication"],
            encryption=row["encryption"],
            pmf=row["pmf"],
            wps=row["wps"],
            hidden=bool(row["hidden"]),
            source=row["source"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            raw=_json_loads(row["raw_json"], {}),
        )

    def upsert_networks(
        self, assessment_id: str, networks: Iterable[NetworkObservation]
    ) -> int:
        changed = 0
        with self.transaction() as conn:
            for network in networks:
                bssid = normalize_bssid(network.bssid)
                existing = conn.execute(
                    """SELECT id, first_seen FROM networks
                    WHERE assessment_id=? AND bssid=? AND source=?""",
                    (assessment_id, bssid, network.source),
                ).fetchone()
                if existing:
                    conn.execute(
                        """UPDATE networks SET ssid=?, signal_dbm=?, signal_percent=?,
                        channel=?, band=?, standards=?, authentication=?, encryption=?,
                        pmf=?, wps=?, hidden=?, last_seen=?, raw_json=?
                        WHERE id=?""",
                        (
                            network.ssid,
                            network.signal_dbm,
                            network.signal_percent,
                            network.channel,
                            network.band,
                            network.standards,
                            network.authentication,
                            network.encryption,
                            network.pmf,
                            network.wps,
                            int(network.hidden),
                            network.last_seen or iso_now(),
                            json.dumps(network.raw, ensure_ascii=False),
                            existing["id"],
                        ),
                    )
                    network.id = existing["id"]
                else:
                    cursor = conn.execute(
                        """INSERT INTO networks
                        (assessment_id, ssid, bssid, signal_dbm, signal_percent, channel,
                         band, standards, authentication, encryption, pmf, wps, hidden,
                         source, first_seen, last_seen, raw_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            assessment_id,
                            network.ssid,
                            bssid,
                            network.signal_dbm,
                            network.signal_percent,
                            network.channel,
                            network.band,
                            network.standards,
                            network.authentication,
                            network.encryption,
                            network.pmf,
                            network.wps,
                            int(network.hidden),
                            network.source,
                            network.first_seen or iso_now(),
                            network.last_seen or iso_now(),
                            json.dumps(network.raw, ensure_ascii=False),
                        ),
                    )
                    network.id = int(cursor.lastrowid)
                changed += 1
        return changed

    def list_networks(
        self, assessment_id: str, search: str = "", source: str = ""
    ) -> list[NetworkObservation]:
        sql = "SELECT * FROM networks WHERE assessment_id=?"
        params: list[Any] = [assessment_id]
        if source:
            sql += " AND source=?"
            params.append(source)
        if search:
            sql += " AND (ssid LIKE ? OR bssid LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like])
        sql += " ORDER BY signal_dbm DESC, ssid COLLATE NOCASE, bssid"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._network_from_row(row) for row in rows]

    def get_network(self, network_id: int) -> NetworkObservation | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM networks WHERE id=?", (network_id,)).fetchone()
        return self._network_from_row(row) if row else None

    def network_count(self, assessment_id: str | None = None) -> int:
        with self._connect() as conn:
            if assessment_id:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM networks WHERE assessment_id=?",
                    (assessment_id,),
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) AS n FROM networks").fetchone()
        return int(row["n"])

                                                                                   
    @staticmethod
    def _finding_from_row(row: sqlite3.Row) -> Finding:
        return Finding(
            id=row["id"],
            assessment_id=row["assessment_id"],
            network_id=row["network_id"],
            rule_id=row["rule_id"],
            title=row["title"],
            severity=coerce_severity(row["severity"]),
            category=row["category"],
            explanation=row["explanation"],
            impact=row["impact"],
            remediation=row["remediation"],
            status=coerce_status(row["status"]),
            confidence=row["confidence"],
            evidence=row["evidence"],
            bssid=row["bssid"],
            ssid=row["ssid"],
            created_at=row["created_at"],
        )

    def add_finding(self, assessment_id: str, finding: Finding) -> int:
        with self.transaction() as conn:
            cursor = conn.execute(
                """INSERT INTO findings
                (assessment_id, network_id, rule_id, title, severity, category,
                 explanation, impact, remediation, status, confidence, evidence,
                 bssid, ssid, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    assessment_id,
                    finding.network_id,
                    finding.rule_id,
                    finding.title,
                    finding.severity.value,
                    finding.category,
                    finding.explanation,
                    finding.impact,
                    finding.remediation,
                    finding.status.value,
                    finding.confidence,
                    finding.evidence,
                    finding.bssid,
                    finding.ssid,
                    finding.created_at or iso_now(),
                ),
            )
            return int(cursor.lastrowid)

    def add_findings(self, assessment_id: str, findings: Iterable[Finding]) -> int:
        count = 0
        with self.transaction() as conn:
            for finding in findings:
                conn.execute(
                    """INSERT INTO findings
                    (assessment_id, network_id, rule_id, title, severity, category,
                     explanation, impact, remediation, status, confidence, evidence,
                     bssid, ssid, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        assessment_id,
                        finding.network_id,
                        finding.rule_id,
                        finding.title,
                        finding.severity.value,
                        finding.category,
                        finding.explanation,
                        finding.impact,
                        finding.remediation,
                        finding.status.value,
                        finding.confidence,
                        finding.evidence,
                        finding.bssid,
                        finding.ssid,
                        finding.created_at or iso_now(),
                    ),
                )
                count += 1
        return count

    def list_findings(
        self,
        assessment_id: str,
        severity: str = "",
        search: str = "",
    ) -> list[Finding]:
        sql = "SELECT * FROM findings WHERE assessment_id=?"
        params: list[Any] = [assessment_id]
        if severity:
            sql += " AND severity=?"
            params.append(severity)
        if search:
            sql += " AND (title LIKE ? OR ssid LIKE ? OR bssid LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like, like])
        sql += """ ORDER BY CASE severity
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
            WHEN 'low' THEN 3 ELSE 4 END, created_at DESC"""
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._finding_from_row(row) for row in rows]

    def clear_findings(self, assessment_id: str, network_id: int | None = None) -> None:
        with self.transaction() as conn:
            if network_id is None:
                conn.execute("DELETE FROM findings WHERE assessment_id=?", (assessment_id,))
            else:
                conn.execute(
                    "DELETE FROM findings WHERE assessment_id=? AND network_id=?",
                    (assessment_id, network_id),
                )

    def finding_counts(self, assessment_id: str | None = None) -> dict[str, int]:
        counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
        with self._connect() as conn:
            if assessment_id:
                rows = conn.execute(
                    "SELECT severity, COUNT(*) AS n FROM findings WHERE assessment_id=? GROUP BY severity",
                    (assessment_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
                ).fetchall()
        for row in rows:
            if row["severity"] in counts:
                counts[row["severity"]] = int(row["n"])
        return counts

                                                                                   
    @staticmethod
    def _capture_from_row(row: sqlite3.Row) -> Capture:
        return Capture(
            id=row["id"],
            assessment_id=row["assessment_id"],
            filename=row["filename"],
            stored_path=row["stored_path"],
            format=row["format"],
            size_bytes=row["size_bytes"],
            sha256=row["sha256"],
            packet_count=row["packet_count"],
            start_ts=row["start_ts"],
            end_ts=row["end_ts"],
            bssid=row["bssid"],
            ssid=row["ssid"],
            link_type=row["link_type"],
            integrity=row["integrity"],
            metadata=_json_loads(row["metadata_json"], {}),
            imported_at=row["imported_at"],
            status=row["status"],
        )

    def add_capture(self, assessment_id: str, capture: Capture) -> Capture:
        with self.transaction() as conn:
            cursor = conn.execute(
                """INSERT INTO captures
                (assessment_id, filename, stored_path, format, size_bytes, sha256,
                 packet_count, start_ts, end_ts, bssid, ssid, link_type, integrity,
                 metadata_json, imported_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    assessment_id,
                    capture.filename,
                    capture.stored_path,
                    capture.format,
                    capture.size_bytes,
                    capture.sha256,
                    capture.packet_count,
                    capture.start_ts,
                    capture.end_ts,
                    capture.bssid,
                    capture.ssid,
                    capture.link_type,
                    capture.integrity,
                    json.dumps(capture.metadata, ensure_ascii=False),
                    capture.imported_at or iso_now(),
                    capture.status,
                ),
            )
            capture.id = int(cursor.lastrowid)
            capture.assessment_id = assessment_id
        return capture

    def list_captures(self, assessment_id: str) -> list[Capture]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM captures WHERE assessment_id=? ORDER BY imported_at DESC",
                (assessment_id,),
            ).fetchall()
        return [self._capture_from_row(row) for row in rows]

    def get_capture(self, capture_id: int) -> Capture | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM captures WHERE id=?", (capture_id,)).fetchone()
        return self._capture_from_row(row) if row else None

    def update_capture_analysis(self, capture: Capture) -> None:
        with self.transaction() as conn:
            conn.execute(
                """UPDATE captures SET packet_count=?, start_ts=?, end_ts=?, bssid=?,
                ssid=?, link_type=?, integrity=?, metadata_json=?, status=? WHERE id=?""",
                (
                    capture.packet_count,
                    capture.start_ts,
                    capture.end_ts,
                    capture.bssid,
                    capture.ssid,
                    capture.link_type,
                    capture.integrity,
                    json.dumps(capture.metadata, ensure_ascii=False),
                    capture.status,
                    capture.id,
                ),
            )

    def delete_capture(self, capture_id: int) -> None:
        with self.transaction() as conn:
            conn.execute("DELETE FROM captures WHERE id=?", (capture_id,))

                                                                                   
    @staticmethod
    def _evidence_from_row(row: sqlite3.Row) -> Evidence:
        return Evidence(
            id=row["id"],
            assessment_id=row["assessment_id"],
            capture_id=row["capture_id"],
            label=row["label"],
            kind=row["kind"],
            path=row["path"],
            sha256=row["sha256"],
            notes=row["notes"],
            added_at=row["added_at"],
        )

    def add_evidence(self, assessment_id: str, evidence: Evidence) -> Evidence:
        with self.transaction() as conn:
            cursor = conn.execute(
                """INSERT INTO evidence
                (assessment_id, capture_id, label, kind, path, sha256, notes, added_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    assessment_id,
                    evidence.capture_id,
                    evidence.label,
                    evidence.kind,
                    evidence.path,
                    evidence.sha256,
                    evidence.notes,
                    evidence.added_at or iso_now(),
                ),
            )
            evidence.id = int(cursor.lastrowid)
            evidence.assessment_id = assessment_id
        return evidence

    def list_evidence(self, assessment_id: str) -> list[Evidence]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM evidence WHERE assessment_id=? ORDER BY added_at DESC",
                (assessment_id,),
            ).fetchall()
        return [self._evidence_from_row(row) for row in rows]

    def delete_evidence(self, evidence_id: int) -> None:
        with self.transaction() as conn:
            conn.execute("DELETE FROM evidence WHERE id=?", (evidence_id,))

                                                                                  
    def add_password_audit(
        self,
        assessment_id: str,
        capture_id: int | None,
        method: str,
        status: str,
        wordlist_name: str,
        candidates_tested: int,
        recovered: bool,
        matched_index: int | None,
        masked_secret: str,
        elapsed_seconds: float,
        detail: str,
        engine: str,
        strength_score: int | None,
    ) -> int:
        now = iso_now()
        with self.transaction() as conn:
            cursor = conn.execute(
                """INSERT INTO password_audits
                (assessment_id, capture_id, method, status, wordlist_name,
                 candidates_tested, recovered, matched_index, masked_secret,
                 elapsed_seconds, detail, engine, strength_score, started_at,
                 completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    assessment_id,
                    capture_id,
                    method,
                    status,
                    wordlist_name,
                    candidates_tested,
                    int(recovered),
                    matched_index,
                    masked_secret,
                    elapsed_seconds,
                    detail,
                    engine,
                    strength_score,
                    now,
                    now if status in {"completed", "failed", "cancelled"} else "",
                ),
            )
            return int(cursor.lastrowid)

    def list_password_audits(self, assessment_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM password_audits WHERE assessment_id=? ORDER BY started_at DESC",
                (assessment_id,),
            ).fetchall()
        return [dict(row) for row in rows]

                                                                                  
    def add_wordlist(
        self,
        name: str,
        path: str,
        description: str = "",
        line_count: int = 0,
        sha256: str = "",
        size_bytes: int = 0,
        approved: bool = True,
        category: str = "custom",
        source: str = "imported",
        priority: int = 50,
        min_length: int = 0,
        max_length: int = 0,
        catalog_id: str = "",
        is_prepared: bool = False,
        generated_from: str = "",
    ) -> int:
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO wordlists
                (name, path, description, approved, line_count, sha256, size_bytes,
                 added_at, category, source, priority, min_length, max_length, catalog_id,
                 is_prepared, generated_from, last_scanned)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET name=excluded.name,
                description=excluded.description, approved=excluded.approved,
                line_count=excluded.line_count, sha256=excluded.sha256,
                size_bytes=excluded.size_bytes,
                category=excluded.category, source=excluded.source,
                priority=excluded.priority, min_length=excluded.min_length,
                max_length=excluded.max_length, catalog_id=excluded.catalog_id,
                is_prepared=excluded.is_prepared, generated_from=excluded.generated_from,
                last_scanned=excluded.last_scanned""",
                (
                    name,
                    path,
                    description,
                    int(approved),
                    line_count,
                    sha256,
                    size_bytes,
                    iso_now(),
                    category,
                    source,
                    priority,
                    min_length,
                    max_length,
                    catalog_id,
                    int(is_prepared),
                    generated_from,
                    iso_now(),
                ),
            )
            row = conn.execute("SELECT id FROM wordlists WHERE path=?", (path,)).fetchone()
            return int(row["id"]) if row else 0

    def list_wordlists(
        self, *, include_prepared: bool = True, category: str = ""
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM wordlists WHERE 1=1"
        params: list[Any] = []
        if not include_prepared:
            sql += " AND is_prepared=0"
        if category:
            sql += " AND category=?"
            params.append(category)
        sql += " ORDER BY priority, category, name COLLATE NOCASE"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def get_wordlist(self, wordlist_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM wordlists WHERE id=?", (wordlist_id,)).fetchone()
        return dict(row) if row else None

    def remove_wordlist_record(self, wordlist_id: int, *, delete_file: bool = False) -> str | None:
        with self.transaction() as conn:
            row = conn.execute("SELECT path FROM wordlists WHERE id=?", (wordlist_id,)).fetchone()
            if not row:
                return None
            path = str(row["path"])
            conn.execute("DELETE FROM wordlists WHERE id=?", (wordlist_id,))
        if delete_file:
            Path(path).unlink(missing_ok=True)
        return path

    def prune_prepared_wordlists(self, keep: int = 10) -> list[str]:
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT id, path FROM wordlists WHERE is_prepared=1 ORDER BY added_at DESC"
            ).fetchall()
            stale = rows[keep:]
            for row in stale:
                conn.execute("DELETE FROM wordlists WHERE id=?", (row["id"],))
        removed: list[str] = []
        for row in stale:
            path = Path(row["path"])
            if path.exists():
                path.unlink(missing_ok=True)
                removed.append(str(path))
        return removed

                                                                                   
    def add_report(
        self, assessment_id: str, format_name: str, path: str, sha256: str
    ) -> int:
        with self.transaction() as conn:
            cursor = conn.execute(
                """INSERT INTO reports(assessment_id, format, path, sha256, generated_at)
                VALUES (?, ?, ?, ?, ?)""",
                (assessment_id, format_name, path, sha256, iso_now()),
            )
            return int(cursor.lastrowid)

    def list_reports(self, assessment_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM reports WHERE assessment_id=? ORDER BY generated_at DESC",
                (assessment_id,),
            ).fetchall()
        return [dict(row) for row in rows]

                                                                                  
    def log(
        self,
        action: str,
        detail: str = "",
        actor: str = "operator",
        assessment_id: str | None = None,
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO audit_log(assessment_id, action, detail, actor, timestamp)
                VALUES (?, ?, ?, ?, ?)""",
                (assessment_id, action, detail, actor, iso_now()),
            )

    def list_audit_events(
        self, assessment_id: str | None = None, limit: int = 200
    ) -> list[AuditEvent]:
        with self._connect() as conn:
            if assessment_id:
                rows = conn.execute(
                    "SELECT * FROM audit_log WHERE assessment_id=? ORDER BY id DESC LIMIT ?",
                    (assessment_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
        return [
            AuditEvent(
                id=row["id"],
                assessment_id=row["assessment_id"],
                action=row["action"],
                detail=row["detail"],
                actor=row["actor"],
                timestamp=row["timestamp"],
            )
            for row in rows
        ]

                                                                                   
    def stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            assessments = conn.execute(
                "SELECT COUNT(*) AS n FROM assessments WHERE status != 'archived'"
            ).fetchone()["n"]
            active = conn.execute(
                "SELECT COUNT(*) AS n FROM assessments WHERE status='active'"
            ).fetchone()["n"]
            networks = conn.execute("SELECT COUNT(*) AS n FROM networks").fetchone()["n"]
            captures = conn.execute("SELECT COUNT(*) AS n FROM captures").fetchone()["n"]
            audits = conn.execute(
                "SELECT COUNT(*) AS n FROM password_audits WHERE status='completed'"
            ).fetchone()["n"]
        findings = self.finding_counts()
        return {
            "assessments": int(assessments),
            "active_assessments": int(active),
            "networks": int(networks),
            "captures": int(captures),
            "audits": int(audits),
            "findings": findings,
            "total_findings": sum(findings.values()),
        }

    def recent_findings(self, limit: int = 8) -> list[Finding]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT * FROM findings ORDER BY
                CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [self._finding_from_row(row) for row in rows]

    def integrity_check(self) -> tuple[bool, str]:
        with self._connect() as conn:
            row = conn.execute("PRAGMA integrity_check").fetchone()
            foreign = conn.execute("PRAGMA foreign_key_check").fetchall()
        ok = bool(row and row[0] == "ok") and not foreign
        detail = "Database integrity check passed."
        if not ok:
            detail = f"Integrity result: {row[0] if row else 'unknown'}; foreign key issues: {len(foreign)}"
        return ok, detail

