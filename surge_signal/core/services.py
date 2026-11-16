"""Application service layer.

This is the working execution layer of SURGE Signal. It performs discovery,
database writes, capture import and hashing, finding analysis, authorisation
checks, wordlist preparation, local password verification, Aircrack-ng execution
through the configured Kali transport, evidence registration and report
generation. Linux credentials and recovered passphrases are never stored here.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from ..wireless.captures import CaptureAnalysis, CaptureError, analyze_capture
from .config import AppPaths, Settings
from .db import Database, new_assessment_id
from .domain import (
    Assessment,
    AssessmentStatus,
    AuditStatus,
    Capture,
    Evidence,
    Finding,
    FindingStatus,
    NetworkObservation,
    PasswordAuditResult,
    iso_now,
    normalize_bssid,
    valid_bssid,
)
from ..wireless.hardware import HardwareReport, diagnose_adapters
from ..audit.password_audit import (
    LocalWpaAuditor,
    WordlistInfo,
    inspect_wordlist,
    parse_aircrack_output,
)
from ..reporting import GeneratedReport, ReportingEngine, ReportContext, collect_report_context
from ..audit.research import ResearchConnector, ResearchStatus, SudoAuthError
from .rules import analyze_network, analyze_networks
from .safety import (
    AuthorisationError,
    authorize_offline_audit,
    require_active_assessment,
    require_permitted_target,
)
from ..wireless.windows_wifi import DiscoveryResult, discover_networks
from ..audit.wordlists import (
    PreparedWordlist,
    ScanResult,
    WordlistManager,
    WordlistError,
)


class SurgeError(RuntimeError):
    pass


@dataclass(slots=True)
class ImportSummary:
    imported: int
    skipped: int
    networks: list[NetworkObservation]
    errors: list[str]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(name).name).strip("-")
    return cleaned[:120] or "capture.pcap"


class SurgeService:
    def __init__(
        self,
        db: Database,
        paths: AppPaths,
        settings: Settings,
        connector: ResearchConnector,
        logger: object | None = None,
    ):
        self.db = db
        self.paths = paths
        self.settings = settings
        self.connector = connector
        self.logger = logger
        self.reports = ReportingEngine(db, paths)
        self.wordlists = WordlistManager(db, paths, settings)

                                                                                 
    def create_assessment(
        self,
        name: str,
        organisation: str,
        scope: str,
        permitted_targets: Iterable[str],
        tester: str,
        status: AssessmentStatus = AssessmentStatus.DRAFT,
        start_date: str = "",
        end_date: str = "",
        notes: str = "",
    ) -> Assessment:
        if not name.strip():
            raise SurgeError("An assessment name is required.")
        targets = [item.strip() for item in permitted_targets if item.strip()]
        for target in targets:
            if ":" in target and not valid_bssid(target):
                raise SurgeError(f"'{target}' is not a valid BSSID target.")
        assessment = self.db.create_assessment(
            Assessment(
                id=new_assessment_id(),
                name=name.strip(),
                organisation=organisation.strip(),
                scope=scope.strip(),
                permitted_targets=targets,
                tester=tester.strip(),
                status=status,
                start_date=start_date,
                end_date=end_date,
                notes=notes.strip(),
            )
        )
        self.db.log(
            "assessment.created",
            f"Created assessment '{assessment.name}' for {organisation or 'unspecified organisation'}.",
            assessment_id=assessment.id,
        )
        return assessment

    def update_assessment(self, assessment: Assessment) -> None:
        if not assessment.name.strip():
            raise SurgeError("An assessment name is required.")
        for target in assessment.permitted_targets:
            if ":" in target and not valid_bssid(target):
                raise SurgeError(f"'{target}' is not a valid BSSID target.")
        self.db.update_assessment(assessment)
        self.db.log(
            "assessment.updated",
            f"Updated assessment metadata and scope ({assessment.target_count} target(s)).",
            assessment_id=assessment.id,
        )

    def set_assessment_status(self, assessment_id: str, status: AssessmentStatus) -> None:
        assessment = self.db.get_assessment(assessment_id)
        if not assessment:
            raise SurgeError("Assessment not found.")
        assessment.status = status
        if status is AssessmentStatus.COMPLETE and not assessment.end_date:
            assessment.end_date = iso_now()[:10]
        self.db.update_assessment(assessment)
        self.db.log(
            "assessment.status",
            f"Assessment status changed to {status.value}.",
            assessment_id=assessment_id,
        )

    def assessment(self, assessment_id: str) -> Assessment:
        result = self.db.get_assessment(assessment_id)
        if not result:
            raise SurgeError("Assessment not found.")
        return result

                                                                                  
    def scan_windows(self, assessment_id: str) -> DiscoveryResult:
        assessment = self.assessment(assessment_id)
        if assessment.status is AssessmentStatus.ARCHIVED:
            raise SurgeError("Archived assessments cannot be modified.")
        result = discover_networks()
        if result.networks:
            count = self.db.upsert_networks(assessment_id, result.networks)
            self.db.log(
                "discovery.windows",
                f"Windows discovery recorded {count} network observation(s).",
                assessment_id=assessment_id,
            )
        else:
            self.db.log(
                "discovery.windows.empty",
                "; ".join(result.warnings) or "No networks returned.",
                assessment_id=assessment_id,
            )
        return result

    def import_networks(
        self, assessment_id: str, path: Path | str, source: str = "import"
    ) -> ImportSummary:
        assessment = self.assessment(assessment_id)
        if assessment.status is AssessmentStatus.ARCHIVED:
            raise SurgeError("Archived assessments cannot be modified.")
        payload_path = Path(path)
        try:
            payload = json.loads(payload_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SurgeError(f"Network inventory could not be read: {exc}") from exc
        if isinstance(payload, dict):
            source = str(payload.get("source", source) or source)
            items = payload.get("networks", [])
        elif isinstance(payload, list):
            items = payload
        else:
            raise SurgeError("Inventory JSON must be an object or a list of networks.")
        imported: list[NetworkObservation] = []
        errors: list[str] = []
        skipped = 0
        for index, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                errors.append(f"Entry {index} is not an object.")
                continue
            try:
                network = self._network_from_dict(item, source)
            except (ValueError, TypeError) as exc:
                errors.append(f"Entry {index}: {exc}")
                continue
            if not valid_bssid(network.bssid):
                errors.append(f"Entry {index}: invalid BSSID '{network.bssid}'.")
                continue
            imported.append(network)
        if imported:
            self.db.upsert_networks(assessment_id, imported)
        skipped = max(0, len(items) - len(imported))
        self.db.log(
            "discovery.import",
            f"Imported {len(imported)} network(s) from {payload_path.name}; "
            f"{skipped} skipped, {len(errors)} error(s).",
            assessment_id=assessment_id,
        )
        return ImportSummary(
            imported=len(imported), skipped=skipped, networks=imported, errors=errors
        )

    @staticmethod
    def _network_from_dict(item: dict[str, Any], source: str) -> NetworkObservation:
        bssid = normalize_bssid(str(item.get("bssid", item.get("BSSID", ""))))
        if not bssid:
            raise ValueError("BSSID is required")
        ssid = str(item.get("ssid", item.get("SSID", "")) or "")
        channel = item.get("channel", item.get("Channel"))
        try:
            channel_int = int(channel) if channel not in (None, "", "—") else None
        except (TypeError, ValueError):
            channel_int = None
        signal = item.get("signal_dbm", item.get("signal", item.get("rssi")))
        try:
            signal_int = int(float(signal)) if signal not in (None, "", "—") else None
        except (TypeError, ValueError):
            signal_int = None
        authentication = str(
            item.get("authentication", item.get("auth", item.get("security", ""))) or ""
        )
        encryption = str(item.get("encryption", item.get("cipher", "")) or "")
        pmf = str(item.get("pmf", "Unknown") or "Unknown")
        wps = str(item.get("wps", "Unknown") or "Unknown")
        source_value = str(item.get("source", source) or source)
        if source_value not in {"windows", "kali", "import", "lab", "demo"}:
            source_value = source
        return NetworkObservation(
            ssid=ssid,
            bssid=bssid,
            signal_dbm=signal_int,
            signal_percent=item.get("signal_percent") if isinstance(item.get("signal_percent"), int) else None,
            channel=channel_int,
            band=str(item.get("band", "") or ""),
            standards=str(item.get("standards", item.get("radio_type", "")) or ""),
            authentication=authentication,
            encryption=encryption,
            pmf=pmf,
            wps=wps,
            hidden=bool(item.get("hidden", not ssid)),
            source=source_value,
            first_seen=str(item.get("first_seen", iso_now()) or iso_now()),
            last_seen=str(item.get("last_seen", iso_now()) or iso_now()),
            raw={"imported_from": source, "original": item},
        )

                                                                                  
    def inspect_assessment(self, assessment_id: str, network_id: int | None = None) -> list[Finding]:
        assessment = self.assessment(assessment_id)
        if assessment.status is AssessmentStatus.ARCHIVED:
            raise SurgeError("Archived assessments cannot be modified.")
        networks = (
            [self.db.get_network(network_id)]
            if network_id is not None
            else self.db.list_networks(assessment_id)
        )
        networks = [item for item in networks if item is not None]
        if not networks:
            raise SurgeError("No wireless networks are available to inspect.")
        if network_id is not None:
            self.db.clear_findings(assessment_id, network_id)
            findings = analyze_network(networks[0])
            self.db.add_findings(assessment_id, findings)
        else:
            self.db.clear_findings(assessment_id)
            findings = analyze_networks(networks)                          
            self.db.add_findings(assessment_id, findings)
        self.db.log(
            "inspection.completed",
            f"Analysed {len(networks)} network(s); recorded {len(findings)} finding(s).",
            assessment_id=assessment_id,
        )
        return findings

    def set_finding_status(self, finding_id: int, status: FindingStatus) -> None:
        with self.db.transaction() as conn:
            row = conn.execute("SELECT assessment_id FROM findings WHERE id=?", (finding_id,)).fetchone()
            if not row:
                raise SurgeError("Finding not found.")
            conn.execute("UPDATE findings SET status=? WHERE id=?", (status.value, finding_id))
        self.db.log(
            "finding.reviewed",
            f"Finding {finding_id} marked {status.value}.",
            assessment_id=row["assessment_id"],
        )

                                                                                   
    def diagnose_hardware(self) -> HardwareReport:
        report = diagnose_adapters()
        self.db.log(
            "hardware.diagnosed",
            f"Adapter readiness: {report.readiness}; {len(report.adapters)} adapter(s).",
        )
        return report

    def research_status(self) -> ResearchStatus:
        return self.connector.test_connection()

    def privileged_interface_diagnostics(self, password: str):
        """Read-only interface inventory via sudo; password is stdin-only."""
        if not password:
            raise SudoAuthError("A Linux password is required.")
        result = self.connector.run_privileged(["iw", "dev"], password)
        self.db.log(
            "research.privileged_diagnostics",
            f"Privileged interface diagnostics completed with exit code {result.returncode}.",
        )
        return result

                                                                                   
    def import_capture(
        self,
        assessment_id: str,
        source_path: Path | str,
        *,
        notes: str = "",
    ) -> Capture:
        assessment = self.assessment(assessment_id)
        if assessment.status is AssessmentStatus.ARCHIVED:
            raise SurgeError("Archived assessments cannot be modified.")
        source = Path(source_path)
        if not source.is_file():
            raise SurgeError(f"Capture file not found: {source}")
        try:
            analysis = analyze_capture(source)
        except CaptureError as exc:
            raise SurgeError(str(exc)) from exc
        capture_dir = self.paths.evidence / assessment_id / "captures"
        capture_dir.mkdir(parents=True, exist_ok=True)
        digest_prefix = analysis.sha256[:12]
        destination = capture_dir / f"{digest_prefix}-{_safe_filename(source.name)}"
        if destination.exists():
            destination = capture_dir / f"{digest_prefix}-{source.stem}-{iso_now()[:10]}{source.suffix}"
        try:
            shutil.copy2(source, destination)
        except OSError as exc:
            raise SurgeError(f"Capture could not be copied into evidence storage: {exc}") from exc
        capture = Capture(
            filename=source.name,
            stored_path=str(destination),
            format=analysis.format,
            size_bytes=destination.stat().st_size,
            sha256=analysis.sha256,
            packet_count=analysis.packet_count,
            start_ts=analysis.start_ts,
            end_ts=analysis.end_ts,
            bssid=analysis.bssid,
            ssid=analysis.ssid,
            link_type=analysis.link_type_name,
            integrity=analysis.integrity,
            metadata=analysis.metadata(),
            status="analysed",
        )
        try:
            capture = self.db.add_capture(assessment_id, capture)
            self.db.add_evidence(
                assessment_id,
                Evidence(
                    label=f"Capture: {source.name}",
                    kind="capture",
                    path=str(destination),
                    sha256=analysis.sha256,
                    notes=notes or "Imported capture registered with integrity hash.",
                    capture_id=capture.id,
                ),
            )
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        self.db.log(
            "capture.imported",
            f"Imported {source.name} ({analysis.format.upper()}, "
            f"{analysis.packet_count} packets, integrity={analysis.integrity}).",
            assessment_id=assessment_id,
        )
        return capture

    def reanalyze_capture(self, capture_id: int) -> Capture:
        capture = self.db.get_capture(capture_id)
        if not capture:
            raise SurgeError("Capture not found.")
        path = Path(capture.stored_path)
        try:
            analysis = analyze_capture(path)
        except CaptureError as exc:
            raise SurgeError(str(exc)) from exc
        capture.packet_count = analysis.packet_count
        capture.start_ts = analysis.start_ts
        capture.end_ts = analysis.end_ts
        capture.bssid = analysis.bssid
        capture.ssid = analysis.ssid
        capture.link_type = analysis.link_type_name
        capture.integrity = analysis.integrity
        capture.metadata = analysis.metadata()
        self.db.update_capture_analysis(capture)
        self.db.log(
            "capture.analysed",
            f"Re-analysed {capture.filename}; integrity={analysis.integrity}.",
            assessment_id=capture.assessment_id or "",
        )
        return capture

    def export_capture(self, capture_id: int, destination: Path | str) -> Path:
        capture = self.db.get_capture(capture_id)
        if not capture:
            raise SurgeError("Capture not found.")
        source = Path(capture.stored_path)
        if not source.is_file():
            raise SurgeError("The stored capture file is missing.")
        target = Path(destination)
        if target.is_dir():
            target = target / capture.filename
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        self.db.log(
            "capture.exported",
            f"Exported capture {capture.filename} to {target.name}.",
            assessment_id=capture.assessment_id or "",
        )
        return target

                                                                                   
    def attach_evidence(
        self,
        assessment_id: str,
        source_path: Path | str,
        label: str,
        notes: str = "",
        kind: str = "file",
    ) -> Evidence:
        self.assessment(assessment_id)
        source = Path(source_path)
        if not source.is_file():
            raise SurgeError(f"Evidence file not found: {source}")
        destination_dir = self.paths.evidence / assessment_id / "attachments"
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination = destination_dir / f"{_safe_filename(source.name)}"
        if destination.exists():
            destination = destination_dir / f"{source.stem}-{iso_now()[:19].replace(':', '')}{source.suffix}"
        try:
            shutil.copy2(source, destination)
            digest = _sha256(destination)
        except OSError as exc:
            raise SurgeError(f"Evidence could not be stored: {exc}") from exc
        evidence = self.db.add_evidence(
            assessment_id,
            Evidence(
                label=label.strip() or source.name,
                kind=kind,
                path=str(destination),
                sha256=digest,
                notes=notes.strip(),
            ),
        )
        self.db.log(
            "evidence.attached",
            f"Attached evidence '{evidence.label}' (SHA-256 {digest[:16]}…).",
            assessment_id=assessment_id,
        )
        return evidence

    def remove_evidence(self, evidence_id: int) -> None:
        with self.db.transaction() as conn:
            row = conn.execute("SELECT assessment_id, label FROM evidence WHERE id=?", (evidence_id,)).fetchone()
            if not row:
                raise SurgeError("Evidence record not found.")
            conn.execute("DELETE FROM evidence WHERE id=?", (evidence_id,))
        self.db.log(
            "evidence.removed",
            f"Removed evidence record '{row['label']}'.",
            assessment_id=row["assessment_id"],
        )

                                                                                   
    def scan_wordlists(
        self, progress: Callable[[int, int, str], None] | None = None
    ) -> ScanResult:
        try:
            result = self.wordlists.scan_library(progress=progress)
        except WordlistError as exc:
            raise SurgeError(str(exc)) from exc
        self.db.log(
            "wordlist.scanned",
            f"Library scan registered {result.registered} list(s); "
            f"{result.skipped} skipped; {len(result.errors)} error(s).",
        )
        return result

    def import_wordlist(
        self,
        path: Path | str,
        category: str = "custom",
        description: str = "",
        name: str | None = None,
    ) -> dict[str, Any]:
        try:
            return self.wordlists.import_file(
                path, category, description=description, name=name
            )
        except WordlistError as exc:
            raise SurgeError(str(exc)) from exc

    def register_wordlist(self, path: Path | str, description: str = "") -> dict[str, Any]:
        return self.import_wordlist(path, "custom", description=description)

    def wordlist_records(self, include_prepared: bool = True) -> list[dict[str, Any]]:
        return self.wordlists.lists(include_prepared=include_prepared)

    def wordlist_catalog(self) -> list[dict[str, Any]]:
        return self.wordlists.catalog()

    def remove_wordlist(self, wordlist_id: int, delete_file: bool = False) -> None:
        try:
            self.wordlists.remove(wordlist_id, delete_file=delete_file)
        except WordlistError as exc:
            raise SurgeError(str(exc)) from exc

    def prepare_wordlist(
        self,
        wordlist_ids: list[int],
        *,
        min_length: int | None = None,
        max_length: int | None = None,
        max_candidates: int | None = None,
        progress: Callable[[int, int, int, str], None] | None = None,
        stop_event: threading.Event | None = None,
    ) -> PreparedWordlist:
        try:
            return self.wordlists.prepare(
                wordlist_ids,
                min_length=min_length
                if min_length is not None
                else self.settings.get_int("wordlist_include_min", 8),
                max_length=max_length
                if max_length is not None
                else self.settings.get_int("wordlist_include_max", 63),
                max_candidates=max_candidates
                or self.settings.get_int("wordlist_max_candidates", 1_000_000),
                progress=progress,
                stop_event=stop_event,
            )
        except WordlistError as exc:
            raise SurgeError(str(exc)) from exc

    def write_wordlist_index(self) -> Path:
        return self.wordlists.write_index()

                                                                                    
    def run_local_audit(
        self,
        assessment_id: str,
        capture_id: int,
        wordlist_path: Path | str,
        *,
        bssid: str = "",
        confirmed: bool = False,
        lab_attestation: bool = False,
        max_candidates: int | None = None,
        progress: Callable[[int, int], None] | None = None,
        stop_event: threading.Event | None = None,
    ) -> PasswordAuditResult:
        assessment = self.assessment(assessment_id)
        capture = self.db.get_capture(capture_id)
        if not capture:
            raise SurgeError("Capture not found.")
        target = normalize_bssid(bssid or capture.bssid)
        authorize_offline_audit(
            assessment,
            target,
            capture.ssid or "",
            confirmed=confirmed,
            lab_attestation=lab_attestation,
        )
        wordlist = Path(wordlist_path)
        if not wordlist.is_file():
            raise SurgeError(f"Wordlist file not found: {wordlist}")
        try:
            info = inspect_wordlist(wordlist)
        except (OSError, ValueError) as exc:
            raise SurgeError(str(exc)) from exc
        limit = max_candidates or self.settings.get_int("max_local_candidates", 250_000)
        auditor = LocalWpaAuditor(progress=progress, stop_event=stop_event)
        result = auditor.audit(
            capture.stored_path,
            wordlist,
            target,
            max_candidates=limit,
        )
        self._record_audit(assessment_id, capture_id, wordlist.name, result)
        return result

    def run_aircrack_audit(
        self,
        assessment_id: str,
        capture_id: int,
        wordlist_path: Path | str,
        *,
        bssid: str = "",
        confirmed: bool = False,
        lab_attestation: bool = False,
    ) -> PasswordAuditResult:
        assessment = self.assessment(assessment_id)
        capture = self.db.get_capture(capture_id)
        if not capture:
            raise SurgeError("Capture not found.")
        target = normalize_bssid(bssid or capture.bssid)
        authorize_offline_audit(
            assessment,
            target,
            capture.ssid or "",
            confirmed=confirmed,
            lab_attestation=lab_attestation,
        )
        wordlist = Path(wordlist_path)
        if not wordlist.is_file():
            raise SurgeError(f"Wordlist file not found: {wordlist}")
        try:
            command = self.connector.run_aircrack(
                wordlist, capture.stored_path, target, timeout=900
            )
        except Exception as exc:
            result = PasswordAuditResult(
                status=AuditStatus.FAILED,
                method="offline-wpa2",
                detail=str(exc),
                engine="aircrack-ng",
            )
            self._record_audit(assessment_id, capture_id, wordlist.name, result)
            return result
        recovered, masked, detail = parse_aircrack_output(command.stdout)
        result = PasswordAuditResult(
            status=AuditStatus.COMPLETED if command.ok else AuditStatus.FAILED,
            method="offline-wpa2",
            recovered=recovered,
            masked_secret=masked,
            elapsed_seconds=command.duration_seconds,
            detail=detail if command.ok else (command.stderr.strip() or "Aircrack-ng failed."),
            engine="aircrack-ng",
        )
        self._record_audit(assessment_id, capture_id, wordlist.name, result)
        return result

    def _record_audit(
        self,
        assessment_id: str,
        capture_id: int,
        wordlist_name: str,
        result: PasswordAuditResult,
    ) -> None:
        self.db.add_password_audit(
            assessment_id=assessment_id,
            capture_id=capture_id,
            method=result.method,
            status=result.status.value,
            wordlist_name=wordlist_name,
            candidates_tested=result.candidates_tested,
            recovered=result.recovered,
            matched_index=result.matched_index,
            masked_secret=result.masked_secret,
            elapsed_seconds=result.elapsed_seconds,
            detail=result.detail,
            engine=result.engine,
            strength_score=result.strength_score,
        )
        self.db.log(
            "password.audit",
            f"Offline audit via {result.engine}: {result.status.value}; "
            f"{result.candidates_tested} candidate(s); recovered={result.recovered}. "
            "No plaintext secret persisted.",
            assessment_id=assessment_id,
        )

    def record_kali_aircrack_result(
        self,
        assessment_id: str,
        capture_id: int,
        wordlist_name: str,
        result: PasswordAuditResult,
    ) -> None:
        """Persist a terminal Aircrack outcome after masking any recovered key."""
        self._record_audit(assessment_id, capture_id, wordlist_name, result)

                                                                                   
    def generate_reports(
        self, assessment_id: str, formats: list[str], output_dir: Path | None = None
    ) -> list[GeneratedReport]:
        return self.reports.generate(assessment_id, formats, output_dir)

    def report_context(self, assessment_id: str) -> ReportContext:
        return collect_report_context(self.db, assessment_id)

                                                                                    
    def dashboard(self) -> dict[str, Any]:
        stats = self.db.stats()
        assessments = self.db.list_assessments()
        recent_assessments = assessments[:5]
        recent_findings = self.db.recent_findings(6)
        last_id = self.settings.get("last_assessment_id", "")
        current = self.db.get_assessment(last_id) if last_id else None
        if current is None:
            current = assessments[0] if assessments else None
        return {
            "stats": stats,
            "assessments": recent_assessments,
            "findings": recent_findings,
            "current": current,
            "audit_events": self.db.list_audit_events(limit=8),
        }

    def set_current_assessment(self, assessment_id: str) -> None:
        self.settings.set("last_assessment_id", assessment_id)

    def integrity_check(self) -> tuple[bool, str]:
        return self.db.integrity_check()

