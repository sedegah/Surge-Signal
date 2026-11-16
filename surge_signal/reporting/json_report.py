"""Structured JSON report for integration and archival."""

from __future__ import annotations

import json
from typing import Any

from ..core.branding import APP_NAME, APP_VERSION
from .model import ReportContext, executive_summary, report_metadata


def build_json(context: ReportContext) -> dict[str, Any]:
    assessment = context.assessment
    return {
        "schema": "surge-signal.report.v1",
        "product": {"name": APP_NAME, "version": APP_VERSION},
        "report": {
            **report_metadata(context),
            "summary": executive_summary(context),
            "classification": "Authorised security assessment",
            "limitations": [
                "Wireless beacon metadata describes advertised configuration, not exploitability.",
                "Active disruptive testing is excluded from this release.",
                "Absence of findings is not proof that the environment is secure.",
            ],
        },
        "assessment": {
            "id": assessment.id,
            "name": assessment.name,
            "organisation": assessment.organisation,
            "scope": assessment.scope,
            "permitted_targets": assessment.permitted_targets,
            "tester": assessment.tester,
            "status": assessment.status.value,
            "start_date": assessment.start_date,
            "end_date": assessment.end_date,
            "notes": assessment.notes,
            "created_at": assessment.created_at,
            "updated_at": assessment.updated_at,
        },
        "severity_counts": context.counts,
        "risk_classification": {
            "verified": context.verified_count,
            "potential": context.potential_count,
            "observation": context.observation_count,
            "highest_severity": context.highest_severity,
        },
        "networks": [
            {
                "bssid": item.bssid,
                "ssid": item.ssid,
                "hidden": item.hidden,
                "signal_dbm": item.signal_dbm,
                "signal_percent": item.signal_percent,
                "channel": item.channel,
                "band": item.band,
                "standards": item.standards,
                "authentication": item.authentication,
                "encryption": item.encryption,
                "pmf": item.pmf,
                "wps": item.wps,
                "source": item.source,
                "first_seen": item.first_seen,
                "last_seen": item.last_seen,
            }
            for item in context.networks
        ],
        "findings": [
            {
                "reference": f"F-{index:02d}",
                "rule_id": item.rule_id,
                "title": item.title,
                "severity": item.severity.value,
                "status": item.status.value,
                "confidence": item.confidence,
                "category": item.category,
                "ssid": item.ssid,
                "bssid": item.bssid,
                "explanation": item.explanation,
                "impact": item.impact,
                "remediation": item.remediation,
                "evidence": item.evidence,
                "created_at": item.created_at,
            }
            for index, item in enumerate(context.sorted_findings(), start=1)
        ],
        "captures": [
            {
                "filename": item.filename,
                "format": item.format,
                "size_bytes": item.size_bytes,
                "sha256": item.sha256,
                "packet_count": item.packet_count,
                "start_ts": item.start_ts,
                "end_ts": item.end_ts,
                "bssid": item.bssid,
                "ssid": item.ssid,
                "link_type": item.link_type,
                "integrity": item.integrity,
                "handshakes": item.metadata.get("handshakes", []),
                "imported_at": item.imported_at,
            }
            for item in context.captures
        ],
        "evidence": [
            {
                "label": item.label,
                "kind": item.kind,
                "sha256": item.sha256,
                "notes": item.notes,
                "added_at": item.added_at,
            }
            for item in context.evidence
        ],
        "password_audits": [
            {
                "method": item.get("method", ""),
                "status": item.get("status", ""),
                "candidates_tested": item.get("candidates_tested", 0),
                "recovered": bool(item.get("recovered")),
                "masked_secret": item.get("masked_secret", ""),
                "elapsed_seconds": item.get("elapsed_seconds", 0),
                "engine": item.get("engine", ""),
                "detail": item.get("detail", ""),
                "started_at": item.get("started_at", ""),
            }
            for item in context.audits
        ],
        "audit_trail": [
            {
                "timestamp": item.timestamp,
                "action": item.action,
                "detail": item.detail,
                "actor": item.actor,
            }
            for item in context.audit_events
        ],
        "conclusion": (
            f"Recorded {len(context.networks)} networks and {len(context.findings)} findings. "
            f"Highest severity: {context.highest_severity}."
        ),
    }


def render_json(context: ReportContext) -> str:
    return json.dumps(build_json(context), indent=2, ensure_ascii=False)


