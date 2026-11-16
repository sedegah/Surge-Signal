"""Report generation orchestration."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from ..core.config import AppPaths
from ..core.db import Database
from .html_report import render_html
from .json_report import render_json
from .model import ReportContext, collect_report_context
from .pdf_report import write_pdf


class ReportGenerationError(RuntimeError):
    pass


@dataclass(slots=True)
class GeneratedReport:
    format: str
    path: str
    sha256: str
    size_bytes: int


SUPPORTED_FORMATS = ("html", "pdf", "json")


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")
    return cleaned[:70] or "assessment"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


class ReportingEngine:
    def __init__(self, db: Database, paths: AppPaths):
        self.db = db
        self.paths = paths

    def generate(
        self, assessment_id: str, formats: list[str], output_dir: Path | None = None
    ) -> list[GeneratedReport]:
        formats = [fmt.lower() for fmt in formats]
        invalid = [fmt for fmt in formats if fmt not in SUPPORTED_FORMATS]
        if invalid:
            raise ReportGenerationError(f"Unsupported report format: {', '.join(invalid)}")
        if not formats:
            raise ReportGenerationError("Select at least one report format.")
        try:
            context = collect_report_context(self.db, assessment_id)
        except ValueError as exc:
            raise ReportGenerationError(str(exc)) from exc
        directory = output_dir or self.paths.reports
        directory.mkdir(parents=True, exist_ok=True)
        base = directory / f"{_slug(context.assessment.name)}-{context.assessment.id}-{context.report_id[-12:]}"
        generated: list[GeneratedReport] = []
        for fmt in formats:
            path = base.with_suffix(f".{fmt}")
            try:
                if fmt == "html":
                    path.write_text(render_html(context), encoding="utf-8")
                elif fmt == "json":
                    path.write_text(render_json(context), encoding="utf-8")
                elif fmt == "pdf":
                    write_pdf(context, path)
            except Exception as exc:
                raise ReportGenerationError(
                    f"The {fmt.upper()} report could not be generated: {exc}"
                ) from exc
            if not path.exists() or path.stat().st_size == 0:
                raise ReportGenerationError(f"The {fmt.upper()} report was not written.")
            item = GeneratedReport(
                format=fmt,
                path=str(path),
                sha256=_sha256(path),
                size_bytes=path.stat().st_size,
            )
            self.db.add_report(context.assessment.id, fmt, item.path, item.sha256)
            generated.append(item)
        self.db.log(
            "report.generated",
            f"Generated {', '.join(fmt.upper() for fmt in formats)} report(s) for "
            f"{context.assessment.name}.",
            assessment_id=context.assessment.id,
        )
        return generated

