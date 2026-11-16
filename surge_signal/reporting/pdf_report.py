"""Professional PDF report generation with ReportLab."""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from ..core.branding import APP_NAME, APP_VERSION
from ..core.assets import banner_path
from ..core.domain import human_time
from .html_report import SEVERITY_COLOURS
from .model import ReportContext, executive_summary, report_metadata

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    from reportlab.pdfbase.pdfmetrics import stringWidth

    REPORTLAB_AVAILABLE = True
except ImportError:                                                          
    REPORTLAB_AVAILABLE = False


class ReportError(RuntimeError):
    pass


def _e(value: object) -> str:
    return escape("" if value is None else str(value))


class _Styles:
    def __init__(self) -> None:
        base = getSampleStyleSheet()
        self.body = ParagraphStyle(
            "Body",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9.2,
            leading=13.5,
            textColor=colors.HexColor("#1f2937"),
            spaceAfter=5,
        )
        self.small = ParagraphStyle(
            "Small",
            parent=self.body,
            fontSize=7.6,
            leading=10.5,
            textColor=colors.HexColor("#475569"),
        )
        self.tiny = ParagraphStyle(
            "Tiny",
            parent=self.body,
            fontSize=6.8,
            leading=8.7,
        )
        self.h1 = ParagraphStyle(
            "H1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=17,
            leading=21,
            textColor=colors.HexColor("#0f1d32"),
            spaceBefore=10,
            spaceAfter=6,
        )
        self.h2 = ParagraphStyle(
            "H2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#0f1d32"),
            spaceBefore=13,
            spaceAfter=5,
        )
        self.h3 = ParagraphStyle(
            "H3",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=9.4,
            leading=12,
            textColor=colors.HexColor("#111827"),
            spaceBefore=8,
            spaceAfter=3,
        )
        self.label = ParagraphStyle(
            "Label",
            parent=self.small,
            fontName="Helvetica-Bold",
            fontSize=6.8,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=1,
        )
        self.mono = ParagraphStyle(
            "Mono",
            parent=self.small,
            fontName="Courier",
            fontSize=6.8,
            leading=9,
        )


def _p(text: object, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_e(text).replace("\n", "<br/>"), style)


def _cover(canvas, doc, context: ReportContext) -> None:
    width, height = A4
    canvas.saveState()
    canvas.setFillColor(colors.HexColor("#080d18"))
    canvas.rect(0, 0, width, height, stroke=0, fill=1)
    banner = banner_path()
    if banner.is_file():
        try:
            canvas.drawImage(
                str(banner),
                20 * mm,
                height - 110 * mm,
                width=width - 40 * mm,
                height=95 * mm,
                preserveAspectRatio=True,
                anchor="n",
                mask="auto",
            )
        except Exception:
            pass
    canvas.setFillColor(colors.HexColor("#ff9b5c"))
    canvas.setLineWidth(2)
    canvas.line(20 * mm, height - 116 * mm, 48 * mm, height - 116 * mm)
    canvas.setFillColor(colors.HexColor("#ffc7a5"))
    canvas.setFont("Helvetica-Bold", 6.5)
    canvas.drawString(20 * mm, height - 122 * mm, "AUTHORISED ASSESSMENT  ·  CONFIDENTIAL")

    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 24)
    title = context.assessment.name
    lines: list[str] = []
    current = ""
    for word in title.split():
        candidate = f"{current} {word}".strip()
        if stringWidth(candidate, "Helvetica-Bold", 24) > width - 40 * mm:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    y = height - 138 * mm
    for line in lines[:3]:
        canvas.drawString(20 * mm, y, line)
        y -= 10.5 * mm
    canvas.setFillColor(colors.HexColor("#a9bad0"))
    canvas.setFont("Helvetica", 10.5)
    canvas.drawString(
        20 * mm,
        y - 3 * mm,
        context.assessment.organisation or "Authorised assessment",
    )

    meta = report_metadata(context)
    fields = [
        ("ASSESSMENT ID", context.assessment.id),
        ("REPORT ID", meta["report_id"]),
        ("GENERATED", human_time(context.generated_at)),
        ("TESTER", context.assessment.tester or "Not recorded"),
        ("STATUS", context.assessment.status.value.title()),
        ("PRODUCT", APP_VERSION),
    ]
    top = 68 * mm
    for index, (label, value) in enumerate(fields):
        column = index % 3
        row = index // 3
        xpos = 20 * mm + column * 58 * mm
        ypos = top - row * 22 * mm
        canvas.setFillColor(colors.HexColor("#8ca3bf"))
        canvas.setFont("Helvetica-Bold", 6.5)
        canvas.drawString(xpos, ypos, label)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(xpos, ypos - 4.5 * mm, str(value)[:44])

    canvas.setStrokeColor(colors.HexColor("#ff9b5c"))
    canvas.setLineWidth(0.8)
    canvas.rect(20 * mm, 20 * mm, 58 * mm, 7 * mm, stroke=1, fill=0)
    canvas.setFillColor(colors.HexColor("#ffc7a5"))
    canvas.setFont("Helvetica-Bold", 6.2)
    canvas.drawString(23 * mm, 22.8 * mm, "AUTHORISED USE ONLY")
    canvas.restoreState()


def _later_pages(canvas, doc, context: ReportContext) -> None:
    width, height = A4
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#e2e8f0"))
    canvas.setLineWidth(0.5)
    canvas.line(20 * mm, height - 15 * mm, width - 20 * mm, height - 15 * mm)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.setFont("Helvetica", 6.6)
    canvas.drawString(20 * mm, height - 12 * mm, f"{APP_NAME} · {context.assessment.name}")
    canvas.drawRightString(width - 20 * mm, height - 12 * mm, context.assessment.id)
    canvas.line(20 * mm, 14 * mm, width - 20 * mm, 14 * mm)
    canvas.setFont("Helvetica", 6.6)
    canvas.drawString(20 * mm, 9 * mm, f"{context.report_id} · Authorised use only")
    canvas.drawRightString(width - 20 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _table(data: list[list[object]], widths: list[float], *, header: bool = True) -> Table:
    table = Table(data, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f1d32")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 6.4),
        ]
        for row in range(1, len(data)):
            if row % 2 == 0:
                style.append(("BACKGROUND", (0, row), (-1, row), colors.HexColor("#f8fafc")))
    table.setStyle(TableStyle(style))
    return table


def _header_row(labels: list[str], styles: _Styles) -> list[Paragraph]:
    return [Paragraph(f"<b>{_e(label)}</b>", styles.tiny) for label in labels]


def write_pdf(context: ReportContext, output_path: Path) -> Path:
    if not REPORTLAB_AVAILABLE:
        raise ReportError(
            "ReportLab is not installed. Install the reporting dependencies to generate PDFs."
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    styles = _Styles()
    counts = context.counts
    meta = report_metadata(context)
    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=21 * mm,
        bottomMargin=19 * mm,
        title=f"{APP_NAME} — {context.assessment.name}",
        author=context.assessment.tester or APP_NAME,
        subject="Authorised wireless security assessment",
        creator=f"{APP_NAME} {APP_VERSION}",
    )
    story: list[object] = [PageBreak()]

    def heading(text: str) -> None:
        story.append(Paragraph(_e(text), styles.h1))
        story.append(HRFlowable(width="100%", thickness=1.4, color=colors.HexColor("#e8590c"), spaceAfter=7))

    heading("1. Executive summary")
    for paragraph in executive_summary(context):
        story.append(_p(paragraph, styles.body))
    summary_data = [
        _header_row(
            ["Critical", "High", "Medium", "Low", "Info", "Total"], styles
        ),
        [
            Paragraph(f"<b>{counts['critical']}</b>", styles.h3),
            Paragraph(f"<b>{counts['high']}</b>", styles.h3),
            Paragraph(f"<b>{counts['medium']}</b>", styles.h3),
            Paragraph(f"<b>{counts['low']}</b>", styles.h3),
            Paragraph(f"<b>{counts['info']}</b>", styles.h3),
            Paragraph(f"<b>{context.total_findings}</b>", styles.h3),
        ],
    ]
    summary = Table(summary_data, colWidths=[28 * mm] * 6)
    summary.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f1d32")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(Spacer(1, 3 * mm))
    story.append(summary)
    story.append(Spacer(1, 3 * mm))
    story.append(
        _p(
            f"Interpretation: {context.verified_count} finding(s) verified; "
            f"{context.potential_count} potential risk(s) derived from observed configuration; "
            f"{context.observation_count} observation(s). Beacon data proves advertised "
            "configuration, not exploitability. Active disruptive testing is outside this release.",
            styles.small,
        )
    )

    heading("2. Assessment scope")
    scope_rows = [
        _header_row(["Field", "Value"], styles),
        [_p("Assessment", styles.small), _p(context.assessment.name, styles.small)],
        [_p("Organisation / lab", styles.small), _p(context.assessment.organisation or "Not recorded", styles.small)],
        [_p("Assigned tester", styles.small), _p(context.assessment.tester or "Not recorded", styles.small)],
        [_p("Dates", styles.small), _p(f"{context.assessment.start_date or '—'} to {context.assessment.end_date or 'in progress'}", styles.small)],
        [_p("Scope statement", styles.small), _p(context.assessment.scope or "No scope statement recorded.", styles.small)],
    ]
    story.append(_table(scope_rows, [42 * mm, 128 * mm]))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph("Permitted targets", styles.h3))
    targets = [item for item in context.assessment.permitted_targets if item.strip()]
    if targets:
        for target in targets:
            story.append(Paragraph(f"• <font name='Courier' size='7.5'>{_e(target)}</font>", styles.body))
    else:
        story.append(_p("No permitted targets recorded. Active or offline auditing is blocked.", styles.body))
    story.append(
        _p(
            "Only targets explicitly listed are in scope. Offline password auditing is "
            "refused when the capture BSSID is not listed.",
            styles.small,
        )
    )

    heading("3. Methodology")
    story.append(
        _p(
            f"{APP_NAME} combines passive Windows discovery, authorised capture import, "
            "native PCAP/PCAPNG inspection and controlled offline password verification. "
            "No deauthentication, rogue access point, injection or automated attack against "
            "nearby networks is performed by this release.",
            styles.body,
        )
    )
    for bullet in (
        "Discovery: Windows WLAN inventory and optional Kali observations are stored with source and timestamps.",
        "Inspection: authentication, encryption, PMF, WPS and radio metadata are evaluated by an explainable rule set.",
        "Capture analysis: container integrity, packet metadata, beacon security elements and complete WPA handshakes are identified.",
        "Password auditing: only permitted BSSIDs with operator attestation; results are masked and never persisted as plaintext.",
        "Evidence: files are hashed with SHA-256 and associated with the assessment.",
    ):
        story.append(Paragraph(f"• {_e(bullet)}", styles.body))
    story.append(Spacer(1, 2 * mm))
    story.append(
        _p(
            "Status legend — Verified: confirmed and reviewed. Potential risk: derived from "
            "advertised configuration. Observation: contextual information, not a vulnerability.",
            styles.small,
        )
    )

    heading("4. Wireless network inventory")
    network_rows: list[list[object]] = [
        _header_row(["BSSID / SSID", "Signal", "Ch / band", "Authentication", "Encryption", "PMF", "Source"], styles)
    ]
    for network in sorted(context.networks, key=lambda n: (-(n.signal_dbm or -999), n.ssid)):
        network_rows.append(
            [
                Paragraph(
                    f"<font name='Courier' size='6.2'>{_e(network.bssid)}</font><br/>{_e(network.display_ssid)}",
                    styles.tiny,
                ),
                _p(f"{network.signal_dbm if network.signal_dbm is not None else '—'} dBm", styles.tiny),
                _p(f"{network.channel or '—'} / {network.band}", styles.tiny),
                _p(network.authentication or "—", styles.tiny),
                _p(network.encryption or "—", styles.tiny),
                _p(network.pmf, styles.tiny),
                _p(network.source, styles.tiny),
            ]
        )
    if not context.networks:
        network_rows.append([_p("No wireless networks recorded.", styles.small)] + [""] * 6)
    story.append(_table(network_rows, [40 * mm, 17 * mm, 22 * mm, 30 * mm, 22 * mm, 20 * mm, 19 * mm]))
    story.append(PageBreak())

    heading("5. Security findings")
    if not context.findings:
        story.append(_p("No findings were recorded for this assessment.", styles.body))
    for index, finding in enumerate(context.sorted_findings(), start=1):
        colour = SEVERITY_COLOURS.get(finding.severity.value, "#475569")
        badge = Table(
            [
                [
                    Paragraph(
                        f"<font color='white'><b>{_e(finding.severity.value.upper())}</b></font>",
                        styles.tiny,
                    ),
                    Paragraph(
                        f"<b>{_e(finding.status.value.title())}</b> · {_e(finding.confidence)} confidence",
                        styles.tiny,
                    ),
                ]
            ],
            colWidths=[24 * mm, 60 * mm],
        )
        badge.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), colors.HexColor(colour)),
                    ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#f1f5f9")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        block = [
            Paragraph(f"F-{index:02d}  {_e(finding.title)}", styles.h2),
            badge,
            Spacer(1, 2 * mm),
            _p(
                f"Rule {finding.rule_id} · {finding.category} · Affected: "
                f"{finding.ssid or '—'} ({finding.bssid or '—'})",
                styles.small,
            ),
        ]
        story.append(KeepTogether(block))
        story.append(Paragraph("Technical explanation", styles.h3))
        story.append(_p(finding.explanation, styles.body))
        story.append(Paragraph("Potential security implications", styles.h3))
        story.append(_p(finding.impact, styles.body))
        story.append(Paragraph("Recommended remediation", styles.h3))
        story.append(_p(finding.remediation, styles.body))
        story.append(_p(f"Evidence: {finding.evidence}", styles.small))
        story.append(HRFlowable(width="100%", thickness=0.4, color=colors.HexColor("#e2e8f0"), spaceBefore=4, spaceAfter=6))

    heading("6. Evidence and captures")
    story.append(Paragraph("Registered evidence", styles.h3))
    evidence_rows = [_header_row(["Label", "Kind", "SHA-256", "Added"], styles)]
    for item in context.evidence:
        evidence_rows.append(
            [
                _p(item.label, styles.tiny),
                _p(item.kind, styles.tiny),
                Paragraph(f"<font name='Courier' size='5.8'>{_e(item.sha256[:32])}…</font>", styles.tiny),
                _p(human_time(item.added_at), styles.tiny),
            ]
        )
    if not context.evidence:
        evidence_rows.append([_p("No evidence attachments registered.", styles.small), "", "", ""])
    story.append(_table(evidence_rows, [48 * mm, 25 * mm, 70 * mm, 27 * mm]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Imported captures", styles.h3))
    capture_rows = [_header_row(["File", "Format", "Packets", "BSSID / SSID", "Integrity"], styles)]
    for capture in context.captures:
        capture_rows.append(
            [
                _p(capture.filename, styles.tiny),
                _p(capture.format, styles.tiny),
                _p(capture.packet_count, styles.tiny),
                Paragraph(
                    f"<font name='Courier' size='6'>{_e(capture.bssid or '—')}</font><br/>{_e(capture.ssid or '—')}",
                    styles.tiny,
                ),
                _p(capture.integrity, styles.tiny),
            ]
        )
    if not context.captures:
        capture_rows.append([_p("No captures imported.", styles.small), "", "", "", ""])
    story.append(_table(capture_rows, [45 * mm, 20 * mm, 18 * mm, 60 * mm, 27 * mm]))

    heading("7. Controlled password audits")
    story.append(
        _p(
            "Audit results are restricted to authorised laboratory captures. Recovered "
            "values are masked; Surge Signal does not persist plaintext passphrases.",
            styles.small,
        )
    )
    audit_rows = [_header_row(["Method", "Status", "Candidates", "Result", "Detail"], styles)]
    for audit in context.audits:
        audit_rows.append(
            [
                _p(audit.get("method", ""), styles.tiny),
                _p(audit.get("status", ""), styles.tiny),
                _p(audit.get("candidates_tested", 0), styles.tiny),
                _p("Match (masked)" if audit.get("recovered") else "No match", styles.tiny),
                _p(audit.get("detail", ""), styles.tiny),
            ]
        )
    if not context.audits:
        audit_rows.append([_p("No password audits recorded.", styles.small), "", "", "", ""])
    story.append(_table(audit_rows, [34 * mm, 22 * mm, 22 * mm, 28 * mm, 64 * mm]))

    heading("8. Risks and remediation priorities")
    story.append(
        _p(
            "Prioritise critical and high findings affecting confidentiality or network "
            "access, then address configuration weaknesses that increase the likelihood "
            "or impact of credential compromise. Recommendations are conservative where "
            "evidence is advertisement-only.",
            styles.body,
        )
    )
    for bullet in (
        "Retire open and WEP configurations; migrate to WPA3-Personal or WPA2-Personal with AES-CCMP.",
        "Disable WPS and TKIP unless an evidenced operational exception exists.",
        "Enable Protected Management Frames where client compatibility permits.",
        "Use long, unique WPA-Personal passphrases and rotate any credential exposed during testing.",
        "Re-test after remediation and attach the new evidence to this assessment.",
    ):
        story.append(Paragraph(f"• {_e(bullet)}", styles.body))

    heading("9. Assessment conclusion")
    conclusion = (
        f"{context.assessment.name} recorded {len(context.networks)} network(s), "
        f"{len(context.findings)} finding(s), {len(context.captures)} capture(s) and "
        f"{len(context.evidence)} evidence record(s). "
    )
    if context.total_findings:
        conclusion += f"The highest recorded severity is {context.highest_severity.upper()}. "
    else:
        conclusion += (
            "No findings were recorded; confirm coverage before closing the assessment. "
        )
    story.append(_p(conclusion, styles.body))
    story.append(
        _p(
            "The findings are limited to the evidence available at generation time and do "
            "not guarantee that the wireless environment is free of vulnerabilities. Any "
            "credential recovered during an authorised offline audit must be handled as "
            "sensitive evidence and rotated after validation.",
            styles.body,
        )
    )
    story.append(Spacer(1, 8 * mm))
    story.append(
        _p(
            f"Report {meta['report_id']} · Generated {human_time(context.generated_at)} · "
            f"{APP_NAME} {APP_VERSION}",
            styles.small,
        )
    )

    document.build(
        story,
        onFirstPage=lambda canvas, doc: _cover(canvas, doc, context),
        onLaterPages=lambda canvas, doc: _later_pages(canvas, doc, context),
    )
    return output_path


