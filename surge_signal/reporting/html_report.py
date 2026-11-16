"""Self-contained professional HTML report."""

from __future__ import annotations

import base64
import html
from pathlib import Path

from ..core.branding import APP_NAME, APP_VERSION
from ..core.assets import banner_path
from ..core.domain import FindingStatus, human_time, severity_counts
from .model import ReportContext, executive_summary, report_metadata

SEVERITY_COLOURS = {
    "critical": "#b3132f",
    "high": "#c2410c",
    "medium": "#9a6700",
    "low": "#0369a1",
    "info": "#475569",
}

STATUS_LABELS = {
    "verified": "Verified",
    "potential": "Potential risk",
    "observation": "Observation",
}


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _banner_uri() -> str:
    path = banner_path()
    try:
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    except OSError:
        return ""
    return f"data:image/jpeg;base64,{encoded}"


def _severity_badge(severity: str) -> str:
    colour = SEVERITY_COLOURS.get(severity, "#475569")
    return (
        f'<span class="badge" style="background:{colour}">'
        f"{_esc(severity.upper())}</span>"
    )


def _status_badge(status: str) -> str:
    css = {"verified": "verified", "potential": "potential", "observation": "observation"}.get(
        status, "observation"
    )
    return f'<span class="status {css}">{_esc(STATUS_LABELS.get(status, status))}</span>'


def render_html(context: ReportContext) -> str:
    assessment = context.assessment
    counts = context.counts
    meta = report_metadata(context)
    summary = executive_summary(context)
    banner_uri = _banner_uri()
    networks = sorted(context.networks, key=lambda n: (-(n.signal_dbm or -999), n.ssid))
    findings = context.sorted_findings()

    network_rows = "".join(
        f"""<tr>
          <td class="mono">{_esc(n.bssid)}</td>
          <td>{_esc(n.display_ssid)}</td>
          <td>{_esc(n.signal_dbm if n.signal_dbm is not None else "—")}</td>
          <td>{_esc(n.channel or "—")}</td>
          <td>{_esc(n.band)}</td>
          <td>{_esc(n.standards or "—")}</td>
          <td>{_esc(n.authentication or "—")}</td>
          <td>{_esc(n.encryption or "—")}</td>
          <td>{_esc(n.pmf)}</td>
          <td><span class="source">{_esc(n.source)}</span></td>
        </tr>"""
        for n in networks
    ) or '<tr><td colspan="10" class="empty">No wireless networks have been recorded.</td></tr>'

    findings_html = []
    for index, finding in enumerate(findings, start=1):
        network = context.finding_for(finding)
        findings_html.append(
            f"""<section class="finding">
              <div class="finding-head">
                <div>
                  <span class="finding-no">F-{index:02d}</span>
                  <h3>{_esc(finding.title)}</h3>
                </div>
                <div class="badges">{_severity_badge(finding.severity.value)}{_status_badge(finding.status.value)}</div>
              </div>
              <div class="meta-grid">
                <div><span>Rule</span><strong class="mono">{_esc(finding.rule_id)}</strong></div>
                <div><span>Category</span><strong>{_esc(finding.category)}</strong></div>
                <div><span>Confidence</span><strong>{_esc(finding.confidence)}</strong></div>
                <div><span>Affected network</span><strong>{_esc(finding.ssid or "—")}<br><small class="mono">{_esc(finding.bssid or "—")}</small></strong></div>
              </div>
              <h4>Technical explanation</h4><p>{_esc(finding.explanation)}</p>
              <h4>Potential security implications</h4><p>{_esc(finding.impact)}</p>
              <h4>Recommended remediation</h4><p>{_esc(finding.remediation)}</p>
              <p class="evidence"><strong>Evidence:</strong> {_esc(finding.evidence)}</p>
              {f'<p class="context">Discovery source: {_esc(network.source)} · channel {_esc(network.channel or "—")} · {_esc(network.band)}</p>' if network else ''}
            </section>"""
        )
    findings_block = "".join(findings_html) or (
        '<p class="empty-panel">No findings were recorded for this assessment.</p>'
    )

    evidence_rows = "".join(
        f"""<tr><td>{_esc(item.label)}</td><td>{_esc(item.kind)}</td>
        <td class="mono small">{_esc(item.sha256 or "—")}</td>
        <td>{_esc(human_time(item.added_at))}</td>
        <td class="small">{_esc(item.notes)}</td></tr>"""
        for item in context.evidence
    ) or '<tr><td colspan="5" class="empty">No evidence attachments were registered.</td></tr>'

    audit_rows = "".join(
        f"""<tr><td>{_esc(item.get("method", ""))}</td><td>{_esc(item.get("status", ""))}</td>
        <td>{_esc(item.get("candidates_tested", 0))}</td>
        <td>{"Match (masked)" if item.get("recovered") else "No match"}</td>
        <td class="mono">{_esc(item.get("masked_secret") or "—")}</td>
        <td class="small">{_esc(item.get("detail", ""))}</td></tr>"""
        for item in context.audits
    ) or '<tr><td colspan="6" class="empty">No password audits were recorded.</td></tr>'

    target_items = "".join(
        f"<li><span class=\"mono\">{_esc(target)}</span></li>"
        for target in assessment.permitted_targets
        if target.strip()
    ) or "<li>No permitted targets were recorded. Active or offline auditing is blocked.</li>"

    scope_note = (
        "Only targets explicitly listed above are in scope. The platform will refuse "
        "offline password auditing when the capture BSSID is not listed."
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(APP_NAME)} Report — {_esc(assessment.name)}</title>
<style>
  :root {{ --ink:#111827; --muted:#64748b; --line:#e2e8f0; --accent:#e8590c; --navy:#0b1324; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font-family:"Segoe UI",Arial,sans-serif; color:var(--ink); background:#eef2f7; font-size:11pt; line-height:1.55; }}
  .page {{ max-width:1000px; margin:0 auto; background:#fff; }}
  .cover {{ background:linear-gradient(135deg,#080d18 0%,#0f2038 60%,#17324f 100%); color:#fff; padding:0; position:relative; overflow:hidden; }}
  .hero {{ width:100%; height:310px; object-fit:cover; object-position:center 38%; display:block; opacity:.96; }}
  .cover-body {{ padding:34px 64px 48px; position:relative; z-index:2; }}
  .cover:after {{ content:""; position:absolute; right:-100px; top:120px; width:420px; height:420px; border:1px solid rgba(255,255,255,.10); border-radius:50%; box-shadow:0 0 0 50px rgba(255,255,255,.025),0 0 0 110px rgba(255,255,255,.018); z-index:1; }}
  .brand {{ font-size:10px; letter-spacing:.24em; color:#ffb27a; font-weight:700; text-transform:uppercase; }}
  .cover h1 {{ font-size:38px; line-height:1.12; margin:28px 0 10px; max-width:720px; letter-spacing:-.5px; }}
  .cover .sub {{ color:#a9bad0; font-size:15px; margin-bottom:32px; }}
  .cover-grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:18px; border-top:1px solid rgba(255,255,255,.15); padding-top:24px; position:relative; z-index:2; }}
  .cover-grid span {{ display:block; color:#8ca3bf; font-size:9px; text-transform:uppercase; letter-spacing:.12em; margin-bottom:4px; }}
  .cover-grid strong {{ font-size:11px; color:#fff; font-weight:600; }}
  .classification {{ display:inline-block; margin-top:28px; border:1px solid #ff9b5c; color:#ffc7a5; padding:5px 10px; font-size:9px; letter-spacing:.14em; text-transform:uppercase; }}
  .content {{ padding:42px 64px 56px; }}
  h2 {{ font-size:20px; margin:36px 0 12px; color:#0f1d32; border-bottom:2px solid var(--accent); padding-bottom:7px; }}
  h2:first-child {{ margin-top:0; }}
  h3 {{ font-size:14px; margin:0; }}
  h4 {{ font-size:10px; text-transform:uppercase; letter-spacing:.09em; color:#64748b; margin:16px 0 4px; }}
  p {{ margin:8px 0; }}
  .summary-grid {{ display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin:18px 0; }}
  .stat {{ border:1px solid var(--line); border-radius:8px; padding:13px; background:#f8fafc; }}
  .stat .n {{ font-size:23px; font-weight:700; line-height:1; }}
  .stat .l {{ font-size:8px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); margin-top:6px; }}
  .stat.critical .n {{ color:#b3132f; }} .stat.high .n {{ color:#c2410c; }}
  .stat.medium .n {{ color:#9a6700; }} .stat.low .n {{ color:#0369a1; }}
  table {{ width:100%; border-collapse:collapse; margin:14px 0; font-size:9.2pt; }}
  th {{ background:#0f1d32; color:#fff; text-align:left; padding:8px 7px; font-size:8px; letter-spacing:.05em; text-transform:uppercase; }}
  td {{ padding:7px; border-bottom:1px solid var(--line); vertical-align:top; }}
  tr:nth-child(even) td {{ background:#f8fafc; }}
  .mono {{ font-family:Consolas,"Courier New",monospace; }}
  .small {{ font-size:8.4pt; }}
  .badge {{ color:#fff; padding:3px 7px; border-radius:4px; font-size:7.5px; font-weight:700; letter-spacing:.06em; }}
  .badges {{ display:flex; gap:6px; align-items:center; flex-wrap:wrap; }}
  .status {{ font-size:8px; padding:3px 7px; border-radius:10px; border:1px solid; white-space:nowrap; }}
  .status.verified {{ color:#166534; border-color:#86efac; background:#f0fdf4; }}
  .status.potential {{ color:#9a3412; border-color:#fdba74; background:#fff7ed; }}
  .status.observation {{ color:#475569; border-color:#cbd5e1; background:#f8fafc; }}
  .finding {{ border:1px solid var(--line); border-left:4px solid #94a3b8; border-radius:6px; padding:18px 20px; margin:16px 0; page-break-inside:avoid; }}
  .finding-head {{ display:flex; justify-content:space-between; gap:20px; align-items:flex-start; border-bottom:1px solid var(--line); padding-bottom:10px; }}
  .finding-no {{ color:var(--accent); font-size:9px; font-weight:700; letter-spacing:.12em; }}
  .meta-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:13px 0; }}
  .meta-grid span {{ display:block; color:var(--muted); font-size:8px; text-transform:uppercase; letter-spacing:.08em; }}
  .meta-grid strong {{ font-size:9pt; }}
  .evidence {{ background:#f8fafc; border-left:2px solid #cbd5e1; padding:8px 10px; font-size:9pt; }}
  .context {{ color:var(--muted); font-size:8.4pt; }}
  .note {{ background:#fff7ed; border:1px solid #fed7aa; color:#7c2d12; padding:12px 14px; border-radius:6px; font-size:9pt; }}
  .legend {{ display:flex; gap:18px; flex-wrap:wrap; font-size:8.6pt; color:var(--muted); margin:8px 0 18px; }}
  .empty, .empty-panel {{ color:var(--muted); text-align:center; padding:16px; }}
  .empty-panel {{ border:1px dashed #cbd5e1; border-radius:8px; }}
  ul {{ margin:7px 0 7px 20px; padding:0; }}
  .footer {{ border-top:1px solid var(--line); margin-top:36px; padding-top:12px; color:var(--muted); font-size:8pt; display:flex; justify-content:space-between; gap:16px; }}
  @media print {{
    body {{ background:#fff; font-size:9.6pt; }}
    .page {{ max-width:none; }}
    .cover {{ padding:46px 48px 36px; -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
    .content {{ padding:30px 48px; }}
    .cover {{ page-break-after:always; }}
    h2 {{ page-break-after:avoid; }}
    .finding, tr {{ page-break-inside:avoid; }}
  }}
</style>
</head>
<body>
<div class="page">
  <header class="cover">
    {f'<img class="hero" src="{banner_uri}" alt="SURGE Signal — Wireless Security Auditing and Assessment">' if banner_uri else ''}
    <div class="cover-body">
      <div class="brand">Authorised wireless security assessment</div>
      <h1>{_esc(assessment.name)}</h1>
      <div class="sub">{_esc(assessment.organisation or "Authorised assessment")}</div>
      <div class="cover-grid">
        <div><span>Assessment ID</span><strong class="mono">{_esc(assessment.id)}</strong></div>
        <div><span>Report ID</span><strong class="mono">{_esc(meta["report_id"])}</strong></div>
        <div><span>Generated</span><strong>{_esc(human_time(context.generated_at))}</strong></div>
        <div><span>Tester</span><strong>{_esc(assessment.tester or "Not recorded")}</strong></div>
        <div><span>Status</span><strong>{_esc(assessment.status.value.title())}</strong></div>
        <div><span>Product</span><strong>{_esc(APP_VERSION)}</strong></div>
      </div>
      <div class="classification">Authorised assessment · Confidential</div>
    </div>
  </header>
  <main class="content">
    <h2>1. Executive summary</h2>
    {"".join(f"<p>{_esc(paragraph)}</p>" for paragraph in summary)}
    <div class="summary-grid">
      <div class="stat critical"><div class="n">{counts["critical"]}</div><div class="l">Critical</div></div>
      <div class="stat high"><div class="n">{counts["high"]}</div><div class="l">High</div></div>
      <div class="stat medium"><div class="n">{counts["medium"]}</div><div class="l">Medium</div></div>
      <div class="stat low"><div class="n">{counts["low"]}</div><div class="l">Low</div></div>
      <div class="stat info"><div class="n">{counts["info"]}</div><div class="l">Info</div></div>
    </div>
    <p class="note"><strong>Interpretation.</strong> {context.verified_count} finding(s) are marked verified, {context.potential_count} are potential risks derived from observed configuration, and {context.observation_count} are observations. Wireless beacons reveal advertised configuration; they do not prove exploitability. Active disruptive testing is outside this release.</p>

    <h2>2. Assessment scope</h2>
    <table>
      <tr><th style="width:22%">Field</th><th>Value</th></tr>
      <tr><td>Assessment</td><td>{_esc(assessment.name)}</td></tr>
      <tr><td>Organisation / lab</td><td>{_esc(assessment.organisation or "Not recorded")}</td></tr>
      <tr><td>Assigned tester</td><td>{_esc(assessment.tester or "Not recorded")}</td></tr>
      <tr><td>Dates</td><td>{_esc(assessment.start_date or "—")} to {_esc(assessment.end_date or "in progress")}</td></tr>
      <tr><td>Scope statement</td><td>{_esc(assessment.scope or "No scope statement recorded.")}</td></tr>
    </table>
    <h3>Permitted targets</h3>
    <ul>{target_items}</ul>
    <p class="note">{_esc(scope_note)}</p>

    <h2>3. Methodology</h2>
    <p>{_esc(APP_NAME)} combines passive Windows wireless discovery, authorised capture import, native PCAP/PCAPNG inspection and controlled offline password verification. No deauthentication, rogue access point, injection or automated attack against nearby networks is performed by this release.</p>
    <ul>
      <li><strong>Discovery:</strong> Windows WLAN inventory and optional Kali research observations are recorded with their source and timestamps.</li>
      <li><strong>Inspection:</strong> advertised authentication, encryption, PMF, WPS and radio characteristics are evaluated against an explainable rule set.</li>
      <li><strong>Capture analysis:</strong> capture format, integrity, packet metadata, beacon security elements and complete WPA handshakes are identified.</li>
      <li><strong>Password auditing:</strong> only complete handshakes from explicitly permitted BSSIDs, with operator attestation, are checked against an approved wordlist. The result is masked and never stored as plaintext.</li>
      <li><strong>Evidence:</strong> files are hashed with SHA-256 and associated with the assessment record.</li>
    </ul>
    <div class="legend">
      <span><span class="status verified">Verified</span> Confirmed finding, reviewed by the assessor</span>
      <span><span class="status potential">Potential risk</span> Derived from observed configuration</span>
      <span><span class="status observation">Observation</span> Context, not a vulnerability</span>
    </div>

    <h2>4. Wireless network inventory</h2>
    <table>
      <thead><tr><th>BSSID</th><th>SSID</th><th>Signal</th><th>Ch.</th><th>Band</th><th>Standards</th><th>Authentication</th><th>Encryption</th><th>PMF</th><th>Source</th></tr></thead>
      <tbody>{network_rows}</tbody>
    </table>

    <h2>5. Security findings</h2>
    {findings_block}

    <h2>6. Evidence and captures</h2>
    <h3>Registered evidence</h3>
    <table><thead><tr><th>Label</th><th>Kind</th><th>SHA-256</th><th>Added</th><th>Notes</th></tr></thead><tbody>{evidence_rows}</tbody></table>
    <h3>Imported captures</h3>
    <table><thead><tr><th>File</th><th>Format</th><th>Packets</th><th>BSSID</th><th>SSID</th><th>Integrity</th><th>SHA-256</th></tr></thead>
    <tbody>{''.join(f'<tr><td>{_esc(c.filename)}</td><td>{_esc(c.format)}</td><td>{c.packet_count}</td><td class="mono">{_esc(c.bssid or "—")}</td><td>{_esc(c.ssid or "—")}</td><td>{_esc(c.integrity)}</td><td class="mono small">{_esc(c.sha256[:24])}…</td></tr>' for c in context.captures) or '<tr><td colspan="7" class="empty">No captures imported.</td></tr>'}</tbody></table>

    <h2>7. Controlled password audits</h2>
    <p>Audit results are shown for authorised laboratory captures only. Recovered values are masked; Surge Signal does not persist plaintext passphrases.</p>
    <table><thead><tr><th>Method</th><th>Status</th><th>Candidates</th><th>Result</th><th>Masked value</th><th>Detail</th></tr></thead><tbody>{audit_rows}</tbody></table>

    <h2>8. Risks and remediation priorities</h2>
    <p>Prioritise critical and high findings affecting confidentiality or network access, then address configuration weaknesses that increase the likelihood or impact of credential compromise. Recommendations are deliberately conservative where evidence is based on advertisement only.</p>
    <ul>
      <li>Retire open and WEP configurations; migrate to WPA3-Personal or WPA2-Personal with AES-CCMP.</li>
      <li>Disable WPS and TKIP unless an evidenced operational exception exists.</li>
      <li>Enable Protected Management Frames where client compatibility permits.</li>
      <li>Use long, unique WPA-Personal passphrases and rotate any credential exposed during testing.</li>
      <li>Re-test after remediation and attach the new evidence to this assessment.</li>
    </ul>

    <h2>9. Assessment conclusion</h2>
    <p>{_esc(assessment.name)} recorded {len(context.networks)} network(s), {len(context.findings)} finding(s), {len(context.captures)} capture(s) and {len(context.evidence)} evidence record(s). {_esc("The highest recorded severity is " + context.highest_severity.upper() + "." if context.total_findings else "No findings were recorded; confirm coverage before closing the assessment.")}</p>
    <p>The findings in this report are limited to the evidence available at generation time. They do not represent a guarantee that the wireless environment is free of vulnerabilities. Any credential recovered during an authorised offline audit should be handled as sensitive evidence and rotated after validation.</p>

    <div class="footer"><span>{_esc(APP_NAME)} {_esc(APP_VERSION)} · {_esc(meta["report_id"])}</span><span>Generated {_esc(human_time(context.generated_at))} · Authorised use only</span></div>
  </main>
</div>
</body>
</html>"""


