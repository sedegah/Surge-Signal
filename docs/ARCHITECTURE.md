# Architecture

## Overview

SURGE Signal is a Python/PySide6 desktop application with a local SQLite repository
and a narrow research connector. The GUI never shells out for ordinary operations.
Analysis, persistence and reporting are separate modules with typed domain objects.

```text
PySide6 UI (ui/)
  |-- MainWindow + navigation
  |-- Dashboard / Scanner / Inspector / Hardware
  |-- Captures / Auditor / Wordlists / Assessments / Reports / Settings
  |-- TaskRunner -> QThreadPool (UI stays responsive)

Application service layer (core/services.py)
  |-- executes discovery and persists observations
  |-- imports, hashes and analyses captures
  |-- enforces authorisation and scope policy
  |-- prepares wordlists and runs password audits
  |-- invokes Aircrack-ng through the selected Kali transport
  |-- generates reports

Core (core/)
  |-- db.py             SQLite repository
  |-- domain.py         models, enums, validation
  |-- rules.py          explainable Wi-Fi rules
  |-- safety.py         scope gates + command allow-list
  |-- security_fs.py    Windows ACL hardening
  |-- config.py         paths and settings
  |-- branding.py       product identity

Wireless (wireless/)
  |-- windows_wifi.py   Windows netsh + Linux nmcli discovery
  |-- hardware.py       host/adapter capability matrix
  |-- captures.py       PCAP/PCAPNG + 802.11/EAPOL parsing

Audit (audit/)
  |-- password_audit.py strength + PBKDF2/PTK/MIC verifier
  |-- wordlists.py      catalog, import, filter/dedupe/prepare
  |-- research.py       native/WSL/SSH/manual connector + sudo stdin

Persistence
  |-- SQLite (core/db.py): settings, assessments, networks, findings,
      captures, evidence, password_audits, wordlists, reports, audit_log

Reporting
  |-- reporting/: HTML (self-contained + banner), PDF (ReportLab), JSON
```

## Data model

| Table | Purpose |
|---|---|
| `assessments` | Name, organisation, scope, permitted targets JSON, tester, status, dates, notes |
| `networks` | Observation per assessment/BSSID/source with security/radio metadata |
| `findings` | Rule output with severity, status, confidence, explanation, impact, remediation, evidence |
| `captures` | File path, hash, format, packet count, time range, BSSID/SSID, integrity, metadata JSON |
| `evidence` | Hash-linked attachment or capture reference |
| `password_audits` | Engine, status, counts, masked value, elapsed time, strength score — **no plaintext** |
| `wordlists` | Category, source, priority, counts, lengths, hash, prepared flag, provenance |
| `reports` | Format, path, hash, timestamp |
| `audit_log` | Persistent operational trail |
| `settings` | Non-sensitive application settings |
| `schema_meta` | Migration/version marker |

Foreign keys cascade assessment data; evidence/capture links use `ON DELETE SET NULL`
where appropriate. SQLite runs in WAL mode with foreign keys enabled.

## Data flows

### Discovery → findings
1. `windows_wifi` calls `netsh wlan show networks mode=bssid`.
2. Parser creates `NetworkObservation` objects with source `windows`.
3. Service upserts by `(assessment, bssid, source)` and logs.
4. `rules.analyze_network` produces findings.
5. User reviews status; report renders verified/potential/observation separately.

### Capture → evidence → audit
1. Import validates PCAP/PCAPNG structure and hashes the file.
2. File is copied to `evidence/<assessment>/captures/`.
3. Beacon/RSN/EAPOL metadata is extracted; complete msg1/msg2 handshakes are
   identified.
4. Capture and evidence records are created.
5. Auditor requires Active assessment + permitted BSSID + attestation.
6. Wordlists are merged/filtered/deduplicated into a prepared candidate file.
7. Local verifier derives PMK/PTK and validates the EAPOL MIC; Aircrack-ng can be
   invoked instead over WSL/SSH.
8. Masked outcome is persisted; report includes it.

### Reporting
`collect_report_context` aggregates assessment, networks, findings, captures,
evidence, audits and audit events. HTML/JSON are rendered in-process. PDF uses
ReportLab. Each output is hashed and registered.

## UI threading

Long operations (discovery, hardware diagnostics, capture parsing, wordlist
preparation, local audit) run through `TaskRunner`, a `QThreadPool` wrapper with
Qt signals. SQLite connections are short-lived per operation. Progress callbacks emit
tuples; the auditor computes rate and ETA. Cancellation uses a `threading.Event`
checked per candidate.

## Security boundaries

- `safety.py` is the single source of truth for command and scope policy.
- `research.py` never uses a shell for local execution; sudo credentials are stdin
  only.
- `password_audit.py` returns masked values only.
- UI does not construct SQL; repository methods parameterise queries.
- Report HTML escapes all dynamic content; the only embedded binary is the trusted
  application banner.

## Packaging

- `surge_signal.spec` builds a one-file PyInstaller executable.
- `assets/` is bundled as data; `surge_signal/resources_rc.py` embeds the chevron.
- `installer/SurgeSignal.iss` produces a per-user Inno Setup wizard with documentation,
  icon, EULA and launch action.
- The application writes user data to `%LOCALAPPDATA%\SurgeSignal`, never to the
  installation directory.

## Extension points

- Add a rule in `rules.py` with stable id, severity, explanation/impact/remediation.
- Add a capture parser or metadata field in `captures.py` and expose it in the
  capture detail view.
- Add a research transport in `research.py`; keep `validate_argv` and stdin-only
  credential handling.
- Add a wordlist category/catalog entry in `wordlists.py`.
- Add a report section in both HTML and PDF renderers and the JSON schema.
- Add a page by subclassing `BasePage` and registering it in `MainWindow`.

