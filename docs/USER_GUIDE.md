# User guide

## First run

SURGE Signal creates a real **Local Wireless Workspace** on first launch so passive
discovery works immediately. You do not need to create or enter an assessment ID
before scanning. Scope-sensitive auditing still requires an Active assessment with
explicit permitted targets.

### 1. Create an assessment

Open **Assessments → New assessment** and provide:

- a meaningful name;
- the authorising organisation or laboratory;
- the tester;
- scope statement and any exclusions;
- one permitted target per line (exact BSSID or SSID);
- status (`Draft`, `Active`, `Complete`, `Archived`);
- start/end dates and internal notes.

Offline password auditing requires the assessment to be **Active** and the capture
BSSID to appear in permitted targets. Do not paste credentials into notes.

### 2. Discover networks

Open **Wireless Scanner**. With auto-discovery enabled (the default), SURGE Signal
performs a passive Windows scan automatically when an assessment is selected and
refreshes every 45 seconds while the scanner is open. Use the **Auto-refresh**
checkbox to suspend it, or the **Scan Windows Wi-Fi** button for an immediate scan.

- **Scan Windows Wi-Fi** performs passive discovery through the Windows client
  adapter. Results are labelled `Windows discovery`.
- **Import inventory** accepts JSON in the form
  `{"source":"kali","networks":[{...}]}` or a plain list. Each observation retains
  its source.
- Search and filter by source; export the current view to CSV.
- Select a row to review authentication, encryption, PMF, WPS, standards and
  observation times. **Inspect this network** runs the rule engine for that row.

Windows discovery is not monitor mode. Kali observations are a separate source.

### 3. Inspect security configuration

Open **Network Inspector**.

**Run inspection** evaluates every observed network. Findings are explainable and
include severity, confidence, explanation, impact, remediation and evidence.

Review each finding:

- **Mark verified** after you have confirmed it by appropriate evidence;
- **Mark observation** to retain context without presenting it as a vulnerability.

Rebuilding findings replaces prior review statuses; the application warns first.

### 4. Review hardware readiness

Open **Hardware Diagnostics → Run diagnostics**.

The capability table distinguishes:

- **validated** — observed on this host;
- **documented** — known driver knowledge, still requiring validation;
- **limited / untested** — not approved for capture or injection;
- **not supported** — documented as unavailable.

**Test Kali connection** checks the configured transport, environment, user, kernel
and tool presence. **Privileged interface scan** runs a read-only `iw dev` through
sudo. You are prompted for the Linux password only for that operation; it is sent to
sudo over stdin and is never stored.

### 5. Import an authorised capture

Open **Capture Manager → Import capture**, select a `.pcap`/`.pcapng`/`.cap` file
(optionally gzip-compressed), confirm authorisation, and review:

- format, packet count, capture time range and integrity;
- SHA-256 and evidence location;
- BSSID/SSID/security/PMF/WPS metadata;
- complete WPA handshakes and analysis notes.

Captures are copied into the assessment evidence store. **Re-analyse** refreshes
metadata; **Export evidence** copies the stored file to a chosen destination.

### 6. Install wordlists

Open **Wordlist Library**.

- The **Curated catalog** documents 13 collections with provenance, licensing and
  guidance. SURGE Signal does not bundle or silently download them.
- Download an authorised collection from its official source.
- Use **Import list**, choose the category and confirm provenance.
- **Scan library** indexes files placed directly in the managed folders.
- **Create custom** stores an engagement-specific list in the managed custom folder.
- **Use in Password Auditor** carries selected lists into the audit workflow.

See [WORDLISTS.md](WORDLISTS.md) for details.

### 7. Kali terminal and Aircrack-ng

Open **Password Auditor → Kali terminal / Aircrack**, or **Tools → Kali terminal /
Aircrack**. The guided terminal provides:

1. a protected Kali password field (used only for sudo, never stored);
2. **Authenticate & install tools** — installs/updates ircrack-ng, iw,
   wireless-tools, wordlists and 	shark in the configured Kali environment;
3. capture, wordlist and target BSSID selection with a live scope indicator;
4. laboratory attestation and confirmation before execution;
5. the live Aircrack-ng output in the terminal;
6. a one-time recovered passphrase display and copy action, plus a clear-memory
   button. The database stores only a masked result.

Aircrack-ng needs an imported capture containing a valid WPA/WPA2 handshake. Use
Kali to obtain the capture from your own or explicitly authorised lab network first.

### 8. Run a controlled offline audit

Open **Password Auditor → Offline audit**.

1. Select the capture.
2. Confirm or enter the target BSSID. The scope chip shows `IN SCOPE` or
   `NOT PERMITTED`.
3. Check one or more source wordlists.
4. Set the length policy and candidate cap.
5. Choose **Local WPA2 verifier** or **Aircrack-ng in Kali**.
6. **Prepare candidate list** — merges by category priority, filters, deduplicates
   and writes a prepared list with SHA-256.
7. **Run authorised audit** — review the scope and attestation dialog; both boxes
   must be checked.
8. Monitor progress and ETA. **Stop** requests cancellation after the current
   candidate.

Results show status, engine, candidates tested, elapsed time and a **masked** value
if a match is found. The passphrase itself is not persisted.

What the audit does and does not prove:

- It proves whether a candidate matches the handshake in the capture.
- It does not prove that the network is exploitable or that the passphrase is used
  anywhere else.
- Rotate any recovered lab credential after the assessment.

### 9. Manage evidence and audit trail

In **Assessments**, open the workspace:

- **Overview** shows scope, targets, dates, status and permitted actions.
- **Evidence** lists captures and attachments with sizes, hashes and timestamps.
  Attach supporting files; remove records without deleting the stored file.
- **Audit trail** records assessment creation, scans, inspections, imports, audits,
  status changes and report generation. Passwords never appear.

### 10. Generate reports

Open **Reports**:

1. Select PDF, HTML and/or JSON.
2. Choose the output folder.
3. Generate and open the report.

Reports distinguish verified findings, potential risks and observations. The HTML
is self-contained (banner embedded); PDF is print-ready; JSON includes structured
networks, findings, captures, evidence, audits and the audit trail.

### 11. Settings

Configure the research transport, Kali distribution or SSH host, share mapping,
tool commands, sudo timeout, operator name, local verifier cap, wordlist limits,
prepared-list retention and report folder. **Check database** runs SQLite integrity
and foreign-key checks.

## Status semantics

| Status | Meaning |
|---|---|
| Draft | Workspace prepared; not yet authorised for active/offline audit |
| Active | Authorised assessment; permits capture import and offline audit |
| Complete | Assessment concluded; audit blocked, records retained |
| Archived | Removed from active workspace selector; retained with evidence |

## Safety reminders

- Test only networks and captures you are explicitly authorised to assess.
- Do not upload captures or wordlists to untrusted services.
- Do not use recovered credentials to access systems outside the engagement.
- Follow the assessment's data-retention and incident-response requirements.

