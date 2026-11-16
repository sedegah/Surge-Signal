# SURGE Signal Security Audit

Date: 16 November 2026  
Scope: SURGE Signal 1.0.0 source tree, Python environment, Windows build,
Linux package and local data handling.  
Audit type: code review, dependency audit and static analysis. This was not a
network penetration test and no third-party systems were tested.

## Executive summary

No known vulnerable Python dependencies were found. Static analysis reported
**32 low-severity findings and no medium- or high-severity findings**; the
findings reviewed were either deliberate design choices, false positives, or
defence-in-depth improvements.

One concrete issue was fixed during the audit:

- **Linux/macOS data files used default permissions.** Application directories
  are now restricted to the owning user (`0700`) and files to `0600`. The SQLite
  database is explicitly set to `0600` on POSIX.

The largest remaining risks are not code defects:

1. The source repository is public.
2. The Windows installer is unsigned.
3. Captures, reports and the database are not encrypted at rest.
4. Screenshots contain real network names and addresses.
5. Live capture depends on external Kali tooling and hardware.

## Checks performed

### Dependency vulnerabilities

Tool: `pip-audit 2.10.1`  
Command:

```text
python -m pip_audit --format json
```

Result:

- **0 known vulnerabilities** across the installed Python packages.
- No dependency remediation required at audit time.

Re-run this check before every release because advisories change.

### Static analysis

Tool: `bandit 1.9.4`  
Command:

```text
python -m bandit -q -r surge_signal -f json
```

Result:

| Severity | Count |
|---|---:|
| High | 0 |
| Medium | 0 |
| Low | 32 |

Reviewed low findings:

| Finding | Assessment |
|---|---|
| `subprocess` import and calls | Required for approved Kali commands. Commands use argv, not a shell, and pass through `validate_argv`. |
| `try/except/pass` | Used for best-effort logging, marker writes and optional cleanup. No security decision depends on a swallowed exception. |
| Hardcoded empty password | False positive: empty string parameters and UI fields, not credentials. |
| `xml.sax.saxutils.escape` | False positive: used to escape report text, not to parse XML. |
| Partial executable path for `icacls` | Reviewed and fixed. The code now resolves `%SystemRoot%\System32\icacls.exe` before falling back to `PATH`. |

### Secret and sensitive-data scan

Searched source, build files and documentation for credential patterns, keys,
tokens and personal paths.

- No API keys, signing keys, passwords or access tokens are stored in source.
- No plaintext recovered Wi-Fi passwords are stored by the application.
- The audit found one personal Windows path in installation documentation; it
  was replaced with a generic path.
- `docs/screenshots/` contains real SSID/BSSID values from the development
  machine. These are now public because the repository is public.

### Command execution review

- Commands are constructed as argv arrays and executed without a shell.
- `validate_argv` enforces a fixed allow-list.
- Sudo passwords are written only to standard input.
- Aircrack output is parsed in memory; only a masked value is persisted.
- The installer force-closes a running `SurgeSignal.exe` before replacing files.

### Host posture

Checked on the development Windows host:

- Microsoft Defender antivirus: **enabled**.
- Real-time protection: **enabled**.
- Defender signatures updated: 16 November 2026.

Windows Firewall and BitLocker state could not be read from the non-elevated
audit session. Review them with administrator rights:

```powershell
Get-NetFirewallProfile
Get-BitLockerVolume
```

## Findings and status

| ID | Severity | Finding | Status |
|---|---|---|---|
| AUD-01 | High | Source and screenshots are public; source review and reverse engineering are possible. | Accepted by owner. Keep no secrets in source; consider making the repository private again. |
| AUD-02 | Medium | Installer and executable are not code-signed; SmartScreen may warn and users cannot verify publisher identity cryptographically. | Open. Sign releases with an organisation certificate. |
| AUD-03 | Medium | Captures, reports and the SQLite database are not encrypted at rest. | Open. Use BitLocker/EFS, an encrypted volume or an encrypted home directory. |
| AUD-04 | Medium | Screenshots expose real network names and addresses. | Open. Redact screenshots before further public releases. |
| AUD-05 | Low | POSIX data files used default umask permissions. | **Fixed**: directories `0700`, files `0600`, database `0600`. |
| AUD-06 | Low | Windows `icacls` was invoked through `PATH`. | **Fixed**: explicit `%SystemRoot%\System32\icacls.exe` lookup. |
| AUD-07 | Low | Malicious or compromised Kali tooling is trusted once invoked. | Accepted. Use a controlled Kali image and verify tool provenance. |
| AUD-08 | Info | Terms acceptance is stored locally and is not a legal identity check. | Accepted. It records informed acceptance, not identity. |

## Residual risks

- A local administrator or malware running as the user can read app data.
- Hash records prove file identity, not capture origin.
- Findings describe advertised configuration; they do not prove exploitability.
- Wireless results depend on adapter, driver, channel and capture quality.
- The application cannot prevent an authorised operator from misusing it.
- Public release artifacts cannot be made impossible to reverse engineer.

## Recommendations

1. Sign the Windows executable and installer before distributing to third
   parties.
2. Enable full-disk encryption on machines that store client captures.
3. Redact or replace the public screenshots.
4. Re-run `pip-audit` and `bandit` for every release.
5. Keep the Kali research image minimal, patched and controlled.
6. Review firewall and BitLocker settings with administrator rights.
7. If source confidentiality matters, make the repository private again and
   publish only signed release artifacts.

## Verification commands

```powershell
.\.venv\Scripts\python.exe -m pip_audit
.\.venv\Scripts\python.exe -m bandit -q -r surge_signal
.\.venv\Scripts\python.exe -m pytest -q tests
```
