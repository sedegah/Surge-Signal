# Security model

SURGE Signal is a local-first, safety-first assessment tool. Technical controls are
important, but they do not replace written authorisation, professional judgement or
legal compliance.

## Scope enforcement

Every assessment carries an explicit list of permitted BSSIDs/SSIDs. Offline
password auditing checks all of the following before a candidate is tested:

1. the assessment exists and is **Active**;
2. the capture belongs to that assessment;
3. the target BSSID is a valid address and is listed in permitted targets;
4. the operator confirms the capture came from an authorised laboratory network;
5. the operator confirms this is an offline strength assessment, not an access
   attempt.

Failures produce a clear error and no audit is performed. The UI displays an
`IN SCOPE` / `NOT PERMITTED` indicator before the operation.

## Passive-first operation

This release excludes:

- deauthentication and disassociation;
- rogue access points and beacon flooding;
- frame injection;
- automated attacks against nearby networks;
- active capture or PMKID harvesting;
- cloud or distributed cracking.

Windows discovery is passive inventory. Capture import is offline. The local
verifier performs no network I/O. Aircrack-ng is invoked only against a stored
capture and wordlist.

## Command safety

Research commands are argument vectors, not shell strings. The allow-list covers
inspection and offline tools (`aircrack-ng`, `airmon-ng`, `airodump-ng`, `iw`,
`iwconfig`, `ip`, `ethtool`, `lsusb`, `lspci`, `uname`, `which`, `cat`, `stat`,
`tshark`, `dumpcap`, `capinfos`, `hcxpcapngtool`, `echo`, `id`). Destructive or
active-testing tools and markers (`aireplay-ng`, `airbase-ng`, `mdk3`, `mdk4`,
`bettercap`, `--deauth`, floods, `eaphammer`, `wifi-pumpkin`) are rejected.
Shell metacharacters are rejected in research arguments.

## Linux password handling

- Requested only when a privileged operation is initiated.
- Entered in a protected password field.
- Passed to the native `sudo -S -p ""` mechanism via standard input.
- Never placed in argv, environment variables, settings, SQLite or logs.
- Not requested at launch.
- Empty passwords are rejected by the application; a NOPASSWD policy may be used by
  the Linux administrator if appropriate.
- Authentication failures are reported without echoing credentials.
- The user can cancel the operation.

Native sudo policy, group membership and timestamp behaviour remain authoritative.

## Recovered passphrases

The Kali terminal may display a recovered passphrase for one-time use. The local
verifier API returns only:

- recovered yes/no,
- candidate index and count,
- a masked display value (`C***************!`),
- elapsed time and a strength score.

Terminal Aircrack-ng output is parsed in memory, displayed in the terminal, and the
plaintext is not written to the database. The terminal provides an explicit
clear-memory control. The audit table stores the masked value only. Reports and JSON include the
masked value, never the candidate. The application does not provide a plaintext
recovery vault.

## Evidence protection

- Captures are copied into the per-user data directory, not left in arbitrary
  folders.
- Every capture and attachment is SHA-256 hashed and associated with its assessment.
- Windows ACL hardening restricts the application data directory to the current
  user, SYSTEM and Administrators.
- The database stores evidence metadata and audit events, not raw credentials.
- Uninstall does not delete assessment data; retention is an explicit operator
  responsibility.

**Residual risk:** the release does not encrypt evidence at rest. A user with access to
the Windows account (or an administrator) can read captures and prepared wordlists.
Use BitLocker, EFS, controlled folders or organisational DLP where confidentiality
requirements demand encryption. Do not store unrelated sensitive data in the same
profile.

## Audit trail

Events include assessment lifecycle, discovery, import, inspection, finding review,
hardware diagnostics, wordlist preparation, offline audits, evidence and report
generation. The trail includes actor and timestamp, and excludes credentials.
SQLite foreign keys and integrity checks help preserve consistency.

## Reporting integrity

Findings carry a status:

- **Verified** — confirmed and reviewed by the assessor;
- **Potential risk** — derived from advertised configuration, not actively proven;
- **Observation** — contextual, not a vulnerability.

Reports state these distinctions, include methodology and limitations, and avoid
claiming exploitability from beacon data alone. Report files are hashed and recorded.

## Threat boundaries

| Threat | Control | Residual risk |
|---|---|---|
| Testing an unapproved network | Assessment scope gate + attestation | Determined misuse cannot be prevented by software |
| Password theft from DB | No plaintext storage; masked results | Captures may still contain handshakes |
| Credential leakage through logs | Redaction filter; no login logging | OS-level tracing is outside the app |
| Command injection | Argv allow-list; no shell | A compromised local Kali environment is trusted |
| Evidence disclosure | Per-user ACL; local-only storage | Not encrypted at rest by app |
| Fake/forged capture | SHA-256 integrity record; analyst review | Hash proves file identity, not origin |
| Report overclaiming | Status taxonomy + methodology text | Assessor must review before release |

## Operator responsibilities

1. Obtain and retain written authorisation.
2. Define scope and permitted BSSIDs before testing.
3. Use only lawful wordlists and captures.
4. Mark findings verified only with appropriate evidence.
5. Protect and retain evidence according to policy.
6. Rotate credentials exposed during an authorised audit.
7. Review every report before delivery.



## Reverse engineering and release hardening

No desktop application can be made impossible to reverse engineer. Repository
organisation and naming improve maintainability; they are not a security control.
If the source repository is public, the source is readable.

Practical controls for a release are:

- keep the source repository private;
- ship the one-file executable rather than the source tree;
- do not embed credentials, signing keys or private assessment data;
- sign the Windows executable and installer with an organisation certificate;
- compile with a native packager such as Nuitka when stronger resistance to
  casual inspection is required;
- treat client-side obfuscation as a speed bump, not a guarantee;
- keep genuinely sensitive logic or secrets on a controlled server.

PyInstaller and Nuitka binaries can still be analysed by a determined person.
Do not rely on packaging to protect a secret.
