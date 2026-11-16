# Testing and validation

## Automated suite

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests
```

The suite currently contains **45 passing tests**.

| Area | Coverage |
|---|---|
| Domain | BSSID normalisation, security classification, scope matching, severity counts |
| Database | Assessment round-trip, network upsert/search, audit log, integrity check |
| Rules | Open, WEP, WPA1/TKIP, WPA3, PMF, WPS, hidden SSID and observation semantics |
| Captures | PCAP metadata, beacon/RSN/WPS parsing, handshake extraction, MIC verification, truncation |
| Password | Strength heuristics, wordlist inspection, match/no-match/cancel, masked Aircrack output |
| Wordlists | 13-entry catalog, category priority, length filtering, dedupe, cap/truncation, index, custom lists |
| Safety | Disruptive command rejection, allow-list, Active/scope/attestation gates, redaction |
| Services | Full authorised workflow, out-of-scope block, inactive-assessment block |
| Reports | HTML/PDF/JSON generation, status distinction, no plaintext leaked, PDF magic |
| Windows | `netsh` networks/interfaces/drivers parsers |
| UI | Offscreen startup with zero demo data and assessment-backed navigation of all 10 pages |

## Temporary capture fixtures

The capture tests generate a synthetic 802.11/WPA2 capture in a temporary directory.
It contains a beacon with WPA2-PSK/CCMP and WPS, plus a valid msg1/msg2 handshake for
a known test passphrase. This fixture is **not shipped** and is not loaded by the
application. It exists only to prove parsing and cryptographic verification work.

## Live environment validation

Performed on the reference machine:

| Check | Result |
|---|---|
| Windows 11 Pro x64 | Pass |
| Python 3.14 / PySide6 6.12 | Pass |
| Application launch and 10-page navigation | Pass |
| Windows wireless discovery | Returned nearby networks with SSID/BSSID/security |
| Realtek RTL8822CE detection | Pass; readiness Conditional |
| Monitor/injection claims | Correctly untested/limited, not approved |
| Kali WSL detection | `Kali GNU/Linux Rolling`, kernel 6.18 WSL2 |
| Aircrack-ng / TShark / capinfos detection | Pass |
| PDF/HTML/JSON generation | Pass, non-zero files and valid structure |
| PyInstaller executable | Built and smoke-tested |
| Inno Setup installer | Built from the same executable |

## Manual hardware validation procedure

After any adapter or Kali kernel change:

1. Confirm the adapter appears in Windows and in Kali (`lsusb`, `lspci`).
2. Confirm the intended driver is loaded (`lsmod`, `dmesg`).
3. Validate monitor interface creation in Kali, outside SURGE Signal.
4. Run a short controlled capture on your own laboratory network.
5. Import it and verify packet count, BSSID, SSID and integrity.
6. Record the result in **Hardware Diagnostics** and the assessment audit trail.
7. Only then treat capture/audit capability as validated.

Do not mark an adapter validated merely because it connects to Wi-Fi. Windows
client connectivity does not prove monitor mode, capture or injection.

## Packaged build smoke test

```powershell
.\dist\SurgeSignal.exe --smoke-test --data-dir "$env:TEMP\surge-signal-smoke"
Start-Sleep -Seconds 8
Get-Content "$env:TEMP\surge-signal-smoke\logs\surge_signal.log" -Tail 20
```

Expected: `Starting Surge Signal 1.0.0 (Release)` and no traceback. The process exits
after the smoke-test timer.

## Installer validation

1. Run `installer-output\SurgeSignal-Setup-1.0.0.exe`.
2. Complete the wizard; confirm shortcut creation.
3. Launch from the Start menu.
4. Confirm the app icon and banner appear.
5. Confirm user data is under `%LOCALAPPDATA%\SurgeSignal`.
6. Uninstall; confirm program files are removed and assessment data remains.

## Reporting checks

- HTML opens without external assets (banner is embedded).
- PDF pages render cover, summary, inventory and findings without clipping.
- JSON parses and contains `schema: surge-signal.report.v1`.
- No recovered passphrase appears in reports, logs, JSON or SQLite.

## Continuous checks

```powershell
python -m compileall -q surge_signal
python -m pytest -q tests
python -m surge_signal --smoke-test --data-dir "$env:TEMP\surge-smoke"
```


