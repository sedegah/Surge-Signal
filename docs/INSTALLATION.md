# Installation

## Supported host

- Windows 11 x64 (the reference machine is a Lenovo ThinkPad E15 Gen 1,
  i7-10510U, 8 GB RAM, Realtek RTL8822CE).
- Python 3.11 or newer for source use. The packaged build does not need Python.
- Kali Linux is optional for the local verifier and required for Aircrack-ng
  transport, TShark analysis and privileged Linux interface diagnostics.

## Install from the wizard

1. Run `installer-output\SurgeSignal-Setup-1.0.0.exe`.
2. Accept the authorised-use agreement.
3. Choose the per-user destination (default:
   `%LOCALAPPDATA%\Programs\Surge Signal`) and optional desktop shortcut.
4. Finish the wizard and launch SURGE Signal.

The installer is per-user and does not require administrator rights. It is not
code-signed, so Windows SmartScreen may display a warning; inspect the source and
choose **More info → Run anyway** only if you trust this build.

The uninstaller removes program files and documentation. It deliberately does **not**
delete `%LOCALAPPDATA%\SurgeSignal`, because that folder contains assessment records
and evidence. Remove it manually under your retention policy.

## Run from source

```powershell
cd "C:\path\to\Surge Signal"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r project\requirements.txt
.\scripts\Surge Signal.bat
```

Or directly:

```powershell
.\.venv\Scripts\python.exe -m surge_signal
```

The application stores data in:

```text
%LOCALAPPDATA%\SurgeSignal\
├── surge_signal.db
├── evidence\
├── captures\
├── reports\
├── wordlists\
├── exchange\
└── logs\
```

Use `--data-dir <path>` for an isolated test profile, or set
`SURGE_SIGNAL_HOME`.

## Kali research environment

### Option A — WSL2 Kali (recommended for offline tooling)

WSL2 is useful for Aircrack-ng and offline scripting. It does **not** provide direct
monitor-mode access to the internal Realtek adapter. It must not be presented as a
radio-level research environment.

```powershell
wsl --install -d kali-linux
wsl -d kali-linux -- sudo apt update
wsl -d kali-linux -- sudo apt install -y aircrack-ng tshark
wsl -d kali-linux -- which aircrack-ng tshark capinfos
```

Then in **Settings → Research environment** select `WSL2`, set the distribution name
(e.g. `kali-linux`) and use **Test Kali connection**. SURGE Signal identifies the
Linux username and tool availability without requesting a password at launch.

### Option B — Kali VM (recommended for radio-level research)

1. Create a Kali VM in VirtualBox with adequate RAM and disk.
2. Install Kali and update Aircrack-ng/TShark.
3. For an internal adapter, configure USB passthrough only after confirming the
   adapter is visible in Kali (`lsusb`, `ip link`). VirtualBox USB passthrough may
   not support every internal adapter or firmware.
4. For a reliable research workflow, use a supported USB adapter whose exact driver
   has been validated on your Kali kernel.
5. Configure **Settings → Transport → SSH**, enter the VM host/user, and copy an SSH
   key so key authentication works without a password prompt. Alternatively use
   **Manual shared folder** for air-gapped exchange.

### Option C — Manual shared folder

Set a Windows share and its Linux mount point in Settings. Place captures and
wordlists in the exchange folder, run offline analysis inside Kali, and import the
structured results. Manual mode never executes commands automatically.

## Adapter expectations

The internal RTL8822CE is detected as a client adapter. The documented `rtw88`
driver may expose limited monitor mode depending on kernel version, and mainline
frame injection is not supported. SURGE Signal therefore reports readiness as
**Conditional** and does not claim capture or injection capability until it has been
validated in the configured Kali environment.

Connectivity alone is never evidence of monitor mode, packet capture or injection.

## Verify the installation

```powershell
.\.venv\Scripts\python.exe -m compileall -q surge_signal
.\.venv\Scripts\python.exe -m pytest -q tests
.\.venv\Scripts\python.exe -m surge_signal --smoke-test --data-dir "$env:TEMP\surge-signal-smoke"
```

This runs the 45-test suite and an offscreen UI smoke test. For the packaged
application:

```powershell
.\dist\SurgeSignal.exe --smoke-test --data-dir "$env:TEMP\surge-signal-smoke"
Get-Content "$env:TEMP\surge-signal-smoke\logs\surge_signal.log" -Tail 20
```

The log should contain `Starting Surge Signal 1.0.0` and no traceback.

## Troubleshooting

| Symptom | Resolution |
|---|---|
| No networks found | Enable Wi-Fi; ensure WLAN AutoConfig is running; check Windows location permission. |
| `netsh` discovery fails | Run `netsh wlan show interfaces` in a terminal and review the error. |
| Hardware diagnostics show no adapter | Confirm the adapter is enabled in Device Manager. |
| Kali not reachable | Check `wsl -l -v`, the configured distro name, or SSH key/network connectivity. |
| Aircrack-ng missing | `sudo apt install aircrack-ng` in Kali. |
| Local audit says no complete handshake | The capture must contain WPA msg1 and msg2 for the selected BSSID. PMKID-only captures are not supported by the local verifier. |
| Scope error during audit | Mark the assessment Active and add the exact BSSID to permitted targets. |
| PDF generation fails | Reinstall `reportlab`; see the application log and the error dialog. |
| SmartScreen warning | Unsigned local build: verify provenance, then More info → Run anyway. |

