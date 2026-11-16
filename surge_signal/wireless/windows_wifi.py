"""Windows wireless discovery through native netsh/PowerShell interfaces.

Windows discovery is useful for inventory and passive configuration inspection.
It does not provide monitor mode and is labelled distinctly from Kali research
observations throughout the application.
"""

from __future__ import annotations

import json
import locale
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..core.domain import NetworkObservation, channel_to_band, normalize_bssid, signal_to_dbm


class DiscoveryError(RuntimeError):
    pass


NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


@dataclass(slots=True)
class WlanInterface:
    name: str = ""
    description: str = ""
    guid: str = ""
    state: str = ""
    ssid: str = ""
    bssid: str = ""
    radio_type: str = ""
    authentication: str = ""
    cipher: str = ""
    signal_percent: int | None = None
    channel: int | None = None
    band: str = ""
    receive_rate: str = ""
    transmit_rate: str = ""
    connected: bool = False
    raw: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class DiscoveryResult:
    networks: list[NetworkObservation]
    interface: WlanInterface | None
    warnings: list[str] = field(default_factory=list)
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    )


def _decode(data: bytes) -> str:
    for encoding in ("utf-8", locale.getpreferredencoding(False), "cp1252"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def run_netsh(*args: str, timeout: int = 25) -> str:
    if sys.platform != "win32":
        raise DiscoveryError("Windows wireless discovery is only available on Windows.")
    command = ["netsh", "wlan", *args]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            check=False,
            creationflags=NO_WINDOW,
        )
    except FileNotFoundError as exc:
        raise DiscoveryError("The Windows netsh utility could not be found.") from exc
    except subprocess.TimeoutExpired as exc:
        raise DiscoveryError(
            "Windows wireless discovery timed out. Check that the WLAN AutoConfig "
            "service is running and try again."
        ) from exc
    output = _decode(completed.stdout)
    errors = _decode(completed.stderr).strip()
    if completed.returncode != 0 and not output.strip():
        raise DiscoveryError(
            errors or f"netsh exited with code {completed.returncode}."
        )
    if "The Wireless AutoConfig Service" in output and "not running" in output:
        raise DiscoveryError(
            "The Windows WLAN AutoConfig service is not running. Start the service "
            "and retry the scan."
        )
    return output


def _kv(line: str) -> tuple[str, str] | None:
    match = re.match(r"^\s*([^:]+?)\s*:\s*(.*?)\s*$", line)
    if not match:
        return None
    return match.group(1).strip(), match.group(2).strip()


def parse_networks(output: str, source: str = "windows") -> list[NetworkObservation]:
    """Parse `netsh wlan show networks mode=bssid` output.

    The parser is deliberately tolerant of localisation-neutral field names and
    extra whitespace, and skips malformed BSSID entries rather than guessing.
    """
    networks: list[NetworkObservation] = []
    current_ssid: str | None = None
    current_auth = ""
    current_enc = ""
    current_bssid: dict[str, Any] | None = None
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    def flush_bssid() -> None:
        nonlocal current_bssid
        if not current_bssid:
            return
        bssid = normalize_bssid(current_bssid.get("bssid", ""))
        if not bssid:
            current_bssid = None
            return
        percent = current_bssid.get("signal_percent")
        channel = current_bssid.get("channel")
        band = current_bssid.get("band") or channel_to_band(channel)
        networks.append(
            NetworkObservation(
                ssid=current_ssid or "",
                bssid=bssid,
                signal_dbm=signal_to_dbm(percent) if percent is not None else None,
                signal_percent=percent,
                channel=channel,
                band=band,
                standards=current_bssid.get("radio_type", ""),
                authentication=current_auth,
                encryption=current_enc,
                pmf="Unknown",
                wps="Unknown",
                hidden=not bool(current_ssid),
                source=source,
                first_seen=now,
                last_seen=now,
                raw={
                    "source": source,
                    "raw_signal": current_bssid.get("raw_signal", ""),
                    "network_type": current_bssid.get("network_type", ""),
                    "radio_type": current_bssid.get("radio_type", ""),
                },
            )
        )
        current_bssid = None

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        ssid_match = re.match(r"^\s*SSID\s+\d+\s*:\s*(.*)$", line, re.IGNORECASE)
        if ssid_match:
            flush_bssid()
            current_ssid = ssid_match.group(1).strip()
            current_auth = ""
            current_enc = ""
            continue
        bssid_match = re.match(r"^\s*BSSID\s+\d+\s*:\s*(.*)$", line, re.IGNORECASE)
        if bssid_match:
            flush_bssid()
            current_bssid = {"bssid": bssid_match.group(1).strip()}
            continue
        pair = _kv(line)
        if not pair:
            continue
        key, value = pair
        lowered = key.lower()
        if current_bssid is not None:
            if lowered == "signal":
                match = re.search(r"(\d+)%", value)
                if match:
                    current_bssid["signal_percent"] = int(match.group(1))
                    current_bssid["raw_signal"] = value
            elif lowered == "radio type":
                current_bssid["radio_type"] = value
            elif lowered == "band":
                current_bssid["band"] = value
            elif lowered in {"channel", "primary channel"}:
                try:
                    current_bssid["channel"] = int(re.search(r"\d+", value).group(0))                            
                except (AttributeError, TypeError, ValueError):
                    pass
            elif lowered in {"network type", "network mode"}:
                current_bssid["network_type"] = value
        if lowered == "authentication":
            current_auth = value
        elif lowered == "encryption":
            current_enc = value
    flush_bssid()

    unique: dict[str, NetworkObservation] = {}
    for network in networks:
        unique[network.bssid] = network
    return sorted(
        unique.values(),
        key=lambda item: (item.signal_dbm is None, -(item.signal_dbm or -999), item.ssid),
    )


def parse_interfaces(output: str) -> list[WlanInterface]:
    interfaces: list[WlanInterface] = []
    current: dict[str, Any] | None = None

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        item = WlanInterface(
            name=current.get("name", ""),
            description=current.get("description", ""),
            guid=current.get("guid", ""),
            state=current.get("state", ""),
            ssid=current.get("ssid", ""),
            bssid=normalize_bssid(current.get("bssid") or current.get("ap bssid", "")),
            radio_type=current.get("radio type", ""),
            authentication=current.get("authentication", ""),
            cipher=current.get("cipher", ""),
            signal_percent=current.get("signal_percent"),
            channel=current.get("channel"),
            band=current.get("band", ""),
            receive_rate=current.get("receive rate", "")
            or current.get("receive rate (mbps)", ""),
            transmit_rate=current.get("transmit rate", "")
            or current.get("transmit rate (mbps)", ""),
            connected=current.get("state", "").lower() == "connected",
            raw={k: str(v) for k, v in current.items() if not k.startswith("_")},
        )
        interfaces.append(item)
        current = None

    for line in output.splitlines():
        if re.match(r"^\s*Name\s*:", line, re.IGNORECASE):
            flush()
            current = {}
        if current is None:
            continue
        pair = _kv(line)
        if not pair:
            continue
        key, value = pair
        lowered = key.lower()
        if lowered == "signal":
            match = re.search(r"(\d+)%", value)
            if match:
                current["signal_percent"] = int(match.group(1))
        elif lowered in {"channel", "primary channel"}:
            try:
                current["channel"] = int(re.search(r"\d+", value).group(0))                            
            except (AttributeError, TypeError, ValueError):
                pass
        elif lowered == "band":
            current["band"] = value
        else:
            current[lowered] = value
    flush()
    return interfaces


def parse_drivers(output: str) -> dict[str, Any]:
    """Extract useful capability statements from `netsh wlan show drivers`."""
    data: dict[str, Any] = {"wireless_driver": {}, "raw_excerpt": output[:4000]}
    driver = data["wireless_driver"]
    capture_keys = {
        "interface name": "interface_name",
        "driver": "driver",
        "vendor": "vendor",
        "provider": "provider",
        "date": "date",
        "version": "version",
        "inf file": "inf_file",
        "fips mode supported": "fips",
        "radio types supported": "radio_types",
        "authentication and cipher supported": "auth_ciphers",
        "hosted network supported": "hosted_network",
        "802.11w management frame protection supported": "pmf_supported",
        "wireless display supported": "wireless_display",
    }
    for line in output.splitlines():
        pair = _kv(line)
        if not pair:
            continue
        key, value = pair
        lowered = key.lower()
        if lowered in capture_keys:
            driver[capture_keys[lowered]] = value
    return data


def _powershell_json(script: str, timeout: int = 20) -> Any:
    if sys.platform != "win32":
        return []
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            timeout=timeout,
            check=False,
            creationflags=NO_WINDOW,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    text = _decode(completed.stdout).strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return []


def get_interface_summary() -> tuple[WlanInterface | None, list[WlanInterface]]:
    try:
        interfaces = parse_interfaces(run_netsh("show", "interfaces"))
    except DiscoveryError:
        interfaces = []
    if interfaces:
        connected = next((item for item in interfaces if item.connected), interfaces[0])
        return connected, interfaces
    adapters = _powershell_json(
        "Get-NetAdapter -Physical | Where-Object {$_.PhysicalMediaType -match '802.11' "
        "or $_.Name -match 'Wi-Fi|Wireless|WLAN'} | "
        "Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed | ConvertTo-Json"
    )
    if isinstance(adapters, dict):
        adapters = [adapters]
    fallback: list[WlanInterface] = []
    for adapter in adapters or []:
        fallback.append(
            WlanInterface(
                name=adapter.get("Name", ""),
                description=adapter.get("InterfaceDescription", ""),
                state=adapter.get("Status", ""),
                connected=str(adapter.get("Status", "")).lower() == "up",
                raw=adapter,
            )
        )
    return (fallback[0] if fallback else None), fallback


def _split_nmcli(line: str) -> list[str]:
    """Split nmcli -t output without breaking escaped colons in BSSIDs."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    return fields


def parse_nmcli_networks(output: str) -> list[NetworkObservation]:
    networks: list[NetworkObservation] = []
    for line in output.splitlines():
        fields = _split_nmcli(line)
        if len(fields) < 6:
            continue
        bssid, ssid, channel, signal, security, freq = fields[:6]
        bssid = normalize_bssid(bssid)
        if not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
            continue
        try:
            channel_value = int(channel)
        except ValueError:
            channel_value = None
        try:
            signal_value = int(signal)
        except ValueError:
            signal_value = None
        security = security.strip() or "Open"
        upper = security.upper()
        if "WPA3" in upper:
            authentication = "WPA3-Personal"
            encryption = "CCMP"
        elif "WPA2" in upper:
            authentication = "WPA2-Personal"
            encryption = "CCMP"
        elif "WPA" in upper:
            authentication = "WPA-Personal"
            encryption = "TKIP"
        elif "WEP" in upper:
            authentication = "WEP"
            encryption = "WEP"
        else:
            authentication = "Open"
            encryption = "Open"
        networks.append(
            NetworkObservation(
                ssid=ssid or "<hidden>",
                bssid=bssid,
                signal_dbm=signal_to_dbm(signal_value) if signal_value is not None else None,
                signal_percent=signal_value,
                channel=channel_value,
                authentication=authentication,
                encryption=encryption,
                source="linux",
                raw={"security": security, "frequency_mhz": freq},
            )
        )
    networks.sort(key=lambda item: item.signal_dbm or -999, reverse=True)
    return networks


def discover_linux() -> DiscoveryResult:
    warnings: list[str] = []
    nmcli = shutil.which("nmcli")
    interface: WlanInterface | None = None
    if not nmcli:
        return DiscoveryResult(
            networks=[],
            interface=None,
            warnings=[
                "NetworkManager (nmcli) was not found. Install network-manager or run "
                "capture through the native Kali terminal."
            ],
        )
    try:
        devices = subprocess.run(
            [nmcli, "-t", "-f", "DEVICE,TYPE,STATE", "device"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            creationflags=NO_WINDOW,
        )
        for line in devices.stdout.splitlines():
            fields = _split_nmcli(line)
            if len(fields) >= 3 and fields[1] == "wifi":
                interface = WlanInterface(
                    name=fields[0],
                    description="NetworkManager Wi-Fi adapter",
                    state=fields[2],
                    connected=fields[2] == "connected",
                )
                break
        result = subprocess.run(
            [
                nmcli,
                "-t",
                "-f",
                "BSSID,SSID,CHAN,SIGNAL,SECURITY,FREQ",
                "dev",
                "wifi",
                "list",
                "--rescan",
                "yes",
            ],
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
            creationflags=NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DiscoveryResult(networks=[], interface=interface, warnings=[str(exc)])
    if result.returncode != 0:
        warnings.append(result.stderr.strip() or "NetworkManager could not scan Wi-Fi.")
        return DiscoveryResult(networks=[], interface=interface, warnings=warnings)
    networks = parse_nmcli_networks(result.stdout)
    if not networks:
        warnings.append("No wireless networks were returned by NetworkManager.")
    return DiscoveryResult(networks=networks, interface=interface, warnings=warnings)


def discover_networks() -> DiscoveryResult:
    if sys.platform != "win32":
        return discover_linux()
    warnings: list[str] = []
    interface, all_interfaces = get_interface_summary()
    if not all_interfaces:
        warnings.append(
            "No Windows wireless interface was detected. Verify the Wi-Fi adapter "
            "is enabled and the WLAN AutoConfig service is running."
        )
    try:
        output = run_netsh("show", "networks", "mode=bssid")
    except DiscoveryError as exc:
        return DiscoveryResult(networks=[], interface=interface, warnings=[str(exc)])
    networks = parse_networks(output)
    if not networks:
        warnings.append(
            "No wireless networks were returned. Ensure Wi-Fi is enabled and that "
            "location permissions allow network discovery."
        )
    return DiscoveryResult(networks=networks, interface=interface, warnings=warnings)


def driver_diagnostics() -> dict[str, Any]:
    if sys.platform != "win32":
        return {"error": "Windows driver diagnostics are not applicable on Linux.", "wireless_driver": {}}
    try:
        output = run_netsh("show", "drivers")
    except DiscoveryError as exc:
        return {"error": str(exc), "wireless_driver": {}}
    return parse_drivers(output)

