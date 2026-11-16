"""Wireless adapter and research-environment diagnostics.

Capabilities are never inferred from ordinary Wi-Fi connectivity. The module
distinguishes what Windows reports, what the Linux kernel documents, and what has
actually been validated on this machine. Unverified capabilities remain
`untested` and are presented as limitations rather than approvals.
"""

from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .windows_wifi import NO_WINDOW, WlanInterface, driver_diagnostics, get_interface_summary


@dataclass(frozen=True, slots=True)
class Capability:
    name: str
    status: str
    detail: str
    source: str


@dataclass(frozen=True, slots=True)
class AdapterProfile:
    match: tuple[str, ...]
    label: str
    linux_driver: str
    monitor: str
    injection: str
    bands: str
    notes: str


                                                                        
                                                                      
KNOWN_ADAPTERS: tuple[AdapterProfile, ...] = (
    AdapterProfile(
        ("rtl8822ce", "8822ce"),
        "Realtek RTL8822CE",
        "rtw88_8822ce (in-kernel; kernel 5.9+)",
        "Limited / kernel-dependent",
        "Not supported by mainline driver",
        "2.4 GHz, 5 GHz",
        "Common internal adapter in the ThinkPad E15 Gen 1. Basic Wi-Fi works via "
        "rtw88, but monitor mode is inconsistent and frame injection is not a "
        "supported mainline feature. Treat capture/injection as unvalidated.",
    ),
    AdapterProfile(
        ("rtl8812au", "8812au", "rtl88xxau"),
        "Realtek RTL8812AU (USB)",
        "rtl88xxau / 8812au (out-of-tree)",
        "Supported with the correct driver",
        "Supported with the correct driver",
        "2.4 GHz, 5 GHz",
        "Popular dual-band research adapter. Driver provenance matters; validate "
        "monitor mode, injection and Kali kernel compatibility before relying on it.",
    ),
    AdapterProfile(
        ("ar9271", "ath9k_htc"),
        "Atheros AR9271 (USB)",
        "ath9k_htc (in-kernel)",
        "Supported",
        "Supported",
        "2.4 GHz",
        "Well-supported 2.4 GHz research adapter for passive capture and controlled "
        "injection testing. Still verify the specific hardware revision.",
    ),
    AdapterProfile(
        ("ax200", "ax201", "iwlwifi"),
        "Intel Wi-Fi 6 AX200/AX201",
        "iwlwifi (in-kernel)",
        "Limited / kernel-dependent",
        "Not reliable",
        "2.4 GHz, 5 GHz, 6 GHz (adapter-dependent)",
        "Reliable client connectivity. Monitor mode support varies by kernel and "
        "firmware; injection is not a supported assessment capability.",
    ),
    AdapterProfile(
        ("mt7921", "mt7922"),
        "MediaTek MT7921/MT7922",
        "mt7921e / mt7922e (in-kernel)",
        "Limited / kernel-dependent",
        "Not supported",
        "2.4 GHz, 5 GHz (6 GHz on MT7922)",
        "Modern client adapter. Monitor mode is experimental and should not be "
        "assumed for assessment work.",
    ),
    AdapterProfile(
        ("bcm43", "broadcom"),
        "Broadcom 802.11 adapter",
        "wl (vendor) or b43 (in-kernel)",
        "Driver-dependent",
        "Driver-dependent",
        "Adapter-dependent",
        "Broadcom support varies significantly. Validate the exact PCI ID and driver "
        "in Kali before planning captures.",
    ),
)


def _ps_json(script: str, timeout: int = 20) -> Any:
    if sys.platform != "win32":
        return None
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            timeout=timeout,
            check=False,
            creationflags=NO_WINDOW,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    text = completed.stdout.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


@dataclass(slots=True)
class HostInfo:
    os_name: str = platform.platform()
    machine: str = platform.machine()
    processor: str = ""
    ram_gb: float = 0.0
    virtualization: str = "Unknown"
    python: str = platform.python_version()
    wsl_available: bool = False
    virtualbox_available: bool = False
    free_disk_gb: float = 0.0


@dataclass(slots=True)
class HardwareReport:
    host: HostInfo
    adapters: list[WlanInterface] = field(default_factory=list)
    capabilities: list[Capability] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    )
    driver_data: dict[str, Any] = field(default_factory=dict)
    readiness: str = "Untested"


def _find_profile(*texts: str) -> AdapterProfile | None:
    haystack = " ".join(texts).lower()
    for profile in KNOWN_ADAPTERS:
        if any(marker in haystack for marker in profile.match):
            return profile
    return None


def _cap(name: str, status: str, detail: str, source: str) -> Capability:
    return Capability(name=name, status=status, detail=detail, source=source)


def _host_info() -> HostInfo:
    info = HostInfo()
    info.wsl_available = bool(shutil.which("wsl"))
    info.virtualbox_available = bool(
        shutil.which("VBoxManage") or Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe").exists()
    )
    try:
        info.free_disk_gb = round(shutil.disk_usage(Path.home()).free / (1024**3), 1)
    except OSError:
        pass
    system = _ps_json(
        "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,"
        "TotalPhysicalMemory,HypervisorPresent | ConvertTo-Json"
    )
    processor = _ps_json(
        "Get-CimInstance Win32_Processor | Select-Object -First 1 Name,NumberOfCores,"
        "NumberOfLogicalProcessors | ConvertTo-Json"
    )
    if isinstance(system, dict):
        info.processor = (
            f"{system.get('Manufacturer', '')} {system.get('Model', '')}".strip()
        )
        try:
            info.ram_gb = round(int(system.get("TotalPhysicalMemory", 0)) / (1024**3), 1)
        except (TypeError, ValueError):
            pass
        hypervisor = bool(system.get("HypervisorPresent"))
        info.virtualization = "Hypervisor detected" if hypervisor else "Not detected"
    if isinstance(processor, dict):
        name = str(processor.get("Name", "")).strip()
        if name:
            info.processor = name
    if not info.ram_gb and sys.platform != "win32":
        info.ram_gb = 0.0
    return info


def diagnose_adapters() -> HardwareReport:
    host = _host_info()
    interface, adapters = get_interface_summary()
    drivers = driver_diagnostics()
    warnings: list[str] = []
    recommendations: list[str] = []
    capabilities: list[Capability] = []

    if not adapters:
        warnings.append(
            "No wireless adapter was detected by Windows. Hardware compatibility "
            "cannot be assessed until an adapter is present and enabled."
        )

    primary = interface
    primary_text = ""
    if primary:
        primary_text = f"{primary.name} {primary.description}"
    driver_info = drivers.get("wireless_driver", {}) if isinstance(drivers, dict) else {}
    profile = _find_profile(
        primary_text,
        str(driver_info.get("driver", "")),
        str(driver_info.get("provider", "")),
        str(driver_info.get("radio_types", "")),
    )

    if primary:
        capabilities.append(
            _cap(
                "Windows Wi-Fi",
                "validated",
                f"{primary.description or primary.name} is present; state: "
                f"{primary.state or 'unknown'}.",
                "Windows netsh",
            )
        )
        capabilities.append(
            _cap(
                "Monitor mode",
                "untested" if not profile else "limited",
                (
                    profile.monitor
                    if profile
                    else "No validated monitor-mode capability. Windows client drivers "
                    "do not provide the monitor interface required for 802.11 capture."
                ),
                "Documented driver profile; not validated on this machine",
            )
        )
        capabilities.append(
            _cap(
                "Frame injection",
                "untested" if not profile else "limited",
                (
                    profile.injection
                    if profile
                    else "No validated injection capability. This is not inferred from "
                    "ordinary Wi-Fi connectivity."
                ),
                "Documented driver profile; not validated on this machine",
            )
        )
        capabilities.append(
            _cap(
                "Packet capture",
                "untested",
                "Capture capability must be validated inside the Kali research "
                "environment with the adapter passed through or attached. Windows "
                "discovery alone cannot confirm it.",
                "Requires Kali validation",
            )
        )
        capabilities.append(
            _cap(
                "Linux driver availability",
                "documented" if profile else "unknown",
                profile.linux_driver if profile else "No matching driver profile was found.",
                "Driver knowledge base; verify in Kali with lsmod/lspci",
            )
        )
        capabilities.append(
            _cap(
                "Supported bands",
                "documented" if profile else "unknown",
                profile.bands if profile else "Not determined.",
                "Driver knowledge base",
            )
        )

    if profile and "8822ce" in profile.label.lower():
        warnings.append(
            "The internal Realtek RTL8822CE is a client adapter. Do not assume monitor "
            "mode or frame injection is available under Kali; validate the exact "
            "kernel and driver before planning a capture."
        )
        recommendations.append(
            "If the laboratory workflow requires reliable monitor-mode capture, plan "
            "for a supported USB adapter (for example an AR9271 or a correctly driven "
            "RTL8812AU) after validating Kali compatibility."
        )

    if host.wsl_available:
        warnings.append(
            "WSL2 is available for offline tooling but does not provide direct "
            "monitor-mode access to the internal wireless adapter. Use the Kali VM "
            "with USB passthrough for radio-level research."
        )
    else:
        warnings.append(
            "WSL was not detected. The Kali research environment will need the VM or "
            "SSH transport configured in Settings."
        )

    if host.ram_gb and host.ram_gb < 12:
        recommendations.append(
            "The host has less than 12 GB of RAM. Running Windows, a Kali VM and the "
            "application together is constrained; a 16 GB upgrade is recommended."
        )
    if host.free_disk_gb and host.free_disk_gb < 25:
        warnings.append(
            f"Only {host.free_disk_gb} GB of free disk space is reported. Kali, "
            "captures and evidence need additional headroom."
        )
    if primary and not primary.connected:
        recommendations.append(
            "The primary wireless interface is not connected. This is fine for "
            "passive inventory, but verify driver state before diagnostics."
        )

    if not profile and primary:
        warnings.append(
            "The adapter was not matched to a known compatibility profile. All "
            "monitor-mode, injection and Linux-driver capabilities remain unverified."
        )

    readiness = "Conditional"
    if not primary:
        readiness = "Adapter required"
    elif profile and "limited" in profile.monitor.lower():
        readiness = "Conditional — external adapter may be required"
    elif profile:
        readiness = "Profile available — validation required"

    if not recommendations:
        recommendations.append(
            "Validate the adapter in Kali with `lspci`/`lsusb`, `lsmod` and a short "
            "controlled capture before starting an assessment."
        )

    return HardwareReport(
        host=host,
        adapters=adapters,
        capabilities=capabilities,
        warnings=warnings,
        recommendations=recommendations,
        driver_data=drivers,
        readiness=readiness,
    )


def capability_status_style(status: str) -> str:
    lowered = status.lower()
    if lowered in {"validated", "supported", "documented"}:
        return "good"
    if lowered in {"limited", "conditional", "kernel-dependent"}:
        return "warn"
    if lowered in {"not supported", "unsupported", "blocked"}:
        return "bad"
    return "muted"

