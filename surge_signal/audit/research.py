"""Connector to the Kali Linux research environment.

Transports:
* `native` - local Linux/Kali tools when SURGE Signal runs on Linux.
* `wsl`    - WSL2 for offline tooling (not monitor-mode capture).
* `ssh`    - key-authenticated SSH to a Kali VM or host.
* `manual` - shared-folder exchange for air-gapped workflows.

Passwords for sudo are written only to the child process's stdin. They are
never placed in argv, environment variables, logs or the database.
"""

from __future__ import annotations

import json
import locale
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from ..core.config import AppPaths
from ..core.safety import SafetyError, redact_argv, validate_argv


class ResearchError(RuntimeError):
    pass


NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
CREATE_NO_WINDOW = NO_WINDOW


class SudoAuthError(ResearchError):
    pass


@dataclass(slots=True)
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float = 0.0
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def summary(self) -> str:
        return (
            f"`{redact_argv(self.argv)}` exited {self.returncode} in "
            f"{self.duration_seconds:.1f}s"
        )


@dataclass(slots=True)
class ResearchStatus:
    mode: str
    available: bool
    environment: str = ""
    username: str = ""
    kernel: str = ""
    detail: str = ""
    aircrack: bool = False
    tshark: bool = False
    tools: dict[str, bool] = field(default_factory=dict)
    checked_at: float = field(default_factory=time.time)
    guidance: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        if self.available and self.aircrack:
            return "Research environment ready"
        if self.available:
            return "Environment reachable — tools missing"
        return "Research environment unavailable"


@dataclass(slots=True)
class ToolSetupResult:
    missing: list[str]
    already_installed: bool
    check: CommandResult | None = None
    update: CommandResult | None = None
    install: CommandResult | None = None


def _decode(data: bytes) -> str:
    if not data:
        return ""
    if data.count(b"\x00") > len(data) // 4:
        try:
            return data.decode("utf-16-le", errors="replace").replace("\x00", "")
        except UnicodeDecodeError:
            pass
    for encoding in ("utf-8", locale.getpreferredencoding(False), "cp1252"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


class ResearchConnector:
    def __init__(self, settings: object, paths: AppPaths, logger: object | None = None):
        self.settings = settings
        self.paths = paths
        self.logger = logger

    @property
    def mode(self) -> str:
        default = "native" if sys.platform != "win32" else "wsl"
        return str(self.settings.get("research_mode", default))

    @property
    def wsl_exe(self) -> str:
        return shutil.which("wsl.exe") or shutil.which("wsl") or ""

    def _distro(self) -> str:
        return str(self.settings.get("wsl_distro", "kali-linux")).strip()

    def to_linux_path(self, local_path: Path | str) -> str:
        path = Path(local_path)
        if self.mode == "wsl":
            drive = path.drive.rstrip(":").lower()
            parts = list(path.parts)
            if drive and len(parts) >= 2:
                tail = "/".join(part for part in parts[1:] if part not in {"\\", "/"})
                return f"/mnt/{drive}/{tail}".replace("\\", "/")
            return str(path).replace("\\", "/")
        if self.mode == "ssh":
            linux_share = str(self.settings.get("kali_linux_share", "/mnt/surge"))
            windows_share = Path(str(self.settings.get("kali_share", "")))
            try:
                relative = path.resolve().relative_to(windows_share.resolve())
                return f"{linux_share.rstrip('/')}/{relative.as_posix()}"
            except (ValueError, OSError):
                return str(path).replace("\\", "/")
        return str(path)

    def _base_argv(self, argv: Sequence[str]) -> list[str]:
        mode = self.mode
        if mode == "native":
            return list(argv)
        if mode == "wsl":
            if not self.wsl_exe:
                raise ResearchError(
                    "WSL was not found. Install or enable WSL2, or switch the "
                    "research transport to SSH in Settings."
                )
            distro = self._distro()
            base = [self.wsl_exe]
            if distro:
                base += ["-d", distro]
            return base + ["--", *argv]
        if mode == "ssh":
            ssh = shutil.which("ssh")
            if not ssh:
                raise ResearchError("The OpenSSH client was not found.")
            host = str(self.settings.get("ssh_host", "")).strip()
            user = str(self.settings.get("ssh_user", "")).strip()
            if not host:
                raise ResearchError("No SSH host is configured in Settings.")
            target = f"{user}@{host}" if user else host
            return [
                ssh,
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=8",
                target,
                shlex.join(argv),
            ]
        raise ResearchError(
            "Manual exchange mode is selected. Use the shared folder workflow, or "
            "choose WSL/SSH in Settings for automated tool execution."
        )

    def _run(
        self,
        argv: Sequence[str],
        *,
        stdin_data: bytes | None = None,
        timeout: int = 120,
        allow_sudo: bool = False,
    ) -> CommandResult:
        validate_argv(argv, allow_sudo=allow_sudo)
        full = self._base_argv(argv)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                full,
                input=stdin_data,
                capture_output=True,
                timeout=timeout,
                check=False,
                creationflags=NO_WINDOW,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                argv=list(argv),
                returncode=124,
                stdout=_decode(exc.stdout or b""),
                stderr="The research command timed out.",
                duration_seconds=round(time.monotonic() - started, 2),
                timed_out=True,
            )
        except FileNotFoundError as exc:
            raise ResearchError(f"Research executable not found: {exc}") from exc
        return CommandResult(
            argv=list(argv),
            returncode=completed.returncode,
            stdout=_decode(completed.stdout),
            stderr=_decode(completed.stderr),
            duration_seconds=round(time.monotonic() - started, 2),
        )

    def run(self, argv: Sequence[str], timeout: int = 120) -> CommandResult:
        if self.mode == "manual":
            raise ResearchError(
                "Manual exchange mode does not execute commands. Switch to WSL or SSH "
                "for automated offline tooling."
            )
        return self._run(argv, timeout=timeout)

    def run_privileged(
        self,
        argv: Sequence[str],
        password: str,
        timeout: int | None = None,
    ) -> CommandResult:
        """Run an approved command through sudo using stdin-only authentication.

        If the configured sudo policy is NOPASSWD, `password` may be empty. A
        password is never passed in argv or environment variables.
        """
        if not password:
            raise SudoAuthError("A Linux password is required for this privileged operation.")
        if self.mode == "manual":
            raise ResearchError("Privileged execution is unavailable in manual mode.")
        if self.mode == "ssh":
            remote = ["sudo", "-S", "-p", "", "--", *argv]
            validate_argv(remote, allow_sudo=True)
            ssh = shutil.which("ssh")
            host = str(self.settings.get("ssh_host", "")).strip()
            user = str(self.settings.get("ssh_user", "")).strip()
            target = f"{user}@{host}" if user else host
            start = time.monotonic()
            completed = subprocess.run(
                [
                    ssh or "ssh",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ConnectTimeout=8",
                    target,
                    shlex.join(remote),
                ],
                input=(password + "\n").encode("utf-8"),
                capture_output=True,
                timeout=timeout or int(self.settings.get_int("sudo_timeout_seconds", 120)),
                check=False,
                creationflags=NO_WINDOW,
            )
            result = CommandResult(
                argv=list(argv),
                returncode=completed.returncode,
                stdout=_decode(completed.stdout),
                stderr=_decode(completed.stderr),
                duration_seconds=round(time.monotonic() - start, 2),
            )
        else:
            sudo_argv = ["sudo", "-S", "-p", "", "--", *argv]
            validate_argv(sudo_argv, allow_sudo=True)
            result = self._run(
                sudo_argv,
                stdin_data=(password + "\n").encode("utf-8"),
                timeout=timeout or int(self.settings.get_int("sudo_timeout_seconds", 120)),
                allow_sudo=True,
            )
        if result.returncode != 0:
            stderr_lower = result.stderr.lower()
            if "incorrect password" in stderr_lower or "sorry, try again" in stderr_lower:
                raise SudoAuthError(
                    "Linux authentication failed. Check the account password and try again."
                )
            if "not in the sudoers" in stderr_lower or "not allowed" in stderr_lower:
                raise SudoAuthError(
                    "This Linux account is not permitted to run sudo for the requested operation."
                )
        return result

    def test_connection(self) -> ResearchStatus:
        mode = self.mode
        status = ResearchStatus(mode=mode, available=False)
        if mode == "manual":
            status.available = True
            status.detail = (
                "Manual shared-folder mode is active. Automated command execution is "
                "disabled by design."
            )
            status.guidance.append(
                "Place approved captures and wordlists in the configured exchange "
                "folder, then run offline analysis inside Kali."
            )
            return status
        if mode == "native" and sys.platform == "win32":
            status.detail = "Native Linux mode is only available when running on Linux."
            status.guidance.append("Use WSL or SSH on Windows, or install the Linux build.")
            return status
        if mode == "wsl" and not self.wsl_exe:
            status.detail = "WSL was not detected on this Windows host."
            status.guidance.append("Install WSL2 and a Kali Linux distribution.")
            return status
        if mode == "ssh" and not str(self.settings.get("ssh_host", "")).strip():
            status.detail = "No SSH host is configured."
            status.guidance.append("Set the Kali VM/host address and SSH user in Settings.")
            return status

        try:
            result = self.run(["uname", "-r"], timeout=20)
            if result.ok:
                status.kernel = result.stdout.strip().splitlines()[-1] if result.stdout else ""
            user = self.run(["id", "-un"], timeout=20)
            if user.ok:
                status.username = user.stdout.strip().splitlines()[-1] if user.stdout else ""
            env = self.run(["cat", "/etc/os-release"], timeout=20)
            if env.ok:
                for line in env.stdout.splitlines():
                    if line.startswith("PRETTY_NAME="):
                        status.environment = line.split("=", 1)[1].strip().strip('"')
            tools = self.run(["which", "aircrack-ng", "tshark", "capinfos", "hcxpcapngtool"], timeout=25)
            found: dict[str, bool] = {
                name: False
                for name in ("aircrack-ng", "tshark", "capinfos", "hcxpcapngtool")
            }
            for line in tools.stdout.splitlines():
                text = line.strip()
                if not text or "not found" in text.lower():
                    continue
                name = Path(text).name
                if name in found and text.startswith("/"):
                    found[name] = True
            status.tools = found
            status.aircrack = "aircrack-ng" in found
            status.tshark = "tshark" in found
            status.available = result.ok
            if not result.ok:
                status.detail = (
                    result.stderr.strip()
                    or "The research environment could not be reached."
                )
            elif not status.aircrack:
                status.detail = "Kali is reachable but Aircrack-ng is not installed."
                status.guidance.append("Install Aircrack-ng inside the Kali environment.")
            else:
                status.detail = "Kali research environment is reachable."
            return status
        except (ResearchError, SudoAuthError, SafetyError) as exc:
            status.detail = str(exc)
            return status

    def run_aircrack(
        self,
        wordlist: Path | str,
        capture: Path | str,
        bssid: str,
        *,
        timeout: int = 600,
    ) -> CommandResult:
        from .password_audit import build_aircrack_argv

        program = str(self.settings.get("aircrack_path", "aircrack-ng")).strip()
        argv = build_aircrack_argv(
            program,
            self.to_linux_path(wordlist),
            self.to_linux_path(capture),
            bssid,
        )
        validate_argv(argv)
        return self.run(argv, timeout=timeout)

    def run_aircrack_privileged(
        self,
        wordlist: Path | str,
        capture: Path | str,
        bssid: str,
        password: str,
        *,
        timeout: int = 900,
    ) -> CommandResult:
        """Run Aircrack-ng through sudo after validating the Kali password.

        An empty BSSID lets Aircrack choose the first network in the capture.
        """
        from .password_audit import build_aircrack_argv

        program = str(self.settings.get("aircrack_path", "aircrack-ng")).strip()
        argv = build_aircrack_argv(
            program,
            self.to_linux_path(wordlist),
            self.to_linux_path(capture),
            bssid,
        )
        validate_argv(argv)
        return self.run_privileged(argv, password, timeout=timeout)

    def install_kali_tools(self, password: str) -> tuple[CommandResult, CommandResult]:
        """Install the guided Aircrack-ng lab toolkit through sudo.

        The package list is fixed by the application, not by user input.
        """
        update = self.run_privileged(
            ["apt-get", "update"],
            password,
            timeout=900,
        )
        install = self.run_privileged(
            [
                "env",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "install",
                "-y",
                "aircrack-ng",
                "iw",
                "wireless-tools",
                "wordlists",
                "tshark",
            ],
            password,
            timeout=900,
        )
        return update, install

    def ensure_kali_tools(self, password: str) -> ToolSetupResult:
        """Check once and install only missing tools.

        Re-running this is cheap when everything is already present; it avoids
        an unconditional apt update/install on every session.
        """
        required = [
            "aircrack-ng",
            "airmon-ng",
            "airodump-ng",
            "iw",
            "timeout",
            "tshark",
        ]
        check = self.run(["which", *required], timeout=30)
        found = {
            Path(line.strip()).name
            for line in check.stdout.splitlines()
            if line.strip().startswith("/")
        }
        missing = [tool for tool in required if tool not in found]
        if not missing:
            return ToolSetupResult(
                missing=[],
                already_installed=True,
                check=check,
            )
        packages = []
        for tool in missing:
            if tool in {"aircrack-ng", "airmon-ng", "airodump-ng"}:
                packages.append("aircrack-ng")
            elif tool == "iw":
                packages.append("iw")
            elif tool == "timeout":
                packages.append("coreutils")
            elif tool == "tshark":
                packages.append("tshark")
        packages = list(dict.fromkeys(packages))
        update = self.run_privileged(["apt-get", "update"], password, timeout=900)
        install = self.run_privileged(
            [
                "env",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "install",
                "-y",
                *packages,
                "wireless-tools",
                "wordlists",
            ],
            password,
            timeout=900,
        )
        return ToolSetupResult(
            missing=missing,
            already_installed=False,
            check=check,
            update=update,
            install=install,
        )

    def export_exchange_manifest(
        self, name: str, files: Iterable[Path], metadata: dict[str, object]
    ) -> Path:
        outbox = self.paths.exchange / "outbox"
        outbox.mkdir(parents=True, exist_ok=True)
        manifest = {
            "name": name,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "files": [
                {
                    "name": Path(item).name,
                    "size": Path(item).stat().st_size if Path(item).is_file() else 0,
                }
                for item in files
            ],
            "metadata": metadata,
        }
        path = outbox / f"{name}.json"
        path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return path

