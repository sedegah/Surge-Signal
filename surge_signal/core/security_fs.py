"""Filesystem hardening for locally stored assessment evidence.

Windows ACLs are tightened to the current user, SYSTEM and Administrators. This
is not encryption: it limits casual access by other local accounts. Organisations
that require encryption at rest should enable BitLocker/EFS or a managed DLP
control.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


def _run_icacls(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["icacls", *args],
        capture_output=True,
        check=False,
        creationflags=NO_WINDOW,
    )


def harden_data_directory(path: Path) -> tuple[bool, str]:
    """Apply a restrictive per-user ACL to the application data directory.

    Only the root directory's inheritance is changed. The inheritable grants then
    flow to existing and future children. Applying ``/T`` with
    ``/inheritance:r`` would remove inherited access from every file and leave
    files with no usable ACE, so that is deliberately avoided.
    """
    if sys.platform != "win32":
        return False, "Windows ACL hardening is only applicable on Windows."
    marker = path / ".acl-hardened-v2"
    if marker.exists():
        return True, "Application data ACL was already hardened."
    user = os.environ.get("USERNAME", "")
    domain = os.environ.get("USERDOMAIN", "")
    principals = []
    if user:
        principals.append(f"{user}:(OI)(CI)F")
        if domain:
            principals.append(f"{domain}\\{user}:(OI)(CI)F")
    principals.extend(["*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])
    try:
        inherited = _run_icacls(str(path), "/inheritance:r", "/C")
        if inherited.returncode != 0:
            message = inherited.stderr.decode("utf-8", errors="replace").strip()
            return False, f"ACL inheritance could not be removed: {message[:300]}"
        grants = _run_icacls(str(path), "/grant:r", *principals, "/C")
    except OSError as exc:
        return False, f"ACL hardening could not run: {exc}"
    if grants.returncode != 0:
        message = grants.stderr.decode("utf-8", errors="replace").strip()
        return False, f"ACL hardening returned {grants.returncode}: {message[:300]}"
    try:
        marker.write_text(
            "Restricted to the current user, SYSTEM and Administrators.\n",
            encoding="utf-8",
        )
    except OSError:
        pass
    return True, "Application data directory permissions restricted to this user."

