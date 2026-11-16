"""Controlled offline WPA/WPA2 password auditing and strength evaluation.

The local engine verifies a candidate against a *complete msg1/msg2 handshake
already present* in an authorised lab capture. It never transmits frames, never
touches a live network and never persists a recovered passphrase. The Kali
Aircrack-ng transport is offered as an alternative for large approved wordlists.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from ..wireless.captures import Handshake, extract_handshakes
from ..core.domain import (
    AuditStatus,
    PasswordAuditResult,
    mask_secret,
    normalize_bssid,
)


COMMON_PASSWORDS = {
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "password",
    "password1",
    "password123",
    "qwerty",
    "qwerty123",
    "letmein",
    "admin",
    "welcome",
    "monkey",
    "dragon",
    "abc123",
    "iloveyou",
    "sunshine",
    "princess",
    "football",
    "charlie",
    "aa123456",
    "11111111",
    "00000000",
    "changeme",
    "secret",
    "surge",
    "signal",
}

KEYBOARD_SEQUENCES = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "abcdefghijklmnopqrstuvwxyz",
)


def _has_sequence(lowered: str, minimum: int = 4) -> bool:
    for sequence in KEYBOARD_SEQUENCES:
        for start in range(0, len(sequence) - minimum + 1):
            fragment = sequence[start : start + minimum]
            if fragment in lowered or fragment[::-1] in lowered:
                return True
    return False


def _has_year(lowered: str) -> bool:
    return bool(re.search(r"(19|20)\d{2}", lowered))


def _repeated_fraction(value: str) -> float:
    if not value:
        return 1.0
    return max(value.count(char) for char in set(value)) / len(value)


@dataclass(slots=True)
class PasswordAssessment:
    length: int
    entropy_bits: float
    score: int
    label: str
    policy_compliant: bool
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    estimated_offline_crack_time: str = ""

    @property
    def colour(self) -> str:
        return ["#ff4d6d", "#c2410c", "#8a6d00", "#58c7f3", "#41d6a3"][
            max(0, min(4, self.score))
        ]


def _crack_time(bits: float) -> str:
                                                                  
    guesses = 2 ** max(0.0, bits - 1)
    seconds = guesses / 10_000
    if seconds < 1:
        return "less than a second"
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.0f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.0f} hours"
    if seconds < 31_536_000:
        return f"{seconds / 86400:.0f} days"
    if seconds < 31_536_000 * 1000:
        return f"{seconds / 31_536_000:.1f} years"
    return "centuries at this rate"


def evaluate_password(password: str, minimum_length: int = 12) -> PasswordAssessment:
    """Evaluate strength without transmitting or storing the password."""
    issues: list[str] = []
    recommendations: list[str] = []
    length = len(password)
    lowered = password.lower()

    if not password:
        return PasswordAssessment(
            length=0,
            entropy_bits=0.0,
            score=0,
            label="Empty",
            policy_compliant=False,
            issues=["No password was entered."],
            recommendations=["Enter a candidate to evaluate its strength."],
            estimated_offline_crack_time="immediate",
        )

    pool = 0
    if any(char.islower() for char in password):
        pool += 26
    if any(char.isupper() for char in password):
        pool += 26
    if any(char.isdigit() for char in password):
        pool += 10
    if any(not char.isalnum() for char in password):
        pool += 32
    if any(ord(char) > 127 for char in password):
        pool += 64
    entropy = length * math.log2(max(2, pool))

    if lowered in COMMON_PASSWORDS:
        issues.append("This is a well-known common password.")
        entropy = min(entropy, 12)
    if length < 8:
        issues.append("Shorter than the 8-character WPA-Personal minimum.")
        entropy *= 0.35
    elif length < minimum_length:
        issues.append(f"Shorter than the {minimum_length}-character policy target.")
    if length > 63:
        issues.append("Longer than the 63-character WPA-Personal passphrase limit.")
        recommendations.append("Use a passphrase of 12–63 characters for WPA-Personal.")
    if _has_sequence(lowered):
        issues.append("Contains a predictable keyboard or alphabet sequence.")
        entropy *= 0.55
    if _has_year(lowered):
        issues.append("Contains a calendar year, a common guessing pattern.")
        entropy *= 0.7
    if len(set(password)) <= max(2, length // 3):
        issues.append("Uses a small set of repeated characters.")
        entropy *= 0.45
    if _repeated_fraction(password) > 0.5:
        issues.append("A single character makes up most of the password.")
        entropy *= 0.5
    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains a long repeated-character run.")
        entropy *= 0.75
    if password.strip() != password:
        issues.append("Begins or ends with whitespace, which is error-prone.")
    if not any(char.isdigit() for char in password):
        recommendations.append("Add unpredictable digits if the policy permits.")
    if not any(not char.isalnum() for char in password):
        recommendations.append(
            "Consider a longer passphrase rather than predictable symbol substitution."
        )
    if length < 16 and "passphrase" not in " ".join(issues).lower():
        recommendations.append(
            "Prefer a multi-word passphrase of at least 16 characters for WPA-Personal."
        )
    if not issues:
        recommendations.append("No obvious weakness detected; retain a unique passphrase.")

    policy_compliant = (
        length >= minimum_length
        and any(char.islower() for char in password)
        and any(char.isupper() for char in password)
        and any(char.isdigit() for char in password)
        and any(not char.isalnum() for char in password)
    )
    if not policy_compliant and length >= minimum_length:
        recommendations.append(
            f"Policy target: at least {minimum_length} characters with mixed case, "
            "a digit and a symbol."
        )

    if entropy >= 80 and not any("common" in issue.lower() for issue in issues):
        score = 4
        label = "Strong"
    elif entropy >= 62:
        score = 3
        label = "Good"
    elif entropy >= 45:
        score = 2
        label = "Fair"
    elif entropy >= 28:
        score = 1
        label = "Weak"
    else:
        score = 0
        label = "Very weak"

    if any("common password" in issue for issue in issues):
        score, label = 0, "Very weak"

    return PasswordAssessment(
        length=length,
        entropy_bits=round(entropy, 1),
        score=score,
        label=label,
        policy_compliant=policy_compliant,
        issues=issues,
        recommendations=recommendations,
        estimated_offline_crack_time=_crack_time(entropy),
    )


@dataclass(slots=True)
class WordlistInfo:
    name: str
    path: str
    line_count: int
    sha256: str
    size_bytes: int
    min_length: int = 0
    max_length: int = 0
    skipped_lines: int = 0


def inspect_wordlist(path: Path | str, max_lines: int = 5_000_000) -> WordlistInfo:
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Wordlist not found: {path}")
    size = path.stat().st_size
    if size > 500 * 1024 * 1024:
        raise ValueError("Wordlist exceeds the 500 MB safety limit for this release.")
    digest = hashlib.sha256()
    line_count = 0
    min_length = 0
    max_length = 0
    skipped = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
            handle.seek(0)
            for raw in handle:
                candidate = raw.rstrip(b"\r\n")
                if not candidate:
                    skipped += 1
                    continue
                line_count += 1
                if line_count > max_lines:
                    raise ValueError(
                        f"Wordlist exceeds the {max_lines:,}-line safety limit for this release."
                    )
                length = len(candidate)
                min_length = length if not min_length else min(min_length, length)
                max_length = max(max_length, length)
    except OSError as exc:
        raise ValueError(f"Wordlist could not be read: {exc}") from exc
    return WordlistInfo(
        name=path.name,
        path=str(path.resolve()),
        line_count=line_count,
        sha256=digest.hexdigest(),
        size_bytes=size,
        min_length=min_length,
        max_length=max_length,
        skipped_lines=skipped,
    )


def iter_wordlist(
    path: Path, *, max_candidates: int | None = None, stop_event: threading.Event | None = None
) -> Iterable[tuple[int, str]]:
    tested = 0
    with path.open("rb") as handle:
        for raw in handle:
            if stop_event is not None and stop_event.is_set():
                return
            candidate = raw.rstrip(b"\r\n").decode("utf-8", errors="replace")
            if not candidate:
                continue
            tested += 1
            if max_candidates is not None and tested > max_candidates:
                return
            yield tested, candidate


def _prf512(key: bytes, label: bytes, data: bytes, length: int = 64) -> bytes:
    result = b""
    counter = 0
    while len(result) < length:
        result += hmac.new(
            key, label + b"\x00" + data + bytes([counter]), hashlib.sha1
        ).digest()
        counter += 1
    return result[:length]


def derive_ptk(
    passphrase: str, ssid: str, bssid: str, station: str, anonce: bytes, snonce: bytes
) -> bytes:
    pmk = hashlib.pbkdf2_hmac(
        "sha1", passphrase.encode("utf-8"), ssid.encode("utf-8"), 4096, 32
    )
    ap = bytes.fromhex(normalize_bssid(bssid).replace(":", ""))
    client = bytes.fromhex(normalize_bssid(station).replace(":", ""))
    data = (
        min(ap, client)
        + max(ap, client)
        + min(anonce, snonce)
        + max(anonce, snonce)
    )
    return _prf512(pmk, b"Pairwise key expansion", data, 48)


def verify_handshake_candidate(passphrase: str, handshake: Handshake) -> bool:
    if not handshake.complete or len(handshake.eapol) < 99 or len(handshake.mic) != 16:
        return False
    try:
        ptk = derive_ptk(
            passphrase,
            handshake.ssid,
            handshake.bssid,
            handshake.station,
            handshake.anonce,
            handshake.snonce,
        )
    except (ValueError, UnicodeError):
        return False
    kck = ptk[:16]
    eapol = bytearray(handshake.eapol)
    eapol[81:97] = b"\x00" * 16
    computed = hmac.new(kck, bytes(eapol), hashlib.sha1).digest()[:16]
    return hmac.compare_digest(computed, handshake.mic)


class LocalWpaAuditor:
    """Pure-Python offline verifier for complete WPA2-PSK handshakes."""

    def __init__(
        self,
        progress: Callable[[int, int], None] | None = None,
        stop_event: threading.Event | None = None,
    ):
        self.progress = progress
        self.stop_event = stop_event or threading.Event()

    def audit(
        self,
        capture_path: Path | str,
        wordlist_path: Path | str,
        bssid: str = "",
        *,
        max_candidates: int = 250_000,
    ) -> PasswordAuditResult:
        started = time.monotonic()
        capture = Path(capture_path)
        wordlist = Path(wordlist_path)
        if not capture.is_file():
            return self._failed("Capture file not found.", started, "local")
        if not wordlist.is_file():
            return self._failed("Wordlist file not found.", started, "local")
        try:
            handshakes = extract_handshakes(capture)
        except Exception as exc:
            return self._failed(f"Capture could not be read: {exc}", started, "local")
        target = normalize_bssid(bssid)
        valid = [
            item
            for item in handshakes
            if item.complete and (not target or item.bssid == target)
        ]
        if not valid:
            return self._failed(
                "No complete WPA msg1/msg2 handshake was found for the selected BSSID. "
                "Use a capture from the authorised lab that contains the full handshake, "
                "or use the Aircrack-ng transport if configured.",
                started,
                "local",
            )
        handshake = valid[0]
        tested = 0
        try:
            for tested, candidate in iter_wordlist(
                wordlist,
                max_candidates=max_candidates,
                stop_event=self.stop_event,
            ):
                if self.stop_event.is_set():
                    return PasswordAuditResult(
                        status=AuditStatus.CANCELLED,
                        method="offline-wpa2",
                        candidates_tested=tested,
                        elapsed_seconds=round(time.monotonic() - started, 2),
                        detail="Audit cancelled by the operator.",
                        engine="local",
                    )
                if self.progress and (tested % 25 == 0 or tested == 1):
                    self.progress(tested, max_candidates)
                if verify_handshake_candidate(candidate, handshake):
                    score = evaluate_password(candidate).score
                    return PasswordAuditResult(
                        status=AuditStatus.COMPLETED,
                        method="offline-wpa2",
                        candidates_tested=tested,
                        recovered=True,
                        matched_index=tested,
                        masked_secret=mask_secret(candidate),
                        elapsed_seconds=round(time.monotonic() - started, 2),
                        detail=(
                            f"Authorised audit recovered a match for {handshake.ssid or handshake.bssid}. "
                            "The passphrase is masked and was not written to the database."
                        ),
                        engine="local",
                        strength_score=score,
                    )
        except (OSError, ValueError) as exc:
            return self._failed(f"Wordlist could not be read: {exc}", started, "local")
        return PasswordAuditResult(
            status=AuditStatus.COMPLETED,
            method="offline-wpa2",
            candidates_tested=tested,
            recovered=False,
            elapsed_seconds=round(time.monotonic() - started, 2),
            detail=(
                "No candidate matched. If expected, review the wordlist and confirm "
                "the capture contains a complete handshake for the target BSSID."
            ),
            engine="local",
        )

    @staticmethod
    def _failed(detail: str, started: float, engine: str) -> PasswordAuditResult:
        return PasswordAuditResult(
            status=AuditStatus.FAILED,
            method="offline-wpa2",
            elapsed_seconds=round(time.monotonic() - started, 2),
            detail=detail,
            engine=engine,
        )


def build_aircrack_argv(
    aircrack_program: str, wordlist_path: str, capture_path: str, bssid: str
) -> list[str]:
    """Build an offline-only Aircrack-ng invocation.

    BSSID is optional; when supplied it narrows the target. No `-l` output file
    is used, so a recovered key cannot be written to disk by this layer.
    """
    argv = [aircrack_program, "-w", wordlist_path]
    target = normalize_bssid(bssid)
    if target:
        argv += ["-b", target]
    argv.append(capture_path)
    return argv


def parse_aircrack_output(output: str) -> tuple[bool, str, str]:
    """Return (recovered, masked_secret, detail) from Aircrack-ng stdout."""
    recovered, candidate, detail = parse_aircrack_secret(output)
    if recovered:
        return True, mask_secret(candidate), detail
    return False, "", detail


def parse_aircrack_secret(output: str) -> tuple[bool, str, str]:
    """Parse a recovered value for one-time in-memory terminal display.

    Callers must not persist the returned value. The normal service layer uses
    :func:`parse_aircrack_output`, which masks it immediately.
    """
    match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", output, re.IGNORECASE | re.DOTALL)
    if match:
        candidate = match.group(1).strip()
        return True, candidate, "Aircrack-ng recovered a key from the capture."
    if "Passphrase not in dictionary" in output:
        return False, "", "The passphrase was not present in the supplied wordlist."
    if "No valid WPA handshake" in output:
        return False, "", "No valid WPA handshake was available in the capture."
    if "Packets contained no EAPOL data" in output:
        return False, "", "The capture contains no usable EAPOL handshake data."
    if "No networks found" in output:
        return False, "", "Aircrack-ng found no usable network data in the capture."
    return False, "", "Aircrack-ng completed without recovering a key."


def line_count_quick(path: Path, limit: int = 5_000_000) -> int:
    return inspect_wordlist(path, max_lines=limit).line_count


