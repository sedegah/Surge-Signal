"""Test fixtures and a self-contained authorised 802.11/WPA capture generator.

No fixture is shipped with the application. The synthetic capture is created in a
temporary directory solely to verify parsing and offline WPA verification.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from pathlib import Path

AP = "AA:BB:CC:11:22:33"
STA = "DE:AD:BE:EF:00:01"
SSID = "SurgeLab-Authorised"
PASSPHRASE = "Correct-Horse-Battery-9!"
ANONCE = bytes(range(32))
SNONCE = bytes(range(32, 64))


def mac(value: str) -> bytes:
    return bytes.fromhex(value.replace(":", ""))


def _ie(element_id: int, value: bytes) -> bytes:
    return bytes([element_id, len(value)]) + value


def _rsn() -> bytes:
    group = b"\x00\x0f\xac\x04"
    pairwise = b"\x00\x0f\xac\x04"
    akm = b"\x00\x0f\xac\x02"
    return (
        struct.pack("<H", 1)
        + group
        + struct.pack("<H", 1)
        + pairwise
        + struct.pack("<H", 1)
        + akm
        + struct.pack("<H", 0)
    )


def beacon_frame() -> bytes:
    header = (
        struct.pack("<H", 0x0080)
        + struct.pack("<H", 0)
        + b"\xff" * 6
        + mac(AP)
        + mac(AP)
        + struct.pack("<H", 0)
    )
    fixed = struct.pack("<Q", 0) + struct.pack("<H", 100) + struct.pack("<H", 0x0431)
    ies = (
        _ie(0, SSID.encode())
        + _ie(1, b"\x82\x84\x8b\x96")
        + _ie(3, b"\x06")
        + _ie(48, _rsn())
        + _ie(221, b"\x00\x50\xf2\x04")
    )
    return header + fixed + ies


def _prf512(key: bytes, label: bytes, data: bytes, length: int = 48) -> bytes:
    result = b""
    counter = 0
    while len(result) < length:
        result += hmac.new(
            key, label + b"\x00" + data + bytes([counter]), hashlib.sha1
        ).digest()
        counter += 1
    return result[:length]


def derive_kck() -> bytes:
    pmk = hashlib.pbkdf2_hmac("sha1", PASSPHRASE.encode(), SSID.encode(), 4096, 32)
    data = (
        min(mac(AP), mac(STA))
        + max(mac(AP), mac(STA))
        + min(ANONCE, SNONCE)
        + max(ANONCE, SNONCE)
    )
    return _prf512(pmk, b"Pairwise key expansion", data)[:16]


def _eapol(key_info: int, nonce: bytes, replay: int, mic: bytes = b"\x00" * 16) -> bytes:
    body = (
        b"\x02"
        + struct.pack(">H", key_info)
        + struct.pack(">H", 16)
        + struct.pack(">Q", replay)
        + nonce
        + b"\x00" * 16
        + b"\x00" * 8
        + b"\x00" * 8
        + mic
        + struct.pack(">H", 0)
    )
    return b"\x02\x03" + struct.pack(">H", len(body)) + body


def msg1() -> bytes:
    return _eapol(0x008A, ANONCE, 1)


def msg2() -> bytes:
    unsigned = _eapol(0x010A, SNONCE, 1)
    kck = derive_kck()
    mic = hmac.new(kck, unsigned, hashlib.sha1).digest()[:16]
    return _eapol(0x010A, SNONCE, 1, mic)


def data_frame(to_ds: bool, source: str, destination: str, payload: bytes) -> bytes:
    flags = 0x01 if to_ds else 0x02
    fc = struct.pack("<H", 0x0008 | (flags << 8))
    if to_ds:
        addr1, addr2, addr3 = mac(AP), mac(STA), mac(AP)
    else:
        addr1, addr2, addr3 = mac(STA), mac(AP), mac(AP)
    header = (
        fc
        + struct.pack("<H", 0)
        + addr1
        + addr2
        + addr3
        + struct.pack("<H", 0)
    )
    return header + b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" + payload


def write_pcap(path: Path, frames: list[tuple[int, bytes]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(
            b"\xd4\xc3\xb2\xa1"
            + struct.pack("<HH", 2, 4)
            + struct.pack("<I", 0)
            + struct.pack("<I", 0)
            + struct.pack("<I", 65535)
            + struct.pack("<I", 105)
        )
        for index, (seconds, frame) in enumerate(frames):
            handle.write(
                struct.pack("<IIII", seconds, index * 1000, len(frame), len(frame))
                + frame
            )
    return path


def make_handshake_capture(path: Path) -> Path:
    frames = [
        (1_700_000_000, beacon_frame()),
        (1_700_000_001, data_frame(False, AP, STA, msg1())),
        (1_700_000_001, data_frame(True, STA, AP, msg2())),
        (1_700_000_003, beacon_frame()),
    ]
    return write_pcap(path, frames)


def make_beacon_capture(path: Path) -> Path:
    return write_pcap(path, [(1_700_000_000, beacon_frame())])

