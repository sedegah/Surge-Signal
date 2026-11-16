"""Capture import, metadata inspection and 802.11 security analysis.

The inspector understands classic PCAP and PCAPNG containers, Radiotap and raw
802.11 link types, beacon/probe-response information elements and WPA EAPOL key
frames. It intentionally performs no decryption or active network operations.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from ..core.domain import normalize_bssid


class CaptureError(RuntimeError):
    pass


LINK_TYPES = {
    105: "IEEE 802.11",
    127: "IEEE 802.11 + Radiotap",
    119: "Prism",
    163: "AVS",
    1: "Ethernet",
    276: "PPI",
}

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}


@dataclass(slots=True)
class RawPacket:
    timestamp: datetime | None
    link_type: int
    data: bytes
    original_length: int


@dataclass(slots=True)
class EapolKey:
    message: int
    nonce: bytes
    mic: bytes
    key_info: int
    replay_counter: int
    key_version: int
    raw: bytes
    mic_offset: int = 81


@dataclass(slots=True)
class Handshake:
    ssid: str
    bssid: str
    station: str
    anonce: bytes
    snonce: bytes
    eapol: bytes
    mic: bytes
    key_version: int = 2
    pmkid: str = ""
    complete: bool = False

    def public_dict(self) -> dict[str, Any]:
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "station": self.station,
            "key_version": self.key_version,
            "complete": self.complete,
            "pmkid": self.pmkid,
            "anonce_present": bool(self.anonce),
            "snonce_present": bool(self.snonce),
        }


@dataclass(slots=True)
class Parsed80211:
    frame_type: int
    subtype: int
    bssid: str = ""
    source: str = ""
    destination: str = ""
    ssid: str = ""
    channel: int | None = None
    rsn: bool = False
    wpa: bool = False
    wps: bool = False
    pmf: str = "Unknown"
    authentication: str = ""
    encryption: str = ""
    standards: list[str] = field(default_factory=list)
    eapol: EapolKey | None = None
    pmkid: str = ""


@dataclass(slots=True)
class CaptureAnalysis:
    path: str
    filename: str
    format: str
    size_bytes: int
    sha256: str
    packet_count: int = 0
    start_ts: str = ""
    end_ts: str = ""
    link_type: int = 0
    link_type_name: str = ""
    integrity: str = "unknown"
    ssid: str = ""
    bssid: str = ""
    channel: int | None = None
    authentication: str = ""
    encryption: str = ""
    pmf: str = "Unknown"
    wps: str = "Unknown"
    handshakes: list[Handshake] = field(default_factory=list)
    beacon_count: int = 0
    eapol_count: int = 0
    pmkid_count: int = 0
    truncated: bool = False
    notes: list[str] = field(default_factory=list)
    inspected_packets: int = 0

    def metadata(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "packet_count": self.packet_count,
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "link_type": self.link_type,
            "link_type_name": self.link_type_name,
            "integrity": self.integrity,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "channel": self.channel,
            "authentication": self.authentication,
            "encryption": self.encryption,
            "pmf": self.pmf,
            "wps": self.wps,
            "beacon_count": self.beacon_count,
            "eapol_count": self.eapol_count,
            "pmkid_count": self.pmkid_count,
            "handshakes": [item.public_dict() for item in self.handshakes],
            "truncated": self.truncated,
            "inspected_packets": self.inspected_packets,
            "notes": list(self.notes),
        }


def _iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).replace(microsecond=0).isoformat()
    except (OverflowError, OSError, ValueError):
        return ""


class CaptureReader:
    """Streaming PCAP/PCAPNG reader with format and integrity diagnostics."""

    def __init__(self, path: Path, *, max_packet_size: int = 16 * 1024 * 1024):
        self.path = Path(path)
        self.max_packet_size = max_packet_size
        self.format = "unknown"
        self.link_type = 0
        self.endian = "<"
        self.nanoseconds = False
        self.packet_count = 0
        self.truncated = False
        self.notes: list[str] = []
        self._stream: BinaryIO | None = None
        self._gzip = False
        self._interfaces: list[dict[str, Any]] = []
        self._pcap_header: tuple[int, int, int] | None = None

    def __enter__(self) -> "CaptureReader":
        raw = self.path.open("rb")
        magic = raw.read(4)
        raw.seek(0)
        if magic[:2] == b"\x1f\x8b":
            self._stream = gzip.GzipFile(fileobj=raw, mode="rb")
            self._gzip = True
            header = self._stream.read(4)
            self._stream.seek(0)
        else:
            self._stream = raw
            header = magic
        if header in PCAP_MAGICS:
            self.format = "pcap"
            self._read_pcap_header()
        elif header == b"\x0a\x0d\x0d\x0a":
            self.format = "pcapng"
            self._read_pcapng_header()
        else:
            raw.close()
            raise CaptureError(
                "Unrecognised capture format. Supported formats are PCAP and PCAPNG "
                "(optionally gzip-compressed)."
            )
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        if self._stream is not None:
            try:
                self._stream.close()
            finally:
                self._stream = None

    def _read_pcap_header(self) -> None:
        assert self._stream is not None
        header = self._stream.read(24)
        if len(header) != 24:
            raise CaptureError("Truncated PCAP global header.")
        magic = header[:4]
        self.endian, self.nanoseconds = PCAP_MAGICS[magic]
        major, minor = struct.unpack(self.endian + "HH", header[4:8])
        snaplen, link_type = struct.unpack(self.endian + "II", header[16:24])
        self._pcap_header = (major, minor, snaplen)
        self.link_type = link_type
        if link_type not in LINK_TYPES:
            self.notes.append(f"Link type {link_type} is not an 802.11 capture type.")

    def _read_pcapng_header(self) -> None:
        assert self._stream is not None
        header = self._stream.read(12)
        if len(header) < 12:
            raise CaptureError("Truncated PCAPNG section header.")
        block_type, block_len = struct.unpack("<II", header[:8])
        if block_type != 0x0A0D0D0A:
            raise CaptureError("Invalid PCAPNG section header.")
        if block_len < 28 or block_len > 16 * 1024 * 1024:
            raise CaptureError("Invalid PCAPNG section length.")
        rest = self._stream.read(block_len - 12)
        if len(rest) != block_len - 12:
            raise CaptureError("Truncated PCAPNG section header.")
        bom = rest[:4]
        if bom == b"\x4d\x3c\x2b\x1a":
            self.endian = "<"
        elif bom == b"\x1a\x2b\x3c\x4d":
            self.endian = ">"
        else:
            raise CaptureError("Invalid PCAPNG byte-order magic.")
        trailing = struct.unpack(self.endian + "I", rest[-4:])[0]
        if trailing != block_len:
            self.truncated = True
            self.notes.append("PCAPNG section header length mismatch.")

    def _iter_pcap(self) -> Iterator[RawPacket]:
        assert self._stream is not None and self._pcap_header is not None
        while True:
            header = self._stream.read(16)
            if not header:
                break
            if len(header) < 16:
                self.truncated = True
                self.notes.append("Truncated packet record header at end of file.")
                break
            ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
                self.endian + "IIII", header
            )
            if incl_len > self.max_packet_size or incl_len > 64 * 1024 * 1024:
                self.truncated = True
                self.notes.append("Implausible packet length; remaining data skipped.")
                break
            data = self._stream.read(incl_len)
            if len(data) < incl_len:
                self.truncated = True
                self.notes.append("Truncated packet payload at end of file.")
                break
            divisor = 1_000_000_000 if self.nanoseconds else 1_000_000
            timestamp = ts_sec + (ts_frac / divisor)
            self.packet_count += 1
            yield RawPacket(
                timestamp=datetime.fromtimestamp(timestamp, tz=timezone.utc),
                link_type=self.link_type,
                data=data,
                original_length=orig_len,
            )

    def _iter_pcapng(self) -> Iterator[RawPacket]:
        assert self._stream is not None
        while True:
            header = self._stream.read(8)
            if not header:
                break
            if len(header) < 8:
                self.truncated = True
                self.notes.append("Truncated PCAPNG block header.")
                break
            block_type, block_len = struct.unpack(self.endian + "II", header)
            if block_len < 12 or block_len > 64 * 1024 * 1024:
                self.truncated = True
                self.notes.append("Invalid PCAPNG block length; parsing stopped.")
                break
            body = self._stream.read(block_len - 8)
            if len(body) != block_len - 8:
                self.truncated = True
                self.notes.append("Truncated PCAPNG block.")
                break
            if block_len >= 16:
                trailing = struct.unpack(self.endian + "I", body[-4:])[0]
                if trailing != block_len:
                    self.truncated = True
                    self.notes.append("PCAPNG block length mismatch.")
                    break
            payload = body[:-4] if block_len >= 16 else b""

            if block_type == 0x0A0D0D0A:
                if len(payload) < 16:
                    continue
                if payload[4:8] == b"\x4d\x3c\x2b\x1a":
                    self.endian = "<"
                elif payload[4:8] == b"\x1a\x2b\x3c\x4d":
                    self.endian = ">"
                self._interfaces = []
                continue

            if block_type == 1:                               
                if len(payload) < 8:
                    continue
                link_type = struct.unpack(self.endian + "H", payload[:2])[0]
                self.link_type = link_type
                interface = {"link_type": link_type, "ts_units": 1_000_000.0}
                                                                            
                offset = 8
                while offset + 4 <= len(payload):
                    code, length = struct.unpack(
                        self.endian + "HH", payload[offset : offset + 4]
                    )
                    if code == 0:
                        break
                    value = payload[offset + 4 : offset + 4 + length]
                    if code == 9 and value:
                        raw = value[0]
                        if raw & 0x80:
                            interface["ts_units"] = float(2 ** (raw & 0x7F))
                        else:
                            interface["ts_units"] = float(10**raw)
                    offset += 4 + ((length + 3) // 4) * 4
                self._interfaces.append(interface)
                continue

            if block_type == 6:                         
                if len(payload) < 20:
                    continue
                interface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                    self.endian + "IIIII", payload[:20]
                )
                if cap_len > self.max_packet_size:
                    self.truncated = True
                    self.notes.append("PCAPNG packet length exceeds safety limit.")
                    continue
                data = payload[20 : 20 + cap_len]
                if len(data) < cap_len:
                    self.truncated = True
                    continue
                interface = (
                    self._interfaces[interface_id]
                    if interface_id < len(self._interfaces)
                    else {"link_type": self.link_type, "ts_units": 1_000_000.0}
                )
                ts = ((ts_high << 32) | ts_low) / float(interface["ts_units"])
                self.packet_count += 1
                yield RawPacket(
                    timestamp=datetime.fromtimestamp(ts, tz=timezone.utc),
                    link_type=int(interface["link_type"]),
                    data=data,
                    original_length=orig_len,
                )
            elif block_type == 3:                       
                if len(payload) < 4:
                    continue
                orig_len = struct.unpack(self.endian + "I", payload[:4])[0]
                data = payload[4:]
                self.packet_count += 1
                yield RawPacket(
                    timestamp=None,
                    link_type=self.link_type,
                    data=data,
                    original_length=orig_len,
                )

    def packets(self) -> Iterator[RawPacket]:
        if self.format == "pcap":
            yield from self._iter_pcap()
        elif self.format == "pcapng":
            yield from self._iter_pcapng()
        else:
            raise CaptureError("Capture reader was not opened correctly.")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _mac(data: bytes) -> str:
    if len(data) < 6:
        return ""
    return ":".join(f"{byte:02X}" for byte in data[:6])


def _skip_radiotap(data: bytes) -> bytes | None:
    if len(data) < 8:
        return None
    version, pad, length = struct.unpack("<BBH", data[:4])
    if version != 0 or length < 8 or length > len(data):
        return None
    return data[length:]


def _parse_ies(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ssid": "",
        "channel": None,
        "rsn": False,
        "wpa": False,
        "wps": False,
        "pmf": "Unknown",
        "authentication": "",
        "encryption": "",
        "standards": set(),
    }
    offset = 0
    while offset + 2 <= len(data):
        element_id = data[offset]
        length = data[offset + 1]
        value = data[offset + 2 : offset + 2 + length]
        if len(value) < length:
            break
        offset += 2 + length
        if element_id == 0:
            result["ssid"] = value.decode("utf-8", errors="replace")
        elif element_id == 3 and length >= 1:
            result["channel"] = value[0]
        elif element_id == 45:
            result["standards"].add("802.11n")
        elif element_id == 191:
            result["standards"].add("802.11ac")
        elif element_id == 255 and length >= 3:
            ext_id = value[0]
            if ext_id == 36:
                result["standards"].add("802.11ax")
            elif ext_id == 108:
                result["standards"].add("802.11be")
        elif element_id == 221 and length >= 4:
            oui = value[:3]
            oui_type = value[3]
            if oui == b"\x00\x50\xf2" and oui_type == 1:
                result["wpa"] = True
                result["authentication"] = "WPA-Personal"
                result["encryption"] = "TKIP"
            elif oui == b"\x00\x50\xf2" and oui_type == 4:
                result["wps"] = True
        elif element_id == 48:
            result["rsn"] = True
            _parse_rsn(value, result)
    if result["wps"]:
        result["wps"] = "Enabled"
    else:
        result["wps"] = "Not advertised"
    if not result["rsn"] and not result["wpa"]:
        result["authentication"] = result["authentication"] or "Open"
        result["encryption"] = result["encryption"] or "None"
        result["pmf"] = "Not applicable"
    standards = sorted(result["standards"])
    if result["channel"] and not standards:
        standards = ["802.11b/g" if result["channel"] <= 14 else "802.11a"]
    result["standards"] = standards
    return result


def _parse_rsn(value: bytes, result: dict[str, Any]) -> None:
    if len(value) < 2:
        return
    version = struct.unpack("<H", value[:2])[0]
    if version != 1:
        return
    offset = 2
    group_cipher = b""
    pairwise: list[bytes] = []
    akms: list[bytes] = []
    capabilities = 0
    try:
        if offset + 4 <= len(value):
            group_cipher = value[offset : offset + 4]
            offset += 4
        if offset + 2 <= len(value):
            count = struct.unpack("<H", value[offset : offset + 2])[0]
            offset += 2
            for _ in range(count):
                if offset + 4 > len(value):
                    break
                pairwise.append(value[offset : offset + 4])
                offset += 4
        if offset + 2 <= len(value):
            count = struct.unpack("<H", value[offset : offset + 2])[0]
            offset += 2
            for _ in range(count):
                if offset + 4 > len(value):
                    break
                akms.append(value[offset : offset + 4])
                offset += 4
        if offset + 2 <= len(value):
            capabilities = struct.unpack("<H", value[offset : offset + 2])[0]
    except struct.error:
        return

    cipher_names = {2: "TKIP", 4: "CCMP", 5: "WEP-104", 8: "GCMP", 9: "GCMP-256"}
    akm_names = {
        1: "802.1X",
        2: "PSK",
        4: "FT-802.1X",
        5: "FT-PSK",
        6: "802.1X-SHA256",
        8: "SAE",
        9: "FT-SAE",
        18: "OWE",
    }

    def cipher_name(selector: bytes) -> str:
        if len(selector) != 4 or selector[:3] != b"\x00\x0f\xac":
            return "Unknown"
        return cipher_names.get(selector[3], "Unknown")

    def akm_name(selector: bytes) -> str:
        if len(selector) != 4 or selector[:3] != b"\x00\x0f\xac":
            return "Unknown"
        return akm_names.get(selector[3], "Unknown")

    group_name = cipher_name(group_cipher) if group_cipher else ""
    pairwise_names = [cipher_name(item) for item in pairwise]
    encryption = pairwise_names[0] if pairwise_names else group_name or "CCMP"
    result["encryption"] = encryption
    akm_labels = [akm_name(item) for item in akms]
    akm_types = {item[3] for item in akms if len(item) == 4 and item[:3] == b"\x00\x0f\xac"}
    if 18 in akm_types:
        result["authentication"] = "OWE"
    elif akm_types & {8, 9}:
        if akm_types & {2, 5}:
            result["authentication"] = "WPA2/WPA3 Transition"
        else:
            result["authentication"] = "WPA3-Personal"
    elif akm_types & {1, 4, 6}:
        result["authentication"] = "WPA2-Enterprise"
    else:
        result["authentication"] = "WPA2-Personal"

    mfpc = bool(capabilities & 0x0080)
    mfpr = bool(capabilities & 0x0040)
    if mfpc and mfpr:
        result["pmf"] = "Required"
    elif mfpc:
        result["pmf"] = "Capable"
    else:
        result["pmf"] = "Disabled"


def parse_80211(data: bytes, link_type: int) -> Parsed80211 | None:
    if link_type == 127:
        data = _skip_radiotap(data) or b""
    if link_type not in {105, 127}:
        return None
    if len(data) < 24:
        return None
    fc = struct.unpack("<H", data[:2])[0]
    frame_type = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    flags = fc >> 8
    to_ds = bool(flags & 0x01)
    from_ds = bool(flags & 0x02)
    protected = bool(flags & 0x40)
    addr1 = _mac(data[4:10])
    addr2 = _mac(data[10:16])
    addr3 = _mac(data[16:22])
    parsed = Parsed80211(frame_type=frame_type, subtype=subtype)

    if frame_type == 0:
        parsed.bssid = addr3
        parsed.source = addr2
        parsed.destination = addr1
        if subtype in {5, 8} and len(data) >= 36:
            ies = _parse_ies(data[36:])
            parsed.ssid = ies["ssid"]
            parsed.channel = ies["channel"]
            parsed.rsn = ies["rsn"]
            parsed.wpa = ies["wpa"]
            parsed.wps = ies["wps"]
            parsed.pmf = ies["pmf"]
            parsed.authentication = ies["authentication"]
            parsed.encryption = ies["encryption"]
            parsed.standards = ies["standards"]
        return parsed

    if frame_type == 2:
        header_len = 24
        if to_ds and from_ds:
            header_len += 6
        if subtype & 0x8:
            header_len += 2
        if len(data) < header_len:
            return None
        if to_ds:
            parsed.bssid = addr1
            parsed.source = addr2
            parsed.destination = addr3
        elif from_ds:
            parsed.bssid = addr2
            parsed.source = addr3
            parsed.destination = addr1
        else:
            parsed.bssid = addr3
            parsed.source = addr2
            parsed.destination = addr1
        if protected:
            return parsed
        payload = data[header_len:]
        if len(payload) < 8 or payload[:6] != b"\xaa\xaa\x03\x00\x00\x00":
            return parsed
        ethertype = payload[6:8]
        if ethertype != b"\x88\x8e":
            return parsed
        eapol = payload[8:]
        if len(eapol) < 99 or eapol[1] != 3:
            return parsed
        desc_type = eapol[4]
        if desc_type != 2:
            return parsed
        key_info = struct.unpack(">H", eapol[5:7])[0]
        replay = struct.unpack(">Q", eapol[9:17])[0]
        nonce = eapol[17:49]
        mic = eapol[81:97]
        key_version = key_info & 0x7
        has_ack = bool(key_info & 0x0080)
        has_mic = bool(key_info & 0x0100)
        secure = bool(key_info & 0x0200)
        if has_ack and not has_mic:
            message = 1
        elif has_mic and not has_ack and not secure:
            message = 2
        elif has_ack and has_mic:
            message = 3
        elif has_mic and secure:
            message = 4
        else:
            message = 0
        parsed.eapol = EapolKey(
            message=message,
            nonce=nonce,
            mic=mic,
            key_info=key_info,
            replay_counter=replay,
            key_version=key_version,
            raw=eapol,
        )
        parsed.pmkid = _extract_pmkid(eapol)
        return parsed
    return parsed


def _extract_pmkid(eapol: bytes) -> str:
    if len(eapol) < 99:
        return ""
    key_data_len = struct.unpack(">H", eapol[97:99])[0]
    key_data = eapol[99 : 99 + key_data_len]
    offset = 0
    while offset + 6 <= len(key_data):
        element_id = key_data[offset]
        length = key_data[offset + 1]
        value = key_data[offset + 2 : offset + 2 + length]
        if len(value) < length:
            break
        if (
            element_id == 0xDD
            and length >= 20
            and value[:3] == b"\x00\x0f\xac"
            and value[3] == 4
        ):
            pmkid = value[4:20].hex().upper()
            return pmkid
        offset += 2 + length
    return ""


def analyze_capture(
    path: Path | str,
    *,
    max_analysis_packets: int = 120_000,
    max_bytes: int | None = None,
) -> CaptureAnalysis:
    path = Path(path)
    if not path.is_file():
        raise CaptureError(f"Capture file not found: {path}")
    try:
        file_size = path.stat().st_size
    except OSError as exc:
        raise CaptureError(f"Unable to read capture: {exc}") from exc
    if file_size == 0:
        raise CaptureError("The selected capture file is empty.")

    digest = sha256_file(path)
    analysis = CaptureAnalysis(
        path=str(path),
        filename=path.name,
        format="unknown",
        size_bytes=file_size,
        sha256=digest,
    )
    ssid_counts: dict[str, int] = {}
    bssid_counts: dict[str, int] = {}
    channel_values: dict[int, int] = {}
    auth_counts: dict[str, int] = {}
    enc_counts: dict[str, int] = {}
    pmf_values: dict[str, int] = {}
    wps_values: dict[str, int] = {}
    standards: set[str] = set()
    partial_handshakes: dict[tuple[str, str], dict[str, Any]] = {}
    seen_packets = 0
    timestamps: list[float] = []

    try:
        with CaptureReader(path) as reader:
            analysis.format = reader.format
            analysis.link_type = reader.link_type
            analysis.link_type_name = LINK_TYPES.get(reader.link_type, "Unknown")
            for packet in reader.packets():
                seen_packets += 1
                if packet.timestamp is not None:
                    timestamps.append(packet.timestamp.timestamp())
                if seen_packets > max_analysis_packets:
                    continue
                parsed = parse_80211(packet.data, packet.link_type)
                if parsed is None:
                    continue
                analysis.inspected_packets += 1
                if parsed.ssid:
                    ssid_counts[parsed.ssid] = ssid_counts.get(parsed.ssid, 0) + 1
                if parsed.bssid:
                    bssid_counts[parsed.bssid] = bssid_counts.get(parsed.bssid, 0) + 1
                if parsed.channel:
                    channel_values[parsed.channel] = (
                        channel_values.get(parsed.channel, 0) + 1
                    )
                if parsed.authentication:
                    auth_counts[parsed.authentication] = (
                        auth_counts.get(parsed.authentication, 0) + 1
                    )
                if parsed.encryption:
                    enc_counts[parsed.encryption] = (
                        enc_counts.get(parsed.encryption, 0) + 1
                    )
                if parsed.pmf != "Unknown":
                    pmf_values[parsed.pmf] = pmf_values.get(parsed.pmf, 0) + 1
                if parsed.wps != "Unknown":
                    wps_values[parsed.wps] = wps_values.get(parsed.wps, 0) + 1
                standards.update(parsed.standards)
                if parsed.frame_type == 0 and parsed.subtype in {5, 8}:
                    analysis.beacon_count += 1
                if parsed.eapol:
                    analysis.eapol_count += 1
                    station = (
                        parsed.destination
                        if parsed.eapol.message in {1, 3}
                        else parsed.source
                    )
                    key = (parsed.bssid, station)
                    record = partial_handshakes.setdefault(key, {"messages": {}})
                    if parsed.ssid:
                        record["ssid"] = parsed.ssid
                    record["bssid"] = parsed.bssid
                    record["station"] = station
                    record["messages"][parsed.eapol.message] = parsed
                    if parsed.pmkid:
                        analysis.pmkid_count += 1
                        record["pmkid"] = parsed.pmkid
            analysis.packet_count = reader.packet_count
            analysis.truncated = reader.truncated
            analysis.notes.extend(reader.notes)
    except (OSError, EOFError, gzip.BadGzipFile, struct.error) as exc:
        raise CaptureError(f"Unable to parse capture: {exc}") from exc

    if timestamps:
        analysis.start_ts = _iso(min(timestamps))
        analysis.end_ts = _iso(max(timestamps))

    def top(mapping: dict[Any, int], fallback: Any = "") -> Any:
        return max(mapping, key=mapping.get) if mapping else fallback

    analysis.ssid = top(ssid_counts)
    analysis.bssid = top(bssid_counts)
    analysis.channel = top(channel_values, None)
    analysis.authentication = top(auth_counts)
    analysis.encryption = top(enc_counts)
    analysis.pmf = top(pmf_values, "Unknown")
    analysis.wps = top(wps_values, "Unknown")
    if standards:
        analysis.notes.append("Radio standards observed: " + ", ".join(sorted(standards)))

    for (bssid, station), record in partial_handshakes.items():
        messages: dict[int, EapolKey] = record["messages"]
        msg1 = messages.get(1)
        msg2 = messages.get(2)
        if msg1 and msg2 and msg1.eapol and msg2.eapol:
            analysis.handshakes.append(
                Handshake(
                    ssid=record.get("ssid") or analysis.ssid,
                    bssid=bssid,
                    station=station,
                    anonce=msg1.eapol.nonce,
                    snonce=msg2.eapol.nonce,
                    eapol=msg2.eapol.raw,
                    mic=msg2.eapol.mic,
                    key_version=msg2.eapol.key_version or 2,
                    pmkid=record.get("pmkid", ""),
                    complete=True,
                )
            )
        elif record.get("pmkid"):
            analysis.handshakes.append(
                Handshake(
                    ssid=record.get("ssid") or analysis.ssid,
                    bssid=bssid,
                    station=station,
                    anonce=b"",
                    snonce=b"",
                    eapol=b"",
                    mic=b"",
                    pmkid=record["pmkid"],
                    complete=False,
                )
            )
    if not analysis.bssid:
        analysis.bssid = analysis.handshakes[0].bssid if analysis.handshakes else ""
    if not analysis.ssid and analysis.handshakes:
        analysis.ssid = analysis.handshakes[0].ssid

    if analysis.packet_count == 0:
        analysis.integrity = "invalid"
        analysis.notes.append("No packets were recovered from the capture.")
    elif analysis.truncated:
        analysis.integrity = "truncated"
    else:
        analysis.integrity = "valid"
    if analysis.link_type not in {105, 127}:
        analysis.notes.append(
            "The capture does not use an 802.11 link type; wireless metadata cannot "
            "be extracted."
        )
    if analysis.eapol_count and not analysis.handshakes:
        analysis.notes.append(
            "EAPOL frames were present but no complete msg1/msg2 handshake pair was "
            "recovered."
        )
    return analysis


def extract_handshakes(path: Path | str) -> list[Handshake]:
    return analyze_capture(path, max_analysis_packets=250_000).handshakes

