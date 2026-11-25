"""Readers for raw HCI capture files.

Supported:
  * Apple PacketLogger (.pklg): what iOS writes into a sysdiagnose when the Bluetooth logging
    profile is installed (logs/Bluetooth/*.pklg). Both byte orders exist in the wild.
  * btsnoop (.log / .cfa / .btsnoop): Android "Bluetooth HCI snoop log", BlueZ btmon -w.

Every reader yields HciRecord(ts, kind, direction, data) where kind is one of
"cmd", "evt", "acl", "sco", "note" and direction is "tx" (host -> controller, i.e. the phone
sending) or "rx" (controller -> host, i.e. the phone receiving).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class HciRecord:
    ts: float          # seconds since the Unix epoch
    kind: str          # cmd | evt | acl | sco | note
    direction: str     # tx | rx
    data: bytes


class CaptureFormatError(ValueError):
    pass


def read_capture(path: str | Path) -> list[HciRecord]:
    """Detects the format from the file contents and returns all records."""
    blob = Path(path).read_bytes()
    return parse_capture_bytes(blob)


def parse_capture_bytes(blob: bytes) -> list[HciRecord]:
    if blob.startswith(b"btsnoop\x00"):
        return list(_parse_btsnoop(blob))
    return list(_parse_pklg(blob))


# --------------------------------------------------------------------------------------------
# PacketLogger

_PKLG_TYPES = {
    0x00: ("cmd", "tx"),
    0x01: ("evt", "rx"),
    0x02: ("acl", "tx"),
    0x03: ("acl", "rx"),
    0x08: ("sco", "tx"),
    0x09: ("sco", "rx"),
}


def _pklg_endianness(blob: bytes) -> str:
    """Returns '>' or '<' by checking which byte order chains cleanly through the first records."""
    for order in (">", "<"):
        offset, ok = 0, 0
        while offset + 4 <= len(blob) and ok < 8:
            (length,) = struct.unpack_from(order + "I", blob, offset)
            if length < 9 or length > 1 << 20 or offset + 4 + length > len(blob):
                break
            offset += 4 + length
            ok += 1
        if ok >= 8 or (ok > 0 and offset == len(blob)):
            return order
    raise CaptureFormatError("Not a PacketLogger (.pklg) or btsnoop file")


def _parse_pklg(blob: bytes) -> Iterator[HciRecord]:
    order = _pklg_endianness(blob)
    offset = 0
    while offset + 13 <= len(blob):
        (length,) = struct.unpack_from(order + "I", blob, offset)
        if length < 9 or offset + 4 + length > len(blob):
            break  # truncated tail (the log was still being written)
        a, b = struct.unpack_from(order + "II", blob, offset + 4)
        ptype = blob[offset + 12]
        data = blob[offset + 13: offset + 4 + length]
        offset += 4 + length
        # The two 32-bit timestamp halves are (secs, usecs) but their order differs between
        # files; usecs is always < 1e6.
        secs, usecs = (a, b) if b < 1_000_000 else (b, a)
        ts = secs + usecs / 1e6
        if ptype in _PKLG_TYPES:
            kind, direction = _PKLG_TYPES[ptype]
            yield HciRecord(ts, kind, direction, data)
        elif ptype >= 0xF0:
            text = data.decode("utf-8", "replace").strip("\x00 \r\n")
            if text:
                yield HciRecord(ts, "note", "rx", text.encode())


# --------------------------------------------------------------------------------------------
# btsnoop

_BTSNOOP_EPOCH_DELTA_US = 0x00DCDDB30F2F8000  # microseconds from 0000-01-01 to 1970-01-01
_H4_TYPES = {1: "cmd", 2: "acl", 3: "sco", 4: "evt"}


def _parse_btsnoop(blob: bytes) -> Iterator[HciRecord]:
    if len(blob) < 16:
        raise CaptureFormatError("Truncated btsnoop header")
    _version, datalink = struct.unpack_from(">II", blob, 8)
    offset = 16
    while offset + 24 <= len(blob):
        _orig, incl, flags, _drops, ts_us = struct.unpack_from(">IIIIq", blob, offset)
        offset += 24
        data = blob[offset: offset + incl]
        offset += incl
        if len(data) < incl:
            break
        ts = (ts_us - _BTSNOOP_EPOCH_DELTA_US) / 1e6
        direction = "rx" if flags & 1 else "tx"
        if datalink == 1002:  # HCI UART (H4): first byte is the packet type
            if not data:
                continue
            kind = _H4_TYPES.get(data[0])
            if kind is None:
                continue
            data = data[1:]
        elif datalink == 1001:  # HCI without type byte
            kind = ("evt" if direction == "rx" else "cmd") if flags & 2 else "acl"
        else:
            raise CaptureFormatError(f"Unsupported btsnoop datalink {datalink}")
        yield HciRecord(ts, kind, direction, data)


# --------------------------------------------------------------------------------------------
# Writers (used by the tests to build synthetic captures)

def write_pklg(records: list[HciRecord], order: str = ">") -> bytes:
    rev = {v: k for k, v in _PKLG_TYPES.items()}
    out = bytearray()
    for r in records:
        ptype = 0xFC if r.kind == "note" else rev[(r.kind, r.direction)]
        secs = int(r.ts)
        usecs = int(round((r.ts - secs) * 1e6))
        out += struct.pack(order + "III", 9 + len(r.data), secs, usecs)
        out.append(ptype)
        out += r.data
    return bytes(out)


def write_btsnoop(records: list[HciRecord]) -> bytes:
    out = bytearray(b"btsnoop\x00" + struct.pack(">II", 1, 1002))
    rev = {v: k for k, v in _H4_TYPES.items()}
    for r in records:
        data = bytes([rev[r.kind]]) + r.data
        flags = (1 if r.direction == "rx" else 0) | (2 if r.kind in ("cmd", "evt") else 0)
        ts_us = int(round(r.ts * 1e6)) + _BTSNOOP_EPOCH_DELTA_US
        out += struct.pack(">IIIIq", len(data), len(data), flags, 0, ts_us) + data
    return bytes(out)
