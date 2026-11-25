"""Protocol-guessing helpers: checksum detection and payload pattern grouping."""

from __future__ import annotations

from collections import defaultdict


def _crc16(data: bytes, poly: int, init: int, reflect: bool, xorout: int = 0) -> int:
    crc = init
    for b in data:
        if reflect:
            crc ^= b
            for _ in range(8):
                crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
        else:
            crc ^= b << 8
            for _ in range(8):
                crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc ^ xorout


def _crc8(data: bytes, poly: int, init: int, reflect: bool) -> int:
    crc = init
    for b in data:
        crc ^= b
        for _ in range(8):
            if reflect:
                crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
            else:
                crc = ((crc << 1) ^ poly) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


CRC16 = {
    "CRC-16/MODBUS": lambda d: _crc16(d, 0xA001, 0xFFFF, True),
    "CRC-16/ARC": lambda d: _crc16(d, 0xA001, 0x0000, True),
    "CRC-16/CCITT-FALSE": lambda d: _crc16(d, 0x1021, 0xFFFF, False),
    "CRC-16/XMODEM": lambda d: _crc16(d, 0x1021, 0x0000, False),
    "CRC-16/KERMIT": lambda d: _crc16(d, 0x8408, 0x0000, True),
    "CRC-16/X25": lambda d: _crc16(d, 0x8408, 0xFFFF, True, 0xFFFF),
}

CRC8 = {
    "CRC-8": lambda d: _crc8(d, 0x07, 0x00, False),
    "CRC-8/MAXIM": lambda d: _crc8(d, 0x8C, 0x00, True),
    "SUM8": lambda d: sum(d) & 0xFF,
    "SUM8 (two's complement)": lambda d: (-sum(d)) & 0xFF,
    "XOR8": lambda d: _xor(d),
}


def _xor(d: bytes) -> int:
    x = 0
    for b in d:
        x ^= b
    return x


def checksum_candidates(frame: bytes) -> list[str]:
    """Names of checksums that the frame's trailing byte(s) satisfy, e.g.
    'CRC-16/MODBUS, little-endian, over bytes 0..5'. Tries every start offset up to 3."""
    out: list[str] = []
    n = len(frame)
    if n >= 4:
        tail_le = frame[-2] | frame[-1] << 8
        tail_be = frame[-2] << 8 | frame[-1]
        for start in range(0, min(4, n - 3)):
            body = frame[start:-2]
            for name, fn in CRC16.items():
                v = fn(body)
                if v == tail_le:
                    out.append(f"{name}, little-endian, over bytes {start}..{n - 3}")
                if v == tail_be and tail_be != tail_le:
                    out.append(f"{name}, big-endian, over bytes {start}..{n - 3}")
    if n >= 3:
        for start in range(0, min(4, n - 2)):
            body = frame[start:-1]
            for name, fn in CRC8.items():
                if fn(body) == frame[-1]:
                    out.append(f"{name} in last byte, over bytes {start}..{n - 2}")
    return out


def summarize_checksums(frames: list[bytes]) -> str | None:
    """The checksum hypothesis that holds for every frame (only meaningful for >= 2 frames)."""
    distinct = list({f for f in frames})
    if len(distinct) < 2:
        return None
    common: set[str] | None = None
    for f in distinct:
        c = set(checksum_candidates(f))
        common = c if common is None else common & c
        if not common:
            return None
    return sorted(common)[0] if common else None


def patterns(events: list[dict]) -> list[dict]:
    """Groups value-carrying packets by (device, handle, direction, length, first byte) and
    describes which byte positions vary."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for e in events:
        if e.get("kind") != "att" or e.get("op") not in (0x12, 0x52, 0x1B, 0x1D, 0xD2) or not e.get("value"):
            continue
        v = bytes.fromhex(e["value"])
        groups[(e.get("dev"), e.get("handle"), e["dir"], len(v), v[0])].append(e)

    out = []
    for (dev, handle, direction, length, first), evs in groups.items():
        frames = [bytes.fromhex(e["value"]) for e in evs]
        positions = []
        for i in range(length):
            values = sorted({f[i] for f in frames})
            positions.append({
                "i": i,
                "constant": len(values) == 1,
                "values": [f"{v:02X}" for v in values[:12]],
                "more": max(0, len(values) - 12),
            })
        out.append({
            "dev": dev, "handle": handle, "dir": direction, "length": length,
            "prefix": f"{first:02X}", "count": len(evs),
            "distinct": len(set(frames)),
            "first": evs[0]["i"], "examples": [e["i"] for e in evs[:50]],
            "positions": positions,
            "checksum": summarize_checksums(frames),
        })
    out.sort(key=lambda g: (-g["count"]))
    return out
