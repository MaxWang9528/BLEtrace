"""Run: python3 -m unittest discover -s tests   (from the bletrace folder)"""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bletrace import analysis, luma  # noqa: E402
from bletrace.capture_io import HciRecord, parse_capture_bytes, write_btsnoop, write_pklg  # noqa: E402
from bletrace.decode import decode, format_uuid  # noqa: E402

ADDR = bytes([0x12, 0xC6, 0x00, 0x9C, 0x00, 0xA4])  # little-endian on the wire → A4:00:9C:00:C6:12
CONN = 0x0040


def crc_modbus(b: bytes) -> bytes:
    return struct.pack("<H", analysis.CRC16["CRC-16/MODBUS"](b))


def frame(cmd: int, payload: bytes) -> bytes:
    body = bytes([0xA0, cmd, 3 + len(payload)]) + payload
    return body + crc_modbus(body)


def acl(direction: str, att: bytes, ts: float, conn: int = CONN) -> HciRecord:
    l2 = struct.pack("<HH", len(att), 4) + att
    return HciRecord(ts, "acl", direction, struct.pack("<HH", conn | 0x2000, len(l2)) + l2)


def evt(code: int, params: bytes, ts: float) -> HciRecord:
    return HciRecord(ts, "evt", "rx", bytes([code, len(params)]) + params)


def sample_records() -> list[HciRecord]:
    name = b"P09C_C612"
    ad = bytes([len(name) + 1, 0x09]) + name + bytes([3, 0x03, 0x9C, 0xC0])
    adv = bytes([0x02, 1, 0x00, 0x00]) + ADDR + bytes([len(ad)]) + ad + bytes([0xC0])
    conn_complete = bytes([0x01, 0x00]) + struct.pack("<H", CONN) + bytes([0x00, 0x00]) + ADDR + bytes(5)
    recs = [
        evt(0x3E, adv, 100.0),
        evt(0x3E, conn_complete, 100.5),
        # Primary service discovery: E09C covers handles 0x0010-0x0020.
        acl("tx", bytes([0x10]) + struct.pack("<HHH", 1, 0xFFFF, 0x2800), 100.6),
        acl("rx", bytes([0x11, 6]) + struct.pack("<HHH", 0x0010, 0x0020, 0xE09C), 100.7),
        # Characteristic discovery: A09C (writeNoResp) at value handle 0x0012, F09C (notify) at 0x0015.
        acl("tx", bytes([0x08]) + struct.pack("<HHH", 0x10, 0x20, 0x2803), 100.8),
        acl("rx", bytes([0x09, 7]) + struct.pack("<HBHH", 0x0011, 0x04, 0x0012, 0xA09C)
            + struct.pack("<HBHH", 0x0014, 0x10, 0x0015, 0xF09C), 100.9),
    ]
    t = 103.0
    for cmd, payload in [(0x11, b"\x00"), (0x11, b"\x01"), (0x15, b"\xFF\x00\x00"), (0x15, b"\x00\xFF\x00"),
                         (0x15, b"\x00\x00\xFF"), (0x13, b"\x64"), (0x13, b"\x0A")]:
        recs.append(acl("tx", bytes([0x52]) + struct.pack("<H", 0x0012) + frame(cmd, payload), t))
        recs.append(acl("rx", bytes([0x1B]) + struct.pack("<H", 0x0015) + bytes([0xA1, cmd, 4, 1, 0, 0]), t + 0.05))
        t += 3.0
    recs.append(evt(0x05, bytes([0x00]) + struct.pack("<H", CONN) + bytes([0x13]), t))
    return recs


class FormatTests(unittest.TestCase):
    def test_pklg_both_byte_orders_and_btsnoop_round_trip(self):
        recs = sample_records()
        for blob in (write_pklg(recs, ">"), write_pklg(recs, "<"), write_btsnoop(recs)):
            parsed = parse_capture_bytes(blob)
            self.assertEqual(len(parsed), len(recs))
            self.assertEqual([r.data for r in parsed], [r.data for r in recs])
            self.assertAlmostEqual(parsed[3].ts, recs[3].ts, places=5)
            self.assertEqual([r.direction for r in parsed], [r.direction for r in recs])

    def test_truncated_tail_is_ignored(self):
        blob = write_pklg(sample_records())
        self.assertEqual(len(parse_capture_bytes(blob[:-3])), len(sample_records()) - 1)

    def test_garbage_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_capture_bytes(b"hello world, definitely not a capture")


class DecodeTests(unittest.TestCase):
    def setUp(self):
        self.trace = decode(parse_capture_bytes(write_pklg(sample_records())))

    def test_device_named_from_advertising(self):
        dev = self.trace.devices["A4:00:9C:00:C6:12"]
        self.assertEqual(dev["name"], "P09C_C612")
        self.assertIn("C09C", dev["advServices"])
        self.assertEqual(dev["connections"], 1)

    def test_handles_mapped_to_uuids(self):
        hs = self.trace.handles["A4:00:9C:00:C6:12"]
        self.assertEqual(hs[0x12]["uuid"], "A09C")
        self.assertEqual(hs[0x12]["props"], "writeNoResp")
        self.assertEqual(hs[0x12]["service"], "E09C")
        self.assertEqual(hs[0x15]["uuid"], "F09C")

    def test_writes_and_notifications(self):
        writes = [e for e in self.trace.events if e.get("op") == 0x52]
        self.assertEqual(len(writes), 7)
        self.assertEqual(writes[2]["value"], "A01506FF000025C0")  # the published red vector
        notes = [e for e in self.trace.events if e.get("op") == 0x1B]
        self.assertTrue(all(e["dir"] == "rx" and e["handle"] == 0x15 for e in notes))
        links = [e["text"] for e in self.trace.events if e.get("kind") == "link"]
        self.assertTrue(links[0].startswith("Connected") and links[-1].startswith("Disconnected"))

    def test_uuid128_collapses_to_16(self):
        raw = bytes.fromhex("FB349B5F80000080001000009CE00000")
        self.assertEqual(format_uuid(raw), "E09C")


class AnalysisTests(unittest.TestCase):
    def test_detects_modbus(self):
        found = analysis.checksum_candidates(bytes.fromhex("A01506FF000025C0"))
        self.assertIn("CRC-16/MODBUS, little-endian, over bytes 0..5", found)

    def test_sum8(self):
        body = bytes([0x7E, 0x04, 0x01, 0x55])
        self.assertTrue(any(c.startswith("SUM8 in last byte") for c in analysis.checksum_candidates(body + bytes([sum(body) & 0xFF]))))

    def test_patterns_group_and_find_varying_bytes(self):
        trace = decode(sample_records())
        groups = analysis.patterns(trace.events)
        color = next(g for g in groups if g["dir"] == "tx" and g["length"] == 8)
        self.assertEqual(color["count"], 3)
        self.assertTrue(color["positions"][0]["constant"])
        self.assertFalse(color["positions"][3]["constant"])
        self.assertEqual(color["checksum"], "CRC-16/MODBUS, little-endian, over bytes 0..5")


class LumaTests(unittest.TestCase):
    SAMPLE = """Luma diagnostics, Nov 24, 2026 at 8:14:25 PM
Bluetooth: On

== Lights
P09C_C612  id=ED8945B6  status=ready  state=Off

== Log
8:14:15 PM • P09C_C612: Connected
8:14:16 PM → P09C_C612: A0 10 04 00 21 21
8:14:16 PM ← P09C_C612: A1 10 04 01 00 00
"""

    def test_parse(self):
        t = luma.parse(self.SAMPLE)
        self.assertEqual(t.devices["P09C_C612"]["status"], "ready")
        kinds = [(e["kind"], e["dir"]) for e in t.events]
        self.assertEqual(kinds, [("note", "rx"), ("att", "tx"), ("att", "rx")])
        self.assertEqual(t.events[1]["value"], "A010040021" + "21")
        self.assertLess(t.events[1]["t"], t.events[2]["t"])


if __name__ == "__main__":
    unittest.main()
