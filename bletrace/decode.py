"""Turns raw HCI records into a GATT-level timeline.

Output (Trace):
  devices  key -> {address, name, connections, packets}
  handles  device key -> handle -> {uuid, props, service, kind}
  events   list of dicts, one per ATT PDU / link event / log note, in time order.

The device key is the peer Bluetooth address when the connection setup is in the capture,
otherwise "conn 0x0040" (the HCI connection handle).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .capture_io import HciRecord

BASE_UUID_SUFFIX = "-0000-1000-8000-00805F9B34FB"

ATT_OPS = {
    0x01: "Error", 0x02: "MTU req", 0x03: "MTU rsp", 0x04: "Find info req", 0x05: "Find info rsp",
    0x06: "Find by type req", 0x07: "Find by type rsp", 0x08: "Read by type req", 0x09: "Read by type rsp",
    0x0A: "Read req", 0x0B: "Read rsp", 0x0C: "Read blob req", 0x0D: "Read blob rsp",
    0x0E: "Read multiple req", 0x0F: "Read multiple rsp", 0x10: "Read by group req", 0x11: "Read by group rsp",
    0x12: "Write req", 0x13: "Write rsp", 0x16: "Prepare write req", 0x17: "Prepare write rsp",
    0x18: "Execute write req", 0x19: "Execute write rsp", 0x1B: "Notify", 0x1D: "Indicate", 0x1E: "Confirm",
    0x52: "Write cmd", 0xD2: "Signed write",
}

# Opcodes whose PDU is handle(2) + value: these are the interesting "data" packets.
VALUE_OPS = {0x12, 0x52, 0x1B, 0x1D, 0xD2, 0x16}
ATT_CID = 0x0004

KNOWN_UUIDS = {
    "1800": "Generic Access", "1801": "Generic Attribute", "180A": "Device Information",
    "180F": "Battery", "1811": "Alert Notification", "FE59": "Nordic DFU",
    "2A00": "Device Name", "2A01": "Appearance", "2A05": "Service Changed", "2A19": "Battery Level",
    "2A29": "Manufacturer", "2A24": "Model Number", "2A26": "Firmware Revision", "2902": "CCCD",
    "2901": "User Description", "2803": "Characteristic", "2800": "Primary Service",
}

PROP_NAMES = [(0x02, "read"), (0x04, "writeNoResp"), (0x08, "write"), (0x10, "notify"), (0x20, "indicate")]


def format_uuid(raw: bytes) -> str:
    if len(raw) == 2:
        return f"{struct.unpack('<H', raw)[0]:04X}"
    if len(raw) == 16:
        h = raw[::-1].hex().upper()
        s = f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
        if s.startswith("0000") and s.endswith(BASE_UUID_SUFFIX):
            return s[4:8]
        return s
    return raw.hex().upper()


def format_props(p: int) -> str:
    return ", ".join(n for bit, n in PROP_NAMES if p & bit) or "-"


def format_addr(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw[::-1])


def parse_ad(data: bytes) -> dict:
    """Parses advertising data into {name, services, mfr}."""
    out: dict = {"services": []}
    i = 0
    while i < len(data):
        length = data[i]
        if length == 0 or i + 1 + length > len(data):
            break
        ad_type, value = data[i + 1], data[i + 2: i + 1 + length]
        if ad_type in (0x08, 0x09):
            out["name"] = value.decode("utf-8", "replace")
        elif ad_type in (0x02, 0x03):
            out["services"] += [format_uuid(value[j:j + 2]) for j in range(0, len(value) - 1, 2)]
        elif ad_type in (0x06, 0x07):
            out["services"] += [format_uuid(value[j:j + 16]) for j in range(0, len(value) - 15, 16)]
        elif ad_type == 0xFF:
            out["mfr"] = value.hex().upper()
        i += 1 + length
    return out


@dataclass
class Trace:
    devices: dict = field(default_factory=dict)
    handles: dict = field(default_factory=dict)
    events: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "devices": self.devices,
            "handles": {d: {str(h): v for h, v in hs.items()} for d, hs in self.handles.items()},
            "events": self.events,
            "stats": self.stats,
        }


class Decoder:
    def __init__(self) -> None:
        self.trace = Trace()
        self.conn_dev: dict[int, str] = {}          # HCI connection handle -> device key
        self.adv: dict[str, dict] = {}              # address -> advertising info
        self.acl_buf: dict[tuple[int, str], bytearray] = {}
        self.pending_req: dict[tuple[int, str], tuple[int, bytes]] = {}  # (conn, requester dir) -> (op, pdu)
        self.counts = {"records": 0, "acl": 0, "att": 0, "adv": 0, "notes": 0}

    # ---- entry points

    def feed(self, records: list[HciRecord]) -> Trace:
        for r in sorted(records, key=lambda r: r.ts):
            self.counts["records"] += 1
            try:
                if r.kind == "evt":
                    self._event(r)
                elif r.kind == "acl":
                    self._acl(r)
                elif r.kind == "note":
                    self.counts["notes"] += 1
                    self._emit(r.ts, "rx", None, kind="note", text=r.data.decode("utf-8", "replace")[:500])
            except (struct.error, IndexError):
                continue  # malformed packet: skip rather than abort the whole capture
        for key, dev in self.trace.devices.items():
            info = self.adv.get(dev.get("address", ""), {})
            if info.get("name") and not dev.get("name"):
                dev["name"] = info["name"]
            if info.get("services"):
                dev["advServices"] = sorted(set(info["services"]))
            if info.get("mfr"):
                dev["mfr"] = info["mfr"]
        self.trace.stats = dict(self.counts, advertisers=len(self.adv))
        self.trace.stats["advertisers_named"] = sorted(
            {v["name"] for v in self.adv.values() if v.get("name")})[:200]
        return self.trace

    # ---- HCI events

    def _event(self, r: HciRecord) -> None:
        code, plen = r.data[0], r.data[1]
        p = r.data[2: 2 + plen]
        if code == 0x3E:
            sub = p[0]
            if sub in (0x01, 0x0A) and p[1] == 0:  # (Enhanced) LE Connection Complete, status OK
                conn = struct.unpack_from("<H", p, 2)[0] & 0x0FFF
                addr = format_addr(p[6:12])
                self.conn_dev[conn] = addr
                dev = self._device(addr)
                dev["address"] = addr
                dev["connections"] += 1
                self._emit(r.ts, "rx", addr, kind="link", text=f"Connected (handle 0x{conn:04X})")
            elif sub == 0x02:
                num = p[1]
                if num == 1:
                    addr = format_addr(p[4:10])
                    dlen = p[10]
                    self._advert(addr, p[11: 11 + dlen])
            elif sub == 0x0D:
                num, i = p[1], 2
                for _ in range(num):
                    addr = format_addr(p[i + 3: i + 9])
                    dlen = p[i + 23]
                    self._advert(addr, p[i + 24: i + 24 + dlen])
                    i += 24 + dlen
        elif code == 0x05 and p[0] == 0:  # Disconnection Complete
            conn = struct.unpack_from("<H", p, 1)[0] & 0x0FFF
            key = self.conn_dev.get(conn, f"conn 0x{conn:04X}")
            self._emit(r.ts, "rx", key, kind="link", text=f"Disconnected (reason 0x{p[3]:02X})")
            self.conn_dev.pop(conn, None)

    def _advert(self, addr: str, data: bytes) -> None:
        self.counts["adv"] += 1
        info = self.adv.setdefault(addr, {"services": []})
        parsed = parse_ad(data)
        if parsed.get("name"):
            info["name"] = parsed["name"]
        if parsed.get("mfr"):
            info["mfr"] = parsed["mfr"]
        info["services"] = sorted(set(info["services"]) | set(parsed["services"]))

    # ---- ACL / L2CAP

    def _acl(self, r: HciRecord) -> None:
        self.counts["acl"] += 1
        hf, length = struct.unpack_from("<HH", r.data, 0)
        conn, pb = hf & 0x0FFF, (hf >> 12) & 0x3
        payload = r.data[4: 4 + length]
        key = (conn, r.direction)
        if pb == 0x1:  # continuation
            if key not in self.acl_buf:
                return
            self.acl_buf[key] += payload
        else:
            self.acl_buf[key] = bytearray(payload)
        buf = self.acl_buf[key]
        if len(buf) < 4:
            return
        l2len, cid = struct.unpack_from("<HH", buf, 0)
        if len(buf) < 4 + l2len:
            return
        del self.acl_buf[key]
        if cid == ATT_CID:
            self._att(r.ts, conn, r.direction, bytes(buf[4: 4 + l2len]))

    # ---- ATT

    def _att(self, ts: float, conn: int, direction: str, pdu: bytes) -> None:
        if not pdu:
            return
        self.counts["att"] += 1
        op = pdu[0]
        dev = self.conn_dev.get(conn) or f"conn 0x{conn:04X}"
        if dev not in self.trace.devices:
            self._device(dev)
        handles = self.trace.handles.setdefault(dev, {})
        other = "rx" if direction == "tx" else "tx"

        # Requests are remembered so their responses (which carry no type) can be interpreted.
        if op in (0x04, 0x08, 0x0A, 0x10, 0x12, 0x0C):
            self.pending_req[(conn, direction)] = (op, pdu)
        req = self.pending_req.get((conn, other))

        if op in VALUE_OPS and len(pdu) >= 3:
            handle = struct.unpack_from("<H", pdu, 1)[0]
            value = pdu[3:] if op != 0x16 else pdu[5:]
            if op == 0xD2:
                value = value[:-12]  # strip the signature
            handles.setdefault(handle, {})
            self._emit(ts, direction, dev, kind="att", op=op, handle=handle, value=value.hex().upper())
            return

        handle, value, extra = None, b"", ""
        if op == 0x0A and len(pdu) >= 3:
            handle = struct.unpack_from("<H", pdu, 1)[0]
        elif op in (0x0B, 0x0D) and req and req[0] in (0x0A, 0x0C):
            handle = struct.unpack_from("<H", req[1], 1)[0]
            value = pdu[1:]
            handles.setdefault(handle, {})
        elif op == 0x01 and len(pdu) >= 5:
            handle = struct.unpack_from("<H", pdu, 2)[0]
            extra = f"{ATT_OPS.get(pdu[1], hex(pdu[1]))} failed, code 0x{pdu[4]:02X}"
        elif op in (0x02, 0x03) and len(pdu) >= 3:
            extra = f"MTU {struct.unpack_from('<H', pdu, 1)[0]}"
        elif op == 0x05:
            fmt, step = pdu[1], (4 if pdu[1] == 1 else 18)
            found = []
            for i in range(2, len(pdu) - step + 1, step):
                h = struct.unpack_from("<H", pdu, i)[0]
                uuid = format_uuid(pdu[i + 2: i + step])
                handles.setdefault(h, {}).setdefault("uuid", uuid)
                found.append(f"{h:#06x}={uuid}")
            extra = " ".join(found)
        elif op == 0x09 and req and req[0] == 0x08:
            item_len = pdu[1]
            req_type = format_uuid(req[1][5:])
            found = []
            for i in range(2, len(pdu) - item_len + 1, item_len):
                item = pdu[i: i + item_len]
                h = struct.unpack_from("<H", item, 0)[0]
                if req_type == "2803" and len(item) >= 7:
                    props, vh = item[2], struct.unpack_from("<H", item, 3)[0]
                    uuid = format_uuid(item[5:])
                    entry = handles.setdefault(vh, {})
                    entry.update(uuid=uuid, props=format_props(props))
                    entry.setdefault("service", self._service_for(handles, vh))
                    found.append(f"{vh:#06x}={uuid} [{format_props(props)}]")
                else:
                    found.append(f"{h:#06x}:{item[2:].hex().upper()}")
            extra = " ".join(found)
        elif op == 0x11 and req and req[0] == 0x10:
            item_len = pdu[1]
            found = []
            for i in range(2, len(pdu) - item_len + 1, item_len):
                start, end = struct.unpack_from("<HH", pdu, i)
                uuid = format_uuid(pdu[i + 4: i + item_len])
                handles.setdefault("_services", {})[f"{start}-{end}"] = uuid
                found.append(f"{uuid} {start:#06x}-{end:#06x}")
            extra = " ".join(found)
        else:
            value = pdu[1:]

        self._emit(ts, direction, dev, kind="att", op=op, handle=handle,
                   value=value.hex().upper(), extra=extra)

    @staticmethod
    def _service_for(handles: dict, h: int) -> str | None:
        for rng, uuid in handles.get("_services", {}).items():
            start, end = map(int, rng.split("-"))
            if start <= h <= end:
                return uuid
        return None

    # ---- helpers

    def _device(self, key: str) -> dict:
        return self.trace.devices.setdefault(key, {"connections": 0, "packets": 0})

    def _emit(self, ts: float, direction: str, dev: str | None, **fields) -> None:
        ev = {"i": len(self.trace.events), "t": round(ts, 6), "dir": direction, "dev": dev}
        ev.update({k: v for k, v in fields.items() if v not in (None, "")})
        if "op" in ev:
            ev["opName"] = ATT_OPS.get(ev["op"], f"ATT 0x{ev['op']:02X}")
        if dev:
            self._device(dev)["packets"] += 1
        self.trace.events.append(ev)


def decode(records: list[HciRecord]) -> Trace:
    trace = Decoder().feed(records)
    # Move the service-range helper table out of the per-handle map.
    for dev, hs in trace.handles.items():
        services = hs.pop("_services", {})
        for h, entry in hs.items():
            if isinstance(entry, dict) and "service" not in entry:
                for rng, uuid in services.items():
                    start, end = map(int, rng.split("-"))
                    if start <= h <= end:
                        entry["service"] = uuid
        if services:
            trace.devices.setdefault(dev, {}).setdefault("services", sorted(set(services.values())))
    return trace
