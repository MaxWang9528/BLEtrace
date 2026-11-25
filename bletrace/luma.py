"""Reads Luma's Documents/diagnostics.txt (see LumaRemote) as a capture.

Luma only knows what *it* sent and received, so these captures are for checking Luma's own
behaviour against a real capture of the vendor app.
"""

from __future__ import annotations

import re
from datetime import datetime

from .decode import Trace

HEADER_RE = re.compile(r"^Luma diagnostics, (.+)$")
LOG_RE = re.compile(r"^(\d{1,2}:\d{2}:\d{2}\s?[AP]M) (→|←|•) ([^:]+): (.*)$")
LIGHT_RE = re.compile(r"^(\S+)\s+id=(\S+)\s+status=(\S+)")


def _parse_date(text: str) -> datetime | None:
    text = text.replace(" ", " ").replace(" at ", " ")
    for fmt in ("%b %d, %Y %I:%M:%S %p", "%d %b %Y %I:%M:%S %p"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def parse(text: str) -> Trace:
    trace = Trace()
    lines = text.replace(" ", " ").splitlines()
    day = None
    if lines and (m := HEADER_RE.match(lines[0])):
        day = _parse_date(m.group(1))
    day = day or datetime.now()

    section = None
    for line in lines:
        if line.startswith("== "):
            section = line[3:].strip()
            continue
        if section == "Lights" and (m := LIGHT_RE.match(line)):
            trace.devices[m.group(1)] = {"connections": 0, "packets": 0, "status": m.group(3), "id": m.group(2)}
        if section != "Log":
            continue
        m = LOG_RE.match(line)
        if not m:
            continue
        clock, arrow, dev, body = m.groups()
        try:
            t = datetime.strptime(clock.replace(" ", ""), "%I:%M:%S%p").time()
        except ValueError:
            continue
        ts = datetime.combine(day.date(), t).timestamp()
        trace.devices.setdefault(dev, {"connections": 0, "packets": 0})["packets"] += 1
        ev = {"i": len(trace.events), "t": ts, "dev": dev}
        hexish = re.fullmatch(r"(?:[0-9A-F]{2} ?)+", body.strip())
        if arrow in "→←" and hexish:
            ev.update(kind="att", dir="tx" if arrow == "→" else "rx",
                      op=0x52 if arrow == "→" else 0x1B,
                      opName="Write cmd" if arrow == "→" else "Notify",
                      value=body.replace(" ", ""))
        else:
            ev.update(kind="note", dir="rx", text=body)
        trace.events.append(ev)
    # Lines share a clock second; keep their order but spread them a little for the trace strip.
    seen: dict[float, int] = {}
    for ev in trace.events:
        n = seen.get(ev["t"], 0)
        seen[ev["t"]] = n + 1
        ev["t"] = round(ev["t"] + min(n, 999) * 0.001, 6)
    trace.stats = {"records": len(trace.events), "source": "luma"}
    return trace
