"""bletrace command line. Run `./bletrace.sh help`."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import analysis, device, store


def _table(capture_id: str, only_values: bool) -> None:
    data = store.load(capture_id)
    labels = data["annotations"]["labels"]
    notes = data["annotations"]["notes"]
    prev_t = None
    for e in data["events"]:
        if only_values and not (e.get("kind") == "att" and e.get("op") in (0x12, 0x52, 0x1B, 0x1D)):
            continue
        if prev_t is not None and e["t"] - prev_t > 1:
            print(f"{'':>6}   ── {e['t'] - prev_t:.1f} s gap ──")
        prev_t = e["t"]
        clock = datetime.fromtimestamp(e["t"]).strftime("%H:%M:%S.%f")[:-3]
        h = e.get("handle")
        hs = f"0x{h:04X}" if isinstance(h, int) else ""
        label = labels.get(f"{e.get('dev')}|{h}", "")
        val = " ".join(e.get("value", "")[i:i + 2] for i in range(0, len(e.get("value", "")), 2))
        what = e.get("opName") or e.get("kind")
        arrow = "→" if e["dir"] == "tx" else "←"
        detail = e.get("extra") or e.get("text") or ""
        note = notes.get(str(e["i"]))
        print(f"{e['i']:>6} {clock} {arrow} {str(e.get('dev') or ''):<18} {what:<16} {hs:<7}{label[:12]:<13}{val} {detail}"
              + (f"   # {note}" if note else ""))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bletrace", description="BLE reverse-engineering workbench")
    sub = ap.add_subparsers(dest="cmd")
    g = sub.add_parser("gui", help="open the GUI in your browser")
    g.add_argument("--port", type=int, default=8765)
    g.add_argument("--no-open", action="store_true", help="don't open a browser window")
    p = sub.add_parser("pull", help="pull the newest sysdiagnose (or Luma's log) from the iPhone")
    p.add_argument("--luma", action="store_true", help="pull Luma's diagnostics.txt instead")
    i = sub.add_parser("import", help="import a .pklg / btsnoop file")
    i.add_argument("file", type=Path)
    sub.add_parser("list", help="list captures")
    s = sub.add_parser("show", help="print a capture as a table")
    s.add_argument("capture", help="capture id (or 'latest')")
    s.add_argument("--all", action="store_true", help="include every ATT packet, not just writes/notifications")
    pt = sub.add_parser("patterns", help="print byte patterns and checksum guesses")
    pt.add_argument("capture")
    sub.add_parser("help")
    args = ap.parse_args(argv)

    def resolve(cid: str) -> str:
        if cid == "latest":
            caps = store.list_captures()
            if not caps:
                sys.exit("No captures yet.")
            return caps[0]["id"]
        return cid

    if args.cmd in (None, "help"):
        ap.print_help()
    elif args.cmd == "gui":
        from .server import serve
        serve(args.port, not args.no_open)
    elif args.cmd == "pull":
        job = device.PullJob("luma" if args.luma else "sysdiagnose")
        fn = device.pull_luma if args.luma else device.pull_sysdiagnose
        job.say = lambda m: print(m)  # type: ignore[method-assign]
        try:
            print("Capture:", fn(job))
        except RuntimeError as e:
            print("Error:", e, file=sys.stderr)
            return 1
    elif args.cmd == "import":
        print("Capture:", store.import_file(args.file))
    elif args.cmd == "list":
        for m in store.list_captures():
            print(f"{m['id']:<44} {m['source']:<12} {m['name']}")
    elif args.cmd == "show":
        _table(resolve(args.capture), not args.all)
    elif args.cmd == "patterns":
        for g_ in analysis.patterns(store.load(resolve(args.capture))["events"]):
            h = g_["handle"]
            print(f"\n{g_['dev']}  handle {('0x%04X' % h) if isinstance(h, int) else '-'}  {g_['dir']}  "
                  f"len {g_['length']}  starts {g_['prefix']}  ×{g_['count']} ({g_['distinct']} distinct)")
            if g_["checksum"]:
                print("  checksum:", g_["checksum"])
            for pos in g_["positions"]:
                vals = pos["values"][0] if pos["constant"] else ", ".join(pos["values"]) + (f" +{pos['more']}" if pos["more"] else "")
                print(f"  byte {pos['i']:>2}: {'const' if pos['constant'] else 'varies'}  {vals}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
