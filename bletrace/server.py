"""Local web GUI: a JSON API plus static files, bound to 127.0.0.1 only."""

from __future__ import annotations

import csv
import io
import json
import mimetypes
import shutil
import subprocess
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from . import analysis, device, store

STATIC = Path(__file__).resolve().parent / "static"
MAX_UPLOAD = 512 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "bletrace"

    def log_message(self, fmt, *args):  # quiet
        pass

    # ---- plumbing

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status: int = 200) -> None:
        self._send(status, json.dumps(obj).encode(), "application/json")

    def _error(self, status: int, message: str) -> None:
        self._json({"error": message}, status)

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_UPLOAD:
            raise ValueError("Upload too large")
        return self.rfile.read(n)

    def _route(self, method: str) -> None:
        # Only same-origin requests may change anything.
        if method == "POST" and self.headers.get("Origin") not in (None, f"http://{self.headers.get('Host')}"):
            return self._error(403, "Cross-origin request refused")
        parts = [unquote(p) for p in urlparse(self.path).path.strip("/").split("/") if p]
        try:
            if not parts or parts[0] != "api":
                return self._static(parts)
            return self._api(method, parts[1:])
        except KeyError:
            self._error(404, "No such capture")
        except Exception as e:
            traceback.print_exc()
            self._error(500, str(e))

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    # ---- static

    def _static(self, parts: list[str]) -> None:
        name = parts[0] if parts else "index.html"
        path = (STATIC / name).resolve()
        if len(parts) > 1 or path.parent != STATIC or not path.is_file():
            return self._error(404, "Not found")
        ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self._send(200, path.read_bytes(), ctype + ("; charset=utf-8" if ctype.startswith("text") or "javascript" in ctype else ""))

    # ---- API

    def _api(self, method: str, p: list[str]) -> None:
        if method == "GET" and p == ["captures"]:
            return self._json(store.list_captures())
        if method == "GET" and p == ["device"]:
            return self._json(device.device_status())
        if p == ["pull"]:
            if method == "POST":
                kind = json.loads(self._body() or b"{}").get("kind", "sysdiagnose")
                if kind not in ("sysdiagnose", "luma"):
                    return self._error(400, "kind must be sysdiagnose or luma")
                return self._json(device.start_pull(kind).state())
            job = device.current_job()
            return self._json(job.state() if job else None)
        if method == "POST" and p == ["import"]:
            filename = self.headers.get("X-Filename", "capture.pklg")
            capture_id = store.import_bytes(filename, self._body())
            return self._json({"id": capture_id})
        if len(p) >= 2 and p[0] == "captures":
            cid = p[1]
            if method == "GET" and len(p) == 2:
                return self._json(store.load(cid))
            if method == "GET" and p[2:] == ["patterns"]:
                return self._json(analysis.patterns(store.load(cid)["events"]))
            if method == "GET" and p[2:] == ["checksum"]:
                hexstr = urlparse(self.path).query.removeprefix("hex=")
                return self._json(analysis.checksum_candidates(bytes.fromhex(unquote(hexstr))))
            if method == "GET" and p[2:] == ["export.csv"]:
                return self._export_csv(cid)
            if method == "POST" and p[2:] == ["note"]:
                body = json.loads(self._body())
                return self._json(store.write_note(cid, body["scope"], str(body["key"]), body.get("text", "")))
            if method == "POST" and p[2:] == ["rename"]:
                store.rename(cid, json.loads(self._body())["name"])
                return self._json({"ok": True})
            if method == "POST" and p[2:] == ["delete"]:
                store.delete(cid)
                return self._json({"ok": True})
        self._error(404, "Unknown endpoint")

    def _export_csv(self, cid: str) -> None:
        data = store.load(cid)
        notes = data["annotations"]["notes"]
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["index", "time", "direction", "device", "operation", "handle", "value_hex", "detail", "note"])
        for e in data["events"]:
            h = e.get("handle")
            w.writerow([e["i"], f"{e['t']:.6f}", e["dir"], e.get("dev") or "", e.get("opName") or e.get("kind"),
                        f"0x{h:04X}" if isinstance(h, int) else "", e.get("value", ""),
                        e.get("extra") or e.get("text") or "", notes.get(str(e["i"]), "")])
        body = buf.getvalue().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv")
        self.send_header("Content-Disposition", f'attachment; filename="{cid}.csv"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def open_browser(url: str) -> None:
    for cmd in (["wslview", url], ["explorer.exe", url], ["xdg-open", url]):
        if shutil.which(cmd[0]):
            try:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
            except OSError:
                continue


def serve(port: int = 8765, open_it: bool = True) -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://localhost:{port}/"
    print(f"bletrace GUI running at {url}  (Ctrl+C to stop)")
    if open_it:
        open_browser(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
