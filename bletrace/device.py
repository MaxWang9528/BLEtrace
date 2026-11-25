"""Talking to the iPhone over USB with libimobiledevice (idevice_id, idevicecrashreport, afcclient).

Pulling a capture:
  1. With Apple's Bluetooth logging profile installed, the user triggers a sysdiagnose
     (hold both volume buttons + side button for ~1 s). iOS builds it in ~5-10 minutes.
  2. idevicecrashreport copies DiagnosticLogs (where sysdiagnose_*.tar.gz lands) to our disk.
  3. We read the .pklg members out of the tarball without extracting anything else.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
import threading
import time
from pathlib import Path

from . import store

CONFIG = store.ROOT / "bletrace.json"
DEFAULT_CONFIG = {
    # Container of an app whose Documents/diagnostics.txt we can pull (LumaRemote).
    "luma_container": "XTL-NUW48458NP.com.example.LumaRemote",
}
MAX_MEMBER = 512 * 1024 * 1024


def config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG.exists():
        try:
            cfg.update(json.loads(CONFIG.read_text()))
        except json.JSONDecodeError:
            pass
    return cfg


def _run(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    if shutil.which(args[0]) is None:
        raise RuntimeError(f"{args[0]} is not installed (sudo apt install libimobiledevice-utils)")
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def device_status() -> dict:
    try:
        r = _run(["idevice_id", "-l"], 10)
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        return {"connected": False, "message": str(e)}
    udids = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    if not udids:
        return {"connected": False, "message": "No iPhone found. Attach it to WSL (usbipd attach) and run usbmuxd."}
    name = udids[0]
    try:
        n = _run(["ideviceinfo", "-k", "DeviceName"], 10).stdout.strip()
        name = n or name
    except Exception:
        pass
    return {"connected": True, "udid": udids[0], "name": name}


class PullJob:
    """A background pull; the GUI polls `state()`."""

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.log: list[str] = []
        self.done = False
        self.error: str | None = None
        self.capture_id: str | None = None
        self.started = time.time()

    def say(self, msg: str) -> None:
        self.log.append(msg)

    def state(self) -> dict:
        return {"kind": self.kind, "log": self.log, "done": self.done, "error": self.error,
                "capture": self.capture_id, "elapsed": round(time.time() - self.started)}


_job: PullJob | None = None
_job_lock = threading.Lock()


def start_pull(kind: str) -> PullJob:
    global _job
    with _job_lock:
        if _job and not _job.done:
            return _job
        _job = PullJob(kind)
        target = pull_sysdiagnose if kind == "sysdiagnose" else pull_luma
        threading.Thread(target=_wrap, args=(target, _job), daemon=True).start()
        return _job


def current_job() -> PullJob | None:
    return _job


def _wrap(fn, job: PullJob) -> None:
    try:
        job.capture_id = fn(job)
    except Exception as e:  # surfaced to the GUI
        job.error = str(e)
    finally:
        job.done = True


def pull_sysdiagnose(job: PullJob) -> str:
    status = device_status()
    if not status["connected"]:
        raise RuntimeError(status["message"])
    job.say(f"Connected to {status['name']}.")
    incoming = store.ROOT / "captures" / ".incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    job.say("Copying diagnostic logs from the phone (this can take a minute)…")
    r = _run(["idevicecrashreport", "-k", "-f", "sysdiagnose", str(incoming)], 900)
    if r.returncode != 0:
        raise RuntimeError("idevicecrashreport failed: " + (r.stderr or r.stdout).strip()[-400:])
    tars = sorted(incoming.rglob("sysdiagnose*.tar.gz"), key=lambda p: p.stat().st_mtime)
    if not tars:
        raise RuntimeError("No sysdiagnose found on the phone yet. It takes 5-10 minutes after the "
                           "button press; try again shortly. (Check Settings › Privacy & Security › "
                           "Analytics & Improvements › Analytics Data for a sysdiagnose_… entry.)")
    newest = tars[-1]
    job.say(f"Reading {newest.name}…")
    pklgs = _read_pklg_members(newest)
    if not pklgs:
        raise RuntimeError("That sysdiagnose has no Bluetooth packet log. Is the Bluetooth logging "
                           "profile installed (Settings › General › VPN & Device Management), and did "
                           "you restart the phone after installing it?")
    name = newest.name.removesuffix(".tar.gz").replace("sysdiagnose_", "iPhone ")
    path = store.new_capture(name, "sysdiagnose")
    for member_name, data in pklgs:
        store.add_file(path, member_name, data)
        job.say(f"Saved {member_name} ({len(data) // 1024} KB).")
    store.load(path.name)
    job.say("Decoded.")
    return path.name


def _read_pklg_members(tar_path: Path) -> list[tuple[str, bytes]]:
    """Reads *.pklg members only. Nothing is extracted to disk, so paths in the archive are never trusted."""
    out = []
    with tarfile.open(tar_path, "r:gz") as tar:
        for m in tar:
            if not m.isfile() or not m.name.endswith(".pklg") or m.size > MAX_MEMBER:
                continue
            f = tar.extractfile(m)
            if f:
                out.append((Path(m.name).name, f.read()))
    return out


def pull_luma(job: PullJob) -> str:
    status = device_status()
    if not status["connected"]:
        raise RuntimeError(status["message"])
    container = config()["luma_container"]
    tmp = store.ROOT / "captures" / ".incoming"
    tmp.mkdir(parents=True, exist_ok=True)
    out = tmp / "luma-diagnostics.txt"
    out.unlink(missing_ok=True)
    job.say(f"Reading Documents/diagnostics.txt from {container}…")
    r = _run(["afcclient", "--container", container, "get", "/Documents/diagnostics.txt", str(out)], 60)
    if not out.exists():
        raise RuntimeError("Couldn't read Luma's diagnostics file: " + (r.stderr or r.stdout).strip()[-300:]
                           + " Open Luma once so it writes the file.")
    path = store.new_capture("Luma log", "luma")
    store.add_file(path, "luma.txt", out.read_bytes())
    store.load(path.name)
    job.say("Imported.")
    return path.name
