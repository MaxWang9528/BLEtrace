"""Capture library on disk.

captures/<id>/
    meta.json        {id, name, created, source, files}
    *.pklg|*.btsnoop|luma.txt   the source data (never modified)
    notes.json       {notes: {"<event index>": text}, labels: {"<dev>|<handle>": text}}
"""

from __future__ import annotations

import json
import re
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path

from .capture_io import read_capture
from .decode import Trace, decode
from . import luma

ROOT = Path(__file__).resolve().parent.parent
CAPTURES = ROOT / "captures"
ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")

_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()


def _safe_id(capture_id: str) -> Path:
    if not ID_RE.match(capture_id) or capture_id.startswith("."):
        raise KeyError(capture_id)
    path = CAPTURES / capture_id
    if not (path / "meta.json").exists():
        raise KeyError(capture_id)
    return path


def new_capture(name: str, source: str) -> Path:
    CAPTURES.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")[:40] or "capture"
    capture_id = f"{stamp}-{slug}"
    n = 1
    while (CAPTURES / capture_id).exists():
        n += 1
        capture_id = f"{stamp}-{slug}-{n}"
    path = CAPTURES / capture_id
    path.mkdir()
    meta = {"id": capture_id, "name": name, "created": time.time(), "source": source, "files": []}
    (path / "meta.json").write_text(json.dumps(meta, indent=2))
    return path


def add_file(path: Path, filename: str, data: bytes) -> None:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(filename).name) or "capture.bin"
    (path / safe).write_bytes(data)
    meta = json.loads((path / "meta.json").read_text())
    meta["files"].append(safe)
    (path / "meta.json").write_text(json.dumps(meta, indent=2))


def import_file(src: Path, name: str | None = None) -> str:
    data = src.read_bytes()
    path = new_capture(name or src.stem, "file")
    add_file(path, src.name, data)
    load(path.name)  # validate now so a bad file fails at import time
    return path.name


def import_bytes(filename: str, data: bytes, name: str | None = None) -> str:
    path = new_capture(name or Path(filename).stem, "upload")
    add_file(path, filename, data)
    try:
        load(path.name)
    except Exception:
        shutil.rmtree(path)
        raise
    return path.name


def list_captures() -> list[dict]:
    if not CAPTURES.exists():
        return []
    out = []
    for p in CAPTURES.iterdir():
        meta_file = p / "meta.json"
        if p.is_dir() and meta_file.exists():
            try:
                out.append(json.loads(meta_file.read_text()))
            except json.JSONDecodeError:
                continue
    return sorted(out, key=lambda m: -m["created"])


def delete(capture_id: str) -> None:
    shutil.rmtree(_safe_id(capture_id))
    _cache.pop(capture_id, None)


def rename(capture_id: str, name: str) -> None:
    path = _safe_id(capture_id)
    meta = json.loads((path / "meta.json").read_text())
    meta["name"] = name.strip()[:120] or meta["name"]
    (path / "meta.json").write_text(json.dumps(meta, indent=2))


def load(capture_id: str) -> dict:
    """Decoded capture (cached until its files change)."""
    path = _safe_id(capture_id)
    meta = json.loads((path / "meta.json").read_text())
    mtime = max((path / f).stat().st_mtime for f in meta["files"]) if meta["files"] else 0
    with _lock:
        hit = _cache.get(capture_id)
        if hit and hit[0] == mtime:
            data = hit[1]
        else:
            data = _decode_files(path, meta["files"]).to_json()
            _cache[capture_id] = (mtime, data)
    return {"meta": meta, **data, "annotations": read_notes(capture_id)}


def _decode_files(path: Path, files: list[str]) -> Trace:
    luma_files = [f for f in files if f.endswith(".txt")]
    if luma_files:
        return luma.parse((path / luma_files[0]).read_text("utf-8", "replace"))
    records = []
    for f in files:
        records += read_capture(path / f)
    return decode(records)


def read_notes(capture_id: str) -> dict:
    f = _safe_id(capture_id) / "notes.json"
    if f.exists():
        try:
            return json.loads(f.read_text())
        except json.JSONDecodeError:
            pass
    return {"notes": {}, "labels": {}}


def write_note(capture_id: str, scope: str, key: str, text: str) -> dict:
    if scope not in ("notes", "labels"):
        raise ValueError(scope)
    notes = read_notes(capture_id)
    text = text.strip()[:2000]
    if text:
        notes[scope][key] = text
    else:
        notes[scope].pop(key, None)
    (_safe_id(capture_id) / "notes.json").write_text(json.dumps(notes, indent=2))
    return notes
