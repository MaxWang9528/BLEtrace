"use strict";

// ---------------------------------------------------------------- state
const S = {
  captures: [],
  id: null,
  data: null,          // {meta, devices, handles, events, annotations}
  rows: [],            // filtered rows: {ev} or {gap: seconds}
  changed: new Map(),  // event index -> Set of changed byte positions
  sumBytes: new Map(), // group key -> number of trailing checksum bytes
  selected: null,      // event index
  hiddenDevs: new Set(),
  hiddenHandles: new Set(),
  show: { values: true, reads: false, link: true, notes: false },
  dedupe: false,
  gap: 1,
  search: "",
  group: null,         // pattern group key filter
  tab: "timeline",
  patterns: null,
};

const VALUE_OPS = new Set([0x12, 0x52, 0x1b, 0x1d, 0xd2, 0x16]);
const KNOWN = {
  "1800": "Generic Access", "1801": "Generic Attribute", "180A": "Device Info", "180F": "Battery",
  "2A00": "Device Name", "2A01": "Appearance", "2A05": "Service Changed", "2A19": "Battery Level", "2902": "CCCD",
};
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const hex2 = (n) => n.toString(16).toUpperCase().padStart(2, "0");
const hexHandle = (h) => (typeof h === "number" ? "0x" + h.toString(16).toUpperCase().padStart(4, "0") : "");
const bytesOf = (hex) => { const out = []; for (let i = 0; i + 1 < hex.length; i += 2) out.push(parseInt(hex.slice(i, i + 2), 16)); return out; };

async function api(path, opts = {}) {
  const res = await fetch("/api/" + path, opts);
  const body = await res.json().catch(() => ({ error: res.statusText }));
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}
const post = (path, obj) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(obj) });

// ---------------------------------------------------------------- naming helpers
function devName(key) {
  const d = S.data?.devices?.[key];
  return (d && d.name) || key || "";
}
function handleInfo(dev, h) {
  return S.data?.handles?.[dev]?.[String(h)] || {};
}
function handleName(dev, h) {
  if (h == null) return "";
  const label = S.data.annotations.labels[`${dev}|${h}`];
  if (label) return label;
  const info = handleInfo(dev, h);
  if (info.uuid) return KNOWN[info.uuid] ? `${info.uuid} ${KNOWN[info.uuid]}` : info.uuid;
  return hexHandle(h);
}
function groupKey(ev) {
  return `${ev.dev}|${ev.handle}|${ev.dir}|${ev.value.length / 2}|${ev.value.slice(0, 2)}`;
}
function clock(t) {
  const d = new Date(t * 1000);
  return d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

// ---------------------------------------------------------------- loading
async function refreshCaptures(selectId) {
  S.captures = await api("captures");
  const sel = $("#capture");
  sel.innerHTML = S.captures.length
    ? S.captures.map((c) => `<option value="${esc(c.id)}">${esc(c.name)} · ${esc(new Date(c.created * 1000).toLocaleString())}</option>`).join("")
    : `<option value="">No captures yet</option>`;
  const id = selectId || S.id || S.captures[0]?.id || null;
  if (id) sel.value = id;
  await loadCapture(id);
}

async function loadCapture(id) {
  S.id = id;
  S.selected = null;
  S.group = null;
  S.patterns = null;
  ["#rename", "#delete", "#export"].forEach((s) => $(s).toggleAttribute("disabled", !id));
  if (!id) {
    S.data = null;
    renderAll();
    return;
  }
  $("#export").href = `/api/captures/${encodeURIComponent(id)}/export.csv`;
  S.data = await api("captures/" + encodeURIComponent(id));
  computeDiffs();
  renderAll();
}

// For each packet, which bytes differ from the previous packet of the same shape on the same
// characteristic. This is what makes "red, then green, then blue" jump out.
function computeDiffs() {
  S.changed.clear();
  S.sumBytes.clear();
  const last = new Map();
  const frames = new Map();
  for (const ev of S.data.events) {
    if (ev.kind !== "att" || !VALUE_OPS.has(ev.op) || !ev.value) continue;
    const key = groupKey(ev);
    const cur = bytesOf(ev.value);
    const prev = last.get(key);
    if (prev) {
      const set = new Set();
      cur.forEach((b, i) => { if (b !== prev[i]) set.add(i); });
      S.changed.set(ev.i, set);
    }
    last.set(key, cur);
    if (!frames.has(key)) frames.set(key, new Set());
    frames.get(key).add(ev.value);
  }
}

// ---------------------------------------------------------------- filtering
function visible(ev) {
  if (ev.dev && S.hiddenDevs.has(ev.dev)) return false;
  if (ev.handle != null && S.hiddenHandles.has(`${ev.dev}|${ev.handle}`)) return false;
  if (ev.kind === "att") {
    const isValue = VALUE_OPS.has(ev.op);
    if (isValue && !S.show.values) return false;
    if (!isValue && !S.show.reads) return false;
  } else if (ev.kind === "link" && !S.show.link) return false;
  else if (ev.kind === "note" && !S.show.notes) return false;
  if (S.group && !(ev.kind === "att" && ev.value && groupKey(ev) === S.group)) return false;
  if (S.search) {
    const q = S.search;
    const hexq = q.replace(/[\s:,-]/g, "").toUpperCase();
    const note = S.data.annotations.notes[String(ev.i)] || "";
    const hay = [ev.text, ev.extra, note, devName(ev.dev), ev.opName].join(" ").toLowerCase();
    const hexHit = /^[0-9A-F]+$/.test(hexq) && hexq.length >= 2 && (ev.value || "").includes(hexq);
    if (!hexHit && !hay.includes(q.toLowerCase())) return false;
  }
  return true;
}

function buildRows() {
  S.rows = [];
  if (!S.data) return;
  let prevT = null;
  const lastValue = new Map();
  for (const ev of S.data.events) {
    if (!visible(ev)) continue;
    if (S.dedupe && ev.value && ev.kind === "att") {
      const k = `${ev.dev}|${ev.handle}|${ev.dir}`;
      if (lastValue.get(k) === ev.value) continue;
      lastValue.set(k, ev.value);
    }
    if (prevT !== null && ev.t - prevT >= S.gap) S.rows.push({ gap: ev.t - prevT });
    prevT = ev.t;
    S.rows.push({ ev });
  }
}

// ---------------------------------------------------------------- rendering
function renderAll() {
  buildRows();
  renderSide();
  renderEmpty();
  renderRows(true);
  renderStrip();
  renderDetail();
  if (S.tab === "patterns") renderPatterns();
  const total = S.data ? S.data.events.length : 0;
  const shown = S.rows.filter((r) => r.ev).length;
  $("#count").textContent = S.data ? `${shown.toLocaleString()} of ${total.toLocaleString()} packets` : "";
  const gf = $("#group-filter");
  gf.hidden = !S.group;
  if (S.group) {
    const [dev, h, dir, len, prefix] = S.group.split("|");
    gf.querySelector("span").textContent = `Only ${dir === "tx" ? "sent" : "received"} ${len}-byte ${prefix}… on ${handleName(dev, h === "undefined" ? null : Number(h))}`;
  }
}

function renderEmpty() {
  const empty = $("#empty");
  const has = !!S.data;
  empty.hidden = has;
  $("#timeline").hidden = !has || S.tab !== "timeline";
  $("#patterns").hidden = !has || S.tab !== "patterns";
  if (has) return;
  empty.innerHTML = `
    <h2>Capture what the vendor app sends</h2>
    <ol>
      <li>On the iPhone, install Apple's <b>Bluetooth</b> logging profile from
        <code>developer.apple.com/bug-reporting/profiles-and-logs</code>, then restart the phone.</li>
      <li>Close every other app that talks to the device. Open the vendor app and do one thing at a time,
        a few seconds apart: off, on, red, green, blue, brightness high, brightness low. Write the order down.</li>
      <li>Hold both volume buttons and the side button for about a second, until the phone vibrates.
        iOS takes 5 to 10 minutes to build the report.</li>
      <li>Keep the phone plugged in and unlocked, then choose <b>Pull capture from iPhone</b>.</li>
    </ol>
    <p class="muted">Already have a <code>.pklg</code> from a Mac or an Android <code>btsnoop_hci.log</code>? Use <b>Open file…</b>.</p>`;
}

function renderSide() {
  const devs = $("#devices");
  const handles = $("#handles");
  if (!S.data) { devs.innerHTML = ""; handles.innerHTML = ""; return; }
  const counts = new Map();
  for (const ev of S.data.events) {
    if (ev.handle == null) continue;
    const k = `${ev.dev}|${ev.handle}`;
    counts.set(k, (counts.get(k) || 0) + 1);
  }
  const devKeys = Object.keys(S.data.devices).sort((a, b) => S.data.devices[b].packets - S.data.devices[a].packets);
  devs.innerHTML = devKeys.map((k) => {
    const d = S.data.devices[k];
    const sub = [d.name ? k : "", (d.advServices || []).join(" "), d.mfr ? "mfr " + d.mfr.slice(0, 16) : ""].filter(Boolean).join("  ");
    return `<label class="item"><input type="checkbox" data-dev="${esc(k)}" ${S.hiddenDevs.has(k) ? "" : "checked"}>
      <span class="main">${esc(d.name || k)}${sub ? `<span class="sub">${esc(sub)}</span>` : ""}</span>
      <span class="n">${d.packets}</span></label>`;
  }).join("") || `<p class="hint">No devices.</p>`;

  let html = "";
  for (const dev of devKeys) {
    const hs = Object.entries(S.data.handles[dev] || {}).map(([h, info]) => [Number(h), info]).sort((a, b) => a[0] - b[0]);
    if (!hs.length) continue;
    html += `<div class="dev-head">${esc(devName(dev))}</div>`;
    for (const [h, info] of hs) {
      const k = `${dev}|${h}`;
      const sub = [hexHandle(h), info.props, info.service ? "in " + info.service : ""].filter(Boolean).join("  ");
      html += `<label class="item"><input type="checkbox" data-handle="${esc(k)}" ${S.hiddenHandles.has(k) ? "" : "checked"}>
        <span class="main" data-label="${esc(k)}" title="Double-click to label">${esc(handleName(dev, h))}<span class="sub">${esc(sub)}</span></span>
        <span class="n">${counts.get(k) || 0}</span></label>`;
    }
  }
  handles.innerHTML = html || `<p class="hint">No characteristics used.</p>`;
}

function rowHTML(row) {
  if (row.gap != null) return `<div class="row gap"><span>${row.gap.toFixed(1)} s pause</span></div>`;
  const ev = row.ev;
  const note = S.data.annotations.notes[String(ev.i)];
  const prev = prevTime.get(ev.i);
  const delta = prev != null ? "+" + (ev.t - prev).toFixed(3) : "";
  let body;
  if (ev.kind === "att" && ev.value) {
    const ch = S.changed.get(ev.i);
    body = bytesOf(ev.value).map((b, i) => (ch && ch.has(i) ? `<span class="c">${hex2(b)}</span>` : hex2(b))).join(" ");
    if (ev.extra) body += ` <span class="text">${esc(ev.extra)}</span>`;
  } else {
    body = `<span class="text">${esc(ev.extra || ev.text || "")}</span>`;
  }
  if (note) body += `<span class="note">${esc(note)}</span>`;
  const cls = ["row", ev.dir, ev.kind !== "att" ? ev.kind : "", ev.i === S.selected ? "sel" : ""].join(" ");
  return `<div class="${cls}" data-i="${ev.i}">
    <span class="num">${ev.i}</span><span class="time">${clock(ev.t)}</span><span class="delta">${delta}</span>
    <span class="dir">${ev.dir === "tx" ? "→" : "←"}</span><span>${esc(devName(ev.dev))}</span>
    <span>${esc(ev.opName || (ev.kind === "link" ? "Link" : "Note"))}</span>
    <span>${esc(handleName(ev.dev, ev.handle))}</span><span class="bytes">${body}</span></div>`;
}

// Virtualized list: only rows in view are in the DOM, so 100k-packet captures stay smooth.
let prevTime = new Map();
function renderRows(reset) {
  const vp = $("#rows-viewport");
  const rowH = 26;
  if (reset) {
    prevTime = new Map();
    let last = null;
    for (const r of S.rows) if (r.ev) { if (last) prevTime.set(r.ev.i, last.t); last = r.ev; }
    $("#rows-spacer").style.height = S.rows.length * rowH + "px";
  }
  const first = Math.max(0, Math.floor(vp.scrollTop / rowH) - 10);
  const last = Math.min(S.rows.length, first + Math.ceil(vp.clientHeight / rowH) + 20);
  const rows = $("#rows");
  rows.style.transform = `translateY(${first * rowH}px)`;
  rows.innerHTML = S.rows.slice(first, last).map(rowHTML).join("");
  drawStripWindow();
}

function scrollToEvent(i) {
  const idx = S.rows.findIndex((r) => r.ev && r.ev.i === i);
  if (idx < 0) return;
  const vp = $("#rows-viewport");
  const top = idx * 26;
  if (top < vp.scrollTop || top > vp.scrollTop + vp.clientHeight - 52) vp.scrollTop = top - vp.clientHeight / 3;
  renderRows(false);
}

function select(i, scroll = true) {
  S.selected = i;
  if (scroll) scrollToEvent(i); else renderRows(false);
  renderDetail();
}

// ---------------------------------------------------------------- trace strip
let stripGeom = null;
function renderStrip() {
  const c = $("#strip");
  const dpr = window.devicePixelRatio || 1;
  const w = c.clientWidth, h = c.clientHeight;
  c.width = w * dpr; c.height = h * dpr;
  const g = c.getContext("2d");
  g.setTransform(dpr, 0, 0, dpr, 0, 0);
  g.clearRect(0, 0, w, h);
  const evs = S.rows.filter((r) => r.ev).map((r) => r.ev);
  if (!evs.length) { stripGeom = null; return; }
  const pad = 14;
  const t0 = evs[0].t, t1 = evs[evs.length - 1].t;
  const span = Math.max(t1 - t0, 0.001);
  const x = (t) => pad + ((t - t0) / span) * (w - pad * 2);
  const mid = h / 2 + 4;
  stripGeom = { t0, span, pad, w, x, evs };

  // Time ruler.
  g.font = "11px Bahnschrift, Segoe UI, sans-serif";
  g.fillStyle = "#5d6a82";
  g.strokeStyle = "#2c3549";
  const step = niceStep(span / Math.max(2, Math.floor(w / 110)));
  for (let t = Math.ceil(t0 / step) * step; t <= t1; t += step) {
    const px = x(t);
    g.beginPath(); g.moveTo(px, 16); g.lineTo(px, h); g.stroke();
    const label = step < 1 ? clock(t).slice(step < 0.1 ? 3 : 3, step < 0.1 ? 12 : 11) : new Date(t * 1000).toLocaleTimeString([], { hour12: false });
    g.fillText(label, px + 3, 12);
  }
  g.strokeStyle = "#34405a";
  g.beginPath(); g.moveTo(pad, mid); g.lineTo(w - pad, mid); g.stroke();

  // Packets: sent rise above the line, received hang below; height = payload size.
  for (const ev of evs) {
    const px = Math.round(x(ev.t)) + 0.5;
    const len = ev.value ? ev.value.length / 2 : 2;
    const hgt = Math.min(30, 6 + len * 1.4);
    if (ev.kind === "att") {
      g.strokeStyle = ev.dir === "tx" ? "#f0a73a" : "#4cc2c4";
      g.beginPath();
      if (ev.dir === "tx") { g.moveTo(px, mid - 1); g.lineTo(px, mid - hgt); } else { g.moveTo(px, mid + 1); g.lineTo(px, mid + hgt); }
      g.stroke();
    } else {
      g.fillStyle = "#8e9ab0";
      g.fillRect(px - 1.5, mid - 1.5, 3, 3);
    }
  }
  // Annotated packets get a magenta flag with the note text.
  g.fillStyle = "#e06a9e";
  g.font = "11px Bahnschrift, Segoe UI, sans-serif";
  for (const ev of evs) {
    const note = S.data.annotations.notes[String(ev.i)];
    if (!note) continue;
    const px = x(ev.t);
    g.beginPath(); g.moveTo(px, h - 4); g.lineTo(px - 4, h - 12); g.lineTo(px + 4, h - 12); g.closePath(); g.fill();
    g.fillText(note.slice(0, 18), px + 6, h - 4);
  }
  drawStripWindow();
}

function niceStep(raw) {
  const steps = [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 1800, 3600];
  return steps.find((s) => s >= raw) || 7200;
}

function drawStripWindow() {
  const c = $("#strip");
  if (!stripGeom) return;
  let overlay = $("#strip-window");
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.id = "strip-window";
    overlay.style.cssText = "position:absolute;top:16px;bottom:0;border:1px solid #8e9ab055;background:#8e9ab012;pointer-events:none";
    c.parentElement.appendChild(overlay);
  }
  const vp = $("#rows-viewport");
  const first = Math.floor(vp.scrollTop / 26);
  const last = Math.min(S.rows.length - 1, first + Math.ceil(vp.clientHeight / 26));
  const a = S.rows.slice(first).find((r) => r.ev)?.ev;
  const b = S.rows.slice(0, last + 1).reverse().find((r) => r.ev)?.ev;
  if (!a || !b) { overlay.hidden = true; return; }
  overlay.hidden = false;
  const x1 = stripGeom.x(a.t), x2 = stripGeom.x(b.t);
  overlay.style.left = x1 - 2 + "px";
  overlay.style.width = Math.max(4, x2 - x1 + 4) + "px";
}

function stripEventAt(clientX) {
  if (!stripGeom) return null;
  const rect = $("#strip").getBoundingClientRect();
  const t = stripGeom.t0 + ((clientX - rect.left - stripGeom.pad) / (stripGeom.w - stripGeom.pad * 2)) * stripGeom.span;
  const evs = stripGeom.evs;
  let lo = 0, hi = evs.length - 1;
  while (lo < hi) { const m = (lo + hi) >> 1; if (evs[m].t < t) lo = m + 1; else hi = m; }
  const cand = [evs[lo], evs[lo - 1]].filter(Boolean);
  return cand.sort((p, q) => Math.abs(p.t - t) - Math.abs(q.t - t))[0];
}

// ---------------------------------------------------------------- detail panel
async function renderDetail() {
  const box = $("#detail");
  const ev = S.data?.events?.[S.selected];
  if (!ev) {
    box.innerHTML = S.data
      ? `<p class="hint">Select a packet to inspect its bytes. Use the arrow keys to step through packets.</p>
         <h3>This capture</h3><ul>${Object.entries(S.data.stats || {}).filter(([, v]) => typeof v === "number").map(([k, v]) => `<li>${esc(k)}: ${v.toLocaleString()}</li>`).join("")}</ul>
         ${(S.data.stats?.advertisers_named || []).length ? `<h3>Devices seen advertising</h3><p class="mono">${esc(S.data.stats.advertisers_named.join(", "))}</p>` : ""}`
      : "";
    return;
  }
  const info = handleInfo(ev.dev, ev.handle);
  const note = S.data.annotations.notes[String(ev.i)] || "";
  const bytes = ev.value ? bytesOf(ev.value) : [];
  const ch = S.changed.get(ev.i) || new Set();
  const grid = bytes.map((b, i) => `<div class="byte${ch.has(i) ? " c" : ""}"><span class="idx">${i}</span>${hex2(b)}<span class="dec">${b}</span></div>`).join("");
  const ascii = bytes.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : "·")).join("");
  box.innerHTML = `
    <h2>${esc(ev.opName || ev.kind)} ${ev.dir === "tx" ? "sent" : "received"}</h2>
    <p class="meta"><b>#${ev.i}</b> at ${esc(clock(ev.t))} · ${esc(devName(ev.dev))}${ev.handle != null ? ` · <b>${esc(handleName(ev.dev, ev.handle))}</b> (${hexHandle(ev.handle)}${info.props ? ", " + esc(info.props) : ""})` : ""}</p>
    ${bytes.length ? `<div class="bytegrid">${grid}</div>
      <p class="mono">${esc(ev.value.match(/../g).join(" "))}</p>
      <p class="mono">${esc(ascii)}</p>` : ""}
    ${ev.extra || ev.text ? `<p class="mono">${esc(ev.extra || ev.text)}</p>` : ""}
    ${bytes.length >= 3 ? `<h3>Checksum guesses</h3><ul id="sums"><li class="hint">Checking…</li></ul>` : ""}
    <h3>Note</h3>
    <textarea id="note" placeholder="What did you do in the app? e.g. tapped red">${esc(note)}</textarea>
    <div class="row-actions">
      <button id="save-note">Save note</button>
      ${bytes.length ? `<button id="copy-hex">Copy bytes</button>` : ""}
      ${ev.kind === "att" && ev.value ? `<button id="same-shape">Show packets like this</button>` : ""}
      ${ev.handle != null ? `<button id="label-handle">Label characteristic</button>` : ""}
      <span id="note-saved" class="saved" hidden>Saved</span>
    </div>`;
  $("#save-note").onclick = saveNote;
  $("#note").onkeydown = (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) saveNote(); };
  if ($("#copy-hex")) $("#copy-hex").onclick = () => navigator.clipboard.writeText(ev.value.match(/../g).join(" "));
  if ($("#same-shape")) $("#same-shape").onclick = () => { S.group = groupKey(ev); renderAll(); scrollToEvent(ev.i); };
  if ($("#label-handle")) $("#label-handle").onclick = () => editLabel(`${ev.dev}|${ev.handle}`);
  if (bytes.length >= 3) {
    const list = await api(`captures/${encodeURIComponent(S.id)}/checksum?hex=${ev.value}`).catch(() => []);
    const ul = $("#sums");
    if (ul && S.selected === ev.i) ul.innerHTML = list.length ? list.slice(0, 8).map((s) => `<li>${esc(s)}</li>`).join("") : `<li class="hint">No common checksum matches the last bytes.</li>`;
  }
}

async function saveNote() {
  const ev = S.data.events[S.selected];
  S.data.annotations = await post(`captures/${encodeURIComponent(S.id)}/note`, { scope: "notes", key: ev.i, text: $("#note").value });
  renderRows(false);
  renderStrip();
  const s = $("#note-saved");
  if (s) { s.hidden = false; setTimeout(() => (s.hidden = true), 1200); }
}

async function editLabel(key) {
  const [dev, h] = key.split("|");
  const current = S.data.annotations.labels[key] || "";
  const text = prompt(`Name for ${handleName(dev, Number(h))} (${hexHandle(Number(h))}). Leave empty to clear.`, current);
  if (text === null) return;
  S.data.annotations = await post(`captures/${encodeURIComponent(S.id)}/note`, { scope: "labels", key, text });
  renderAll();
}

// ---------------------------------------------------------------- patterns tab
async function renderPatterns() {
  const box = $("#patterns");
  if (!S.data) return;
  if (!S.patterns) {
    box.innerHTML = `<p class="hint">Grouping packets…</p>`;
    S.patterns = await api(`captures/${encodeURIComponent(S.id)}/patterns`);
  }
  const groups = S.patterns.filter((g) => !S.hiddenDevs.has(g.dev) && !S.hiddenHandles.has(`${g.dev}|${g.handle}`));
  if (!groups.length) { box.innerHTML = `<p class="hint">No writes or notifications in this capture.</p>`; return; }
  box.innerHTML = groups.map((g, gi) => {
    const sumN = g.checksum ? (g.checksum.startsWith("CRC-16") ? 2 : 1) : 0;
    const cells = g.positions.map((p) => {
      const isSum = p.i >= g.length - sumN;
      const title = p.constant ? "" : `title="${esc(p.values.join(" ") + (p.more ? ` +${p.more} more` : ""))}"`;
      const label = p.constant ? p.values[0] : `${p.values.length + p.more}×`;
      return `<div class="cell${p.constant ? "" : " var"}${isSum ? " sum" : ""}" ${title}><span class="idx">${p.i}</span>${esc(label)}</div>`;
    }).join("");
    const key = `${g.dev}|${g.handle}|${g.dir}|${g.length}|${g.prefix}`;
    return `<section class="pattern ${g.dir}">
      <h3>${esc(handleName(g.dev, g.handle))} <span class="meta">${esc(devName(g.dev))} · ${g.length} bytes starting ${esc(g.prefix)} · ${g.count} packets, ${g.distinct} different</span></h3>
      <div class="cells">${cells}</div>
      ${g.checksum ? `<p class="sumline">Checksum: ${esc(g.checksum)} (dashed cells)</p>` : ""}
      <button data-group="${esc(key)}" data-first="${g.first}">Show in timeline</button>
    </section>`;
  }).join("");
}

// ---------------------------------------------------------------- pulling & importing
async function startPull(kind) {
  const job = $("#job");
  job.hidden = false;
  $("#job-title").textContent = kind === "luma" ? "Pulling Luma's log" : "Pulling capture from iPhone";
  $("#job-log").innerHTML = "";
  $("#job-close").hidden = true;
  try {
    await post("pull", { kind });
  } catch (e) {
    return jobDone({ error: e.message, log: [] });
  }
  const poll = async () => {
    const st = await api("pull").catch((e) => ({ done: true, error: e.message, log: [] }));
    $("#job-log").innerHTML = st.log.map((l) => `<li>${esc(l)}</li>`).join("");
    if (st.done) return jobDone(st);
    setTimeout(poll, 800);
  };
  poll();
}

async function jobDone(st) {
  const log = $("#job-log");
  log.insertAdjacentHTML("beforeend", st.error ? `<li class="err">${esc(st.error)}</li>` : `<li class="ok">Done. Showing the new capture.</li>`);
  $("#job-close").hidden = false;
  if (st.capture) await refreshCaptures(st.capture);
  if (!st.error) setTimeout(() => ($("#job").hidden = true), 2500);
}

async function importFile(file) {
  const job = $("#job");
  job.hidden = false;
  $("#job-title").textContent = `Opening ${file.name}`;
  $("#job-log").innerHTML = "";
  try {
    const { id } = await api("import", { method: "POST", headers: { "X-Filename": file.name }, body: await file.arrayBuffer() });
    await jobDone({ capture: id, log: [] });
  } catch (e) {
    await jobDone({ error: `Couldn't read that file: ${e.message}`, log: [] });
  }
}

async function checkPhone() {
  const st = await api("device").catch(() => ({ connected: false, message: "bletrace server not reachable" }));
  const el = $("#phone");
  el.classList.toggle("on", st.connected);
  el.textContent = st.connected ? st.name : "No iPhone";
  el.title = st.connected ? `Connected over USB (${st.udid})` : st.message;
}

// ---------------------------------------------------------------- wiring
function bind() {
  $("#capture").onchange = (e) => loadCapture(e.target.value);
  $("#rename").onclick = async () => {
    const cur = S.captures.find((c) => c.id === S.id);
    const name = prompt("Capture name", cur?.name || "");
    if (name) { await post(`captures/${encodeURIComponent(S.id)}/rename`, { name }); refreshCaptures(S.id); }
  };
  $("#delete").onclick = async () => {
    const cur = S.captures.find((c) => c.id === S.id);
    if (!confirm(`Delete "${cur?.name}" and its notes? This can't be undone.`)) return;
    await post(`captures/${encodeURIComponent(S.id)}/delete`, {});
    S.id = null;
    refreshCaptures();
  };
  $("#pull").onclick = () => startPull("sysdiagnose");
  $("#pull-luma").onclick = () => startPull("luma");
  $("#open").onclick = () => $("#file").click();
  $("#file").onchange = (e) => { if (e.target.files[0]) importFile(e.target.files[0]); e.target.value = ""; };
  $("#job-close").onclick = () => ($("#job").hidden = true);

  document.querySelectorAll("[data-show]").forEach((cb) => (cb.onchange = () => { S.show[cb.dataset.show] = cb.checked; renderAll(); }));
  $("#dedupe").onchange = (e) => { S.dedupe = e.target.checked; renderAll(); };
  $("#gap").onchange = (e) => { S.gap = Number(e.target.value); renderAll(); };
  let t;
  $("#search").oninput = (e) => { clearTimeout(t); t = setTimeout(() => { S.search = e.target.value.trim(); renderAll(); }, 150); };
  $("#clear-group").onclick = () => { S.group = null; renderAll(); };

  $("#devices").onchange = (e) => {
    const k = e.target.dataset.dev;
    if (k == null) return;
    e.target.checked ? S.hiddenDevs.delete(k) : S.hiddenDevs.add(k);
    renderAll();
  };
  $("#handles").onchange = (e) => {
    const k = e.target.dataset.handle;
    if (k == null) return;
    e.target.checked ? S.hiddenHandles.delete(k) : S.hiddenHandles.add(k);
    renderAll();
  };
  $("#handles").ondblclick = (e) => {
    const el = e.target.closest("[data-label]");
    if (el) { e.preventDefault(); editLabel(el.dataset.label); }
  };

  document.querySelectorAll("[data-tab]").forEach((b) => (b.onclick = () => {
    S.tab = b.dataset.tab;
    document.querySelectorAll("[data-tab]").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
    renderEmpty();
    if (S.tab === "patterns") renderPatterns(); else renderRows(false);
  }));
  $("#patterns").onclick = (e) => {
    const b = e.target.closest("[data-group]");
    if (!b) return;
    S.group = b.dataset.group;
    $('[data-tab="timeline"]').click();
    renderAll();
    select(Number(b.dataset.first));
  };

  const vp = $("#rows-viewport");
  vp.onscroll = () => requestAnimationFrame(() => renderRows(false));
  $("#rows").onclick = (e) => {
    const r = e.target.closest("[data-i]");
    if (r) select(Number(r.dataset.i), false);
  };
  $("#timeline").onkeydown = (e) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const evRows = S.rows.filter((r) => r.ev);
    let idx = evRows.findIndex((r) => r.ev.i === S.selected);
    idx = e.key === "ArrowDown" ? Math.min(evRows.length - 1, idx + 1) : Math.max(0, idx - 1);
    if (evRows[idx]) select(evRows[idx].ev.i);
  };
  document.onkeydown = (e) => {
    if (e.key === "/" && document.activeElement.tagName !== "INPUT" && document.activeElement.tagName !== "TEXTAREA") {
      e.preventDefault();
      $("#search").focus();
    }
  };

  const strip = $("#strip");
  const tip = $("#strip-tip");
  strip.onmousemove = (e) => {
    const ev = stripEventAt(e.clientX);
    if (!ev) { tip.hidden = true; return; }
    tip.hidden = false;
    tip.textContent = `#${ev.i} ${clock(ev.t)} ${ev.dir === "tx" ? "→" : "←"} ${ev.value ? ev.value.match(/../g).slice(0, 10).join(" ") : ev.text || ev.extra || ""}`;
    const rect = strip.getBoundingClientRect();
    tip.style.left = Math.min(e.clientX - rect.left + 12, rect.width - tip.offsetWidth - 8) + "px";
  };
  strip.onmouseleave = () => (tip.hidden = true);
  strip.onclick = (e) => { const ev = stripEventAt(e.clientX); if (ev) select(ev.i); };
  window.onresize = () => { renderStrip(); renderRows(false); };
}

bind();
// Deep links: /?capture=<id>&select=<packet #>&tab=patterns
const params = new URLSearchParams(location.search);
refreshCaptures(params.get("capture")).then(() => {
  if (params.get("tab") === "patterns") $('[data-tab="patterns"]').click();
  if (params.has("select") && S.data) select(Number(params.get("select")));
}).catch((e) => { $("#empty").hidden = false; $("#empty").textContent = "Couldn't load captures: " + e.message; });
checkPhone();
setInterval(checkPhone, 5000);
