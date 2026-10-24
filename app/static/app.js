// TCsMonitor dashboard: vanilla JS, live over WebSocket.
"use strict";

// ================= helpers =================
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtMs = (v) => (v == null ? "-" : `${v < 10 ? v.toFixed(1) : Math.round(v)}ms`);
const fmtPct = (v) => (v == null ? "-" : `${v.toFixed(v < 10 && v % 1 ? 1 : 0)}%`);
const fmtBps = (b) => (b >= 1e6 ? `${(b / 1e6).toFixed(1)}M` : `${(b / 1e3).toFixed(0)}K`);
const fmtBytes = (b) => (b >= 1e9 ? `${(b / 1e9).toFixed(1)} GB` : b >= 1e6 ? `${(b / 1e6).toFixed(1)} MB` : `${(b / 1e3).toFixed(0)} KB`);
const timeStr = (d) => new Date(d).toLocaleTimeString([], { hour12: false });
const avg = (xs) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);

async function api(path, opts = {}) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts });
  if (res.status === 401) { location.href = "/login"; throw new Error("Not logged in"); }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const d = body.detail;
    throw new Error(Array.isArray(d) ? d.map((x) => x.msg.replace("Value error, ", "")).join("; ") : d || res.statusText);
  }
  return res.status === 204 ? null : res.json();
}
const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body || {}) });

function setNum(id, text) {           // flash a value when it changes
  const el = $(id);
  if (el.textContent === text) return;
  el.textContent = text;
  el.classList.remove("anim-flash"); void el.offsetWidth; el.classList.add("anim-flash");
}

function toast(text, kind = "down") {
  const t = document.createElement("div");
  t.className = `app-toast ${kind}`;
  t.textContent = text;
  $("toasts").append(t);
  setTimeout(() => t.remove(), 5000);
}

async function busy(btn, fn) {         // disable a button while a tool runs
  btn.disabled = true;
  try { await fn(); } finally { btn.disabled = false; }
}

// ================= views =================
const loaded = new Set();
function showView(name) {
  document.querySelectorAll(".app-view").forEach((v) => v.classList.toggle("active", v.dataset.view === name));
  document.querySelectorAll(".app-nav-tab").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  history.replaceState(null, "", `#${name}`);
  if (!loaded.has(name)) { loaded.add(name); onFirstOpen[name]?.(); }
}
const onFirstOpen = {
  packets: () => packetsInit(),
  lan: () => lanInit(),
  tools: () => loadWifi(),
  system: () => { loadInterfaces(); loadConnections(); },
};
$("nav").addEventListener("click", (e) => { if (e.target.dataset.view) showView(e.target.dataset.view); });
document.addEventListener("click", (e) => {     // ✕ collapses a window
  if (e.target.classList.contains("app-window-close")) e.target.closest(".app-window").classList.toggle("collapsed");
});

// ================= monitor =================
const SLOW_MS = 100;   // latency at or above this counts as "slow"
let hosts = new Map();
let selectedId = null;
let chart = null;

function renderHosts() {
  const rows = [...hosts.values()];
  const live = rows.filter((h) => h.enabled);
  const isSlow = (h) => h.status === "up" && ((h.last_latency_ms ?? 0) >= SLOW_MS || (h.loss_pct ?? 0) > 5);
  setNum("n-up", String(live.filter((h) => h.status === "up" && !isSlow(h)).length));
  setNum("n-down", String(live.filter((h) => h.status === "down").length));
  setNum("n-slow", String(live.filter(isSlow).length));
  const upt = avg(live.map((h) => h.uptime_24h).filter((v) => v != null));
  setNum("n-uptime", upt == null ? "--.--%" : `${upt.toFixed(2)}%`);
  $("readout").className = `main-readout-box ${upt == null || upt >= 99 ? "" : upt >= 95 ? "is-warn" : "is-bad"}`;
  const lat = avg(live.map((h) => h.last_latency_ms).filter((v) => v != null));
  const loss = avg(live.map((h) => h.loss_pct).filter((v) => v != null));
  const jit = avg(live.map((h) => h.jitter_ms).filter((v) => v != null));
  setNum("n-lat", fmtMs(lat)); setNum("n-loss", fmtPct(loss)); setNum("n-jit", fmtMs(jit));

  if (!rows.length) {
    $("host-rows").innerHTML = `<tr><td colspan="9" class="app-table-empty">No hosts yet. Add your router (Default Gateway from ipconfig).</td></tr>`;
    return;
  }
  $("host-rows").innerHTML = rows.map((h) => {
    const status = h.enabled ? h.status : "paused";
    const target = h.check_type === "tcp" ? `${h.address}:${h.port}` : h.address;
    const lossCls = h.loss_pct > 10 ? "is-bad" : h.loss_pct > 0 ? "is-warn" : "";
    const certCls = h.cert_days != null && h.cert_days < 14 ? "is-warn" : "";
    return `<tr data-id="${h.id}" class="${h.id === selectedId ? "selected" : ""} ${h.enabled ? "" : "disabled"}">
      <td><span class="app-pill ${status}">${status}</span></td>
      <td>${esc(h.name)}<span class="app-addr">${esc(target)}</span>
        ${h.last_error && h.enabled ? `<span class="app-err">${esc(h.last_error)}</span>` : ""}</td>
      <td class="col-sm-hide">${h.check_type.toUpperCase()}</td>
      <td>${fmtMs(h.last_latency_ms)}${h.enabled ? hostBar(h) : ""}</td>
      <td class="${lossCls}">${fmtPct(h.loss_pct)}</td>
      <td class="col-sm-hide">${fmtMs(h.jitter_ms)}</td>
      <td class="col-md-hide">${fmtPct(h.uptime_24h)}</td>
      <td class="col-md-hide ${certCls}">${h.cert_days == null ? "-" : `${h.cert_days}d`}</td>
      <td><button class="app-mini" data-act="toggle">${h.enabled ? "II" : "▶"}</button>
          <button class="app-mini danger" data-act="delete">✕</button></td></tr>`;
  }).join("");
}

function hostBar(h) {   // moodboard "host list" bar: width = latency, colour = health
  const down = h.status === "down";
  const lat = h.last_latency_ms ?? 0;
  const cls = down ? "down" : lat >= SLOW_MS ? "slow" : "";
  const width = down ? 100 : Math.max(3, Math.min(100, (lat / 200) * 100));
  return `<div class="main-host-bar ${cls}" style="width:${width}%"></div>`;
}

function renderTiming(t) {
  const parts = ["dns", "connect", "tls", "ttfb"].filter((k) => t && t[k] != null);
  if (parts.length < 2) { $("timing-wrap").hidden = true; return; }
  const total = parts.reduce((s, k) => s + t[k], 0) || 1;
  $("timing-wrap").hidden = false;
  $("timing-bar").innerHTML = parts.map((k) => `<div class="t-${k}" style="width:${(t[k] / total) * 100}%"></div>`).join("");
  $("timing-legend").innerHTML = parts.map((k) => `<span><i class="t-${k}"></i>${k.toUpperCase()} ${fmtMs(t[k])}</span>`).join("");
}

async function loadChart(id) {
  selectedId = id;
  renderHosts();
  const h = hosts.get(id);
  $("chart-title").textContent = `Latency: ${h.name}`;
  $("chart-hint").hidden = true;
  renderTiming(h.timings);
  const data = await api(`/api/hosts/${id}/history?limit=60`);
  const labels = data.map((r) => timeStr(r.timestamp));
  const values = data.map((r) => (r.success ? r.latency_ms : null));
  const fails = data.map((r) => (r.success ? null : 0));
  if (typeof Chart === "undefined") return;
  if (!chart) {
    Chart.defaults.font.family = "JetBrains Mono, monospace";
    Chart.defaults.font.size = 11;
    chart = new Chart($("latency-chart"), {
      type: "line",
      data: { labels, datasets: [
        { label: "Latency (ms)", data: values, borderColor: "#22D3EE", backgroundColor: "#22D3EE14", fill: true, tension: 0.25, pointRadius: 0, borderWidth: 2 },
        { label: "Failed", data: fails, borderColor: "#FF2E63", backgroundColor: "#FF2E63", showLine: false, pointRadius: 4, pointStyle: "circle" },
      ] },
      options: { animation: false, maintainAspectRatio: false,
        scales: { x: { ticks: { color: "#64748B", maxTicksLimit: 6 }, grid: { color: "#1C2A3A" } },
                  y: { beginAtZero: true, ticks: { color: "#64748B" }, grid: { color: "#1C2A3A" } } },
        plugins: { legend: { labels: { color: "#94A3B8", boxWidth: 8, boxHeight: 8 } } } },
    });
  } else {
    chart.data.labels = labels;
    chart.data.datasets[0].data = values;
    chart.data.datasets[1].data = fails;
    chart.update();
  }
}

function logLine(id, task, cls = "") {
  const tr = document.createElement("tr");
  tr.className = `anim-row-in ${cls}`;
  tr.innerHTML = `<td>${timeStr(Date.now())}</td><td>${esc(id)}</td><td>${esc(task)}</td>`;
  const body = $("log-rows");
  body.prepend(tr);
  while (body.children.length > 200) body.lastChild.remove();
}

async function refreshHosts() {
  const list = await api("/api/hosts");
  hosts = new Map(list.map((h) => [h.id, h]));
  renderHosts();
}

$("type-select").addEventListener("change", (e) => {
  $("port-label").hidden = e.target.value !== "tcp";
  $("addr-input").placeholder = e.target.value === "http" ? "https://example.com" : "192.168.1.1";
});

$("add-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const body = { name: f.get("name"), address: f.get("address").trim(), check_type: f.get("check_type") };
  if (body.check_type === "tcp") body.port = Number(f.get("port"));
  try {
    const h = await post("/api/hosts", body);
    hosts.set(h.id, h);
    renderHosts();
    logLine(h.id, `Host added: ${h.name}`);
    e.target.reset(); $("port-label").hidden = true; $("form-error").textContent = "";
  } catch (err) { $("form-error").textContent = err.message; }
});

$("host-rows").addEventListener("click", async (e) => {
  const row = e.target.closest("tr[data-id]");
  if (!row) return;
  const id = Number(row.dataset.id);
  const act = e.target.dataset.act;
  if (act === "delete") {
    if (!confirm(`Remove ${hosts.get(id).name}?`)) return;
    await api(`/api/hosts/${id}`, { method: "DELETE" });
    hosts.delete(id);
    if (selectedId === id) { selectedId = null; chart?.destroy(); chart = null; $("chart-hint").hidden = false; $("timing-wrap").hidden = true; }
    renderHosts();
  } else if (act === "toggle") {
    hosts.set(id, await api(`/api/hosts/${id}/toggle`, { method: "PATCH" }));
    renderHosts();
  } else {
    loadChart(id);
  }
});
$("check-now").addEventListener("click", () => post("/api/check-now"));

// ================= WebSocket =================
let ticks = 0;
function connectWs() {
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  ws.onopen = () => { $("conn-dot").classList.add("live"); $("conn-text").textContent = "live"; logLine("SYS", "WebSocket connected"); };
  ws.onclose = () => {
    $("conn-dot").classList.remove("live"); $("conn-text").textContent = "reconnecting";
    api("/api/system").catch(() => {});   // redirects to /login if the session expired
    setTimeout(connectWs, 2000);
  };
  ws.onmessage = (msg) => {
    const m = JSON.parse(msg.data);
    if (m.type === "tick") onTick(m);
    else if (m.type === "event") onEvent(m);
    else if (m.type === "packets") onPackets(m);
  };
}

function onTick(m) {
  $("round").textContent = m.round;
  const s = m.system;
  setNum("n-cpu", `${Math.round(s.cpu_percent)}%`); setNum("n-mem", `${Math.round(s.mem_percent)}%`);
  $("cpu-gauge").style.setProperty("--p", Math.round(s.cpu_percent));
  setNum("n-upbps", fmtBps(s.net_up_bps)); setNum("n-downbps", fmtBps(s.net_down_bps));
  for (const x of m.hosts) {
    const h = hosts.get(x.id);
    if (h) Object.assign(h, { status: x.status, last_latency_ms: x.latency_ms, last_error: x.error,
      loss_pct: x.loss_pct, jitter_ms: x.jitter_ms, timings: x.timings, cert_days: x.cert_days });
  }
  renderHosts();
  const up = m.hosts.filter((x) => x.status === "up").length;
  logLine("SYS", `Round ${m.round}: ${up}/${m.hosts.length} up`);
  if (selectedId && hosts.has(selectedId)) loadChart(selectedId);
  if (++ticks % 6 === 0) refreshHosts();   // refresh 24h uptime about once a minute
}

function onEvent(e, live = true) {
  logLine(e.host_id ?? e.kind.toUpperCase(), e.message, e.status === "down" ? "is-bad" : e.status === "up" ? "is-good" : "is-warn");
  if (live) toast(e.message, e.status === "up" ? "up" : e.status === "down" ? "down" : "warning");
  if (live && e.kind === "device" && loaded.has("lan")) loadDevices();
}

// ================= packets =================
const PROTOS = ["TCP", "TLS", "HTTP", "UDP", "DNS", "DHCP", "ARP", "ICMP", "OTHER"];
let pkRows = [];
let pkFilter = new Set(PROTOS);
let pkPaused = false;

function packetsInit() {
  $("pk-chips").innerHTML = PROTOS.map((p) => `<button class="packets-filter-chip active proto-${p}" data-p="${p}">${p}</button>`).join("");
  api("/api/packets/status").then(pkStatus);
  api("/api/packets/recent").then((rows) => { pkRows = rows.reverse(); renderPackets([]); });
}

function pkStatus(s) {
  if (s.error) $("pk-status").textContent = s.error;
  else $("pk-status").textContent = s.running
    ? `Capturing… ${Object.values(s.counts).reduce((a, b) => a + b, 0)} packets, ${fmtBytes(s.total_bytes)}`
    : "Stopped. Needs Administrator (Windows) or root / CAP_NET_RAW (Linux).";
  if (s.note && !s.error) $("pk-status").textContent += ` (${s.note})`;
  $("pk-status").className = `app-hint ${s.error ? "is-bad" : ""}`;
  const total = Object.values(s.counts).reduce((a, b) => a + b, 0) || 1;
  $("pk-bar").innerHTML = Object.entries(s.counts).sort((a, b) => b[1] - a[1])
    .map(([p, n]) => `<div class="proto-${PROTOS.includes(p) ? p : "OTHER"}" style="width:${(n / total) * 100}%;background:currentColor" title="${esc(p)} ${n}"></div>`).join("");
}

function pkMatch(r) {
  const proto = PROTOS.includes(r.proto) ? r.proto : "OTHER";
  if (!pkFilter.has(proto)) return false;
  const q = $("pk-search").value.trim().toLowerCase();
  return !q || `${r.src} ${r.dst} ${r.info} ${r.proto}`.toLowerCase().includes(q);
}

function pkRow(r, animate) {
  const proto = PROTOS.includes(r.proto) ? r.proto : "OTHER";
  const t = new Date(r.t * 1000);
  const ts = `${t.toLocaleTimeString([], { hour12: false })}.${String(t.getMilliseconds()).padStart(3, "0")}`;
  return `<tr class="${animate ? "anim-row-in" : ""}"><td>${ts}</td><td class="col-sm-hide">${esc(r.src)}</td>
    <td class="col-sm-hide">${esc(r.dst)}</td><td class="proto-${proto}">${esc(r.proto)}</td>
    <td class="col-md-hide">${r.len}</td><td>${esc(r.info)}</td></tr>`;
}

function renderPackets(fresh) {
  const shown = pkRows.filter(pkMatch).slice(0, 300);
  if (!shown.length) { $("pk-rows").innerHTML = `<tr><td colspan="6" class="app-table-empty">No packets match.</td></tr>`; return; }
  const freshSet = new Set(fresh.slice(0, 30));
  $("pk-rows").innerHTML = shown.map((r) => pkRow(r, freshSet.has(r))).join("");
}

function onPackets(m) {
  const fresh = m.rows.slice().reverse();         // newest first
  pkRows = fresh.concat(pkRows).slice(0, 1000);
  if (loaded.has("packets")) { pkStatus(m.status); if (!pkPaused) renderPackets(fresh); }
}

$("pk-start").addEventListener("click", (e) => busy(e.target, async () => {
  $("pk-status").textContent = "Starting capture…";
  pkStatus(await post("/api/packets/start"));
}));
$("pk-stop").addEventListener("click", async () => pkStatus(await post("/api/packets/stop")));
$("pk-pause").addEventListener("click", (e) => {
  pkPaused = !pkPaused;
  e.target.textContent = pkPaused ? "Resume view" : "Pause view";
  if (!pkPaused) renderPackets([]);
});
$("pk-search").addEventListener("input", () => renderPackets([]));
$("pk-chips").addEventListener("click", (e) => {
  const p = e.target.dataset.p;
  if (!p) return;
  pkFilter.has(p) ? pkFilter.delete(p) : pkFilter.add(p);
  e.target.classList.toggle("active");
  renderPackets([]);
});

// ================= LAN =================
let lastNew = new Set();
async function lanInit() {
  const nets = await api("/api/lan/networks");
  $("lan-net").innerHTML = nets.length
    ? nets.map((n) => `<option>${esc(n)}</option>`).join("")
    : `<option value="">No private network found</option>`;
  loadDevices();
}

async function loadDevices() {
  const devs = await api("/api/lan/devices");
  if (!devs.length) return;
  $("lan-rows").innerHTML = devs.map((d) => `<tr class="${lastNew.has(d.mac) ? "lan-new anim-row-in" : ""}">
    <td>${esc(d.ip)}</td><td>${esc(d.mac)}</td><td class="col-sm-hide">${esc(d.vendor || "-")}</td>
    <td class="col-md-hide">${new Date(d.first_seen).toLocaleString()}</td>
    <td class="col-md-hide">${new Date(d.last_seen).toLocaleString()}</td>
    <td><button class="app-mini" data-mac="${esc(d.mac)}">${d.known ? "trusted" : "UNKNOWN"}</button></td></tr>`).join("");
}

$("lan-scan").addEventListener("click", (e) => busy(e.target, async () => {
  const cidr = $("lan-cidr").value.trim() || $("lan-net").value;
  if (!cidr) return;
  $("lan-status").textContent = `Scanning ${cidr}… (about 10-30 s)`;
  try {
    const r = await post("/api/lan/discover", { cidr });
    lastNew = new Set(r.new);
    $("lan-status").textContent = `${r.devices.length} devices in ${r.seconds}s, ${r.new.length} new.` +
      (r.oui_loaded ? "" : " Add data/oui.txt for vendor names.");
    logLine("LAN", `Scan ${r.cidr}: ${r.devices.length} devices`);
    loadDevices();
  } catch (err) { $("lan-status").textContent = err.message; }
}));

$("lan-rows").addEventListener("click", async (e) => {
  const mac = e.target.dataset.mac;
  if (!mac) return;
  await api(`/api/lan/devices/${encodeURIComponent(mac)}/known`, { method: "PATCH" });
  loadDevices();
});

// ================= tools =================
const kv = (obj) => `<dl class="tools-kv">${Object.entries(obj).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>`;

$("trace-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const btn = e.target.querySelector("button");
  busy(btn, async () => {
    const host = new FormData(e.target).get("host");
    $("trace-status").textContent = `Tracing ${host}… (can take 30 s+)`;
    $("trace-out").innerHTML = "";
    try {
      const r = await post("/api/tools/traceroute", { host });
      const max = Math.max(1, ...r.hops.map((h) => h.avg || 0));
      $("trace-status").textContent = `${r.hops.length} hops to ${r.host}. Red = latency jump over 20 ms.`;
      $("trace-out").innerHTML = `<table class="app-table"><thead><tr><th>#</th><th>IP</th><th>Avg</th><th style="width:40%"></th></tr></thead><tbody>${
        r.hops.map((h, i) => `<tr class="anim-row-in" style="animation-delay:${i * 40}ms">
          <td>${h.hop}</td><td>${h.timeout ? '<span class="app-addr">* timed out</span>' : esc(h.ip || "?")}</td>
          <td>${fmtMs(h.avg)}${h.jump > 20 ? ` <span class="is-bad">▲${Math.round(h.jump)}</span>` : ""}</td>
          <td>${h.avg != null ? `<div class="tools-hop-bar ${h.jump > 20 ? "jump" : ""}" style="width:${(h.avg / max) * 100}%"></div>` : ""}</td></tr>`).join("")
      }</tbody></table>`;
    } catch (err) { $("trace-status").textContent = err.message; }
  });
});

$("subnet-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const r = await api(`/api/tools/subnet?cidr=${encodeURIComponent(new FormData(e.target).get("cidr"))}`);
    const out = { Network: r.cidr, Netmask: r.netmask, Wildcard: r.wildcard };
    if (r.version === 4) Object.assign(out, { Broadcast: r.broadcast, "First host": r.first_host,
      "Last host": r.last_host, "Usable hosts": r.usable_hosts.toLocaleString(), Class: r.ip_class });
    out["Total addresses"] = r.total_addresses.toLocaleString();
    out.Private = r.private ? "yes" : "no";
    $("subnet-out").innerHTML = kv(out);
  } catch (err) { $("subnet-out").innerHTML = `<p class="app-hint is-bad">${esc(err.message)}</p>`; }
});

$("mtu-form").addEventListener("submit", (e) => {
  e.preventDefault();
  busy(e.target.querySelector("button"), async () => {
    const host = new FormData(e.target).get("host");
    $("mtu-status").textContent = `Testing ${host}…`;
    $("mtu-out").innerHTML = "";
    try {
      const r = await post("/api/tools/mtu", { host });
      $("mtu-status").textContent = `Path MTU = largest payload + 28 (20 IP header + 8 ICMP header).`;
      $("mtu-out").innerHTML = `<div class="tools-big-number">${r.mtu} <small>bytes MTU</small></div>` +
        kv(Object.fromEntries(r.steps.map((s) => [`${s.size} B payload`, s.ok ? "fits" : "too big"])));
    } catch (err) { $("mtu-status").textContent = err.message; }
  });
});

$("speed-run").addEventListener("click", (e) => busy(e.target, async () => {
  $("speed-status").textContent = "Downloading…";
  $("speed-out").innerHTML = `.. <small>Mbps</small>`;
  try {
    const r = await post("/api/tools/speedtest", {});
    $("speed-out").innerHTML = `${r.mbps} <small>Mbps</small>`;
    $("speed-status").textContent = `${fmtBytes(r.bytes)} in ${r.seconds}s · first byte after ${fmtMs(r.ttfb_ms)}`;
    logLine("TOOL", `Speed test: ${r.mbps} Mbps`);
  } catch (err) { $("speed-status").textContent = err.message; $("speed-out").innerHTML = `-- <small>Mbps</small>`; }
}));

async function loadWifi() {
  const r = await api("/api/net/wifi");
  $("wifi-out").innerHTML = r.available ? kv(r.fields) : `<p class="app-hint">${esc(r.reason)}</p>`;
}
$("wifi-refresh").addEventListener("click", loadWifi);

// ================= system =================
async function loadInterfaces() {
  const rows = await api("/api/net/interfaces");
  $("iface-rows").innerHTML = rows.map((r) => `<tr>
    <td>${esc(r.name)}</td><td>${esc(r.ipv4 || "-")}</td><td class="col-sm-hide">${esc(r.cidr || "-")}</td>
    <td class="col-sm-hide">${esc(r.mac || "-")}</td><td class="col-md-hide">${r.mtu ?? "-"}</td>
    <td class="col-md-hide">${r.speed_mbps ? `${r.speed_mbps} Mbps` : "-"}</td>
    <td><span class="app-pill ${r.up ? "up" : "unknown"}">${r.up ? "up" : "down"}</span></td></tr>`).join("");
}

async function loadConnections() {
  const r = await api("/api/net/connections");
  $("conn-counts").innerHTML = r.error ? `<span class="is-bad">${esc(r.error)}</span>`
    : Object.entries(r.counts).map(([k, v]) => `<span class="app-pill info">${esc(k)} ${v}</span>`).join("") + ` <span class="app-addr">${r.total} total</span>`;
  $("conn-rows").innerHTML = r.rows.map((c) => `<tr><td>${c.proto}</td><td class="col-sm-hide">${esc(c.local)}</td>
    <td>${esc(c.remote || "-")}</td><td>${esc(c.status)}</td><td>${esc(c.process)}</td></tr>`).join("");
}
$("iface-refresh").addEventListener("click", loadInterfaces);
$("conn-refresh").addEventListener("click", loadConnections);

$("logout").addEventListener("click", async () => { await fetch("/logout", { method: "POST" }); location.href = "/login"; });

// ================= PWA =================
if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});
let installPrompt = null;
window.addEventListener("beforeinstallprompt", (e) => {   // Chrome/Edge/Android: offer our own button
  e.preventDefault();
  installPrompt = e;
  $("install-app").hidden = false;
});
$("install-app").addEventListener("click", async () => {
  if (!installPrompt) return;
  installPrompt.prompt();
  await installPrompt.userChoice;
  installPrompt = null;
  $("install-app").hidden = true;
});
window.addEventListener("appinstalled", () => { $("install-app").hidden = true; logLine("SYS", "Installed as an app"); });

// ================= start =================
setInterval(() => { $("clock").textContent = timeStr(Date.now()); }, 1000);
(async () => {
  await refreshHosts();
  const s = await api("/api/system");
  setNum("n-cpu", `${Math.round(s.cpu_percent)}%`); setNum("n-mem", `${Math.round(s.mem_percent)}%`);
  (await api("/api/events")).slice().reverse().forEach((e) => onEvent(e, false));
  connectWs();
  const v = (location.hash || "#monitor").slice(1);
  showView(["monitor", "packets", "lan", "tools", "system"].includes(v) ? v : "monitor");
})();
