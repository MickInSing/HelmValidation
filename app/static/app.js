"use strict";
(() => {
const R = "__rendered__";
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const TIER_COLOR = ["#b65cff", "#f5b03c", "#1e9bff", "#2fd3b5", "#ff6fa8", "#ff8a3d"];
const TIER_NAME = ["Identity & RBAC", "Config", "Workloads", "Network", "Edge", "External (not in chart)"];
const EXT_ICON = {
  values: "M4 6h10 M18 6h2 M4 12h4 M12 12h8 M4 18h12 M20 18h0 M16 4v4 M10 10v4 M18 16v4",
  cluster: "M7 18a4 4 0 0 1-.5-8 6 6 0 0 1 11.5 1.5A3.5 3.5 0 0 1 17.5 18z",
  operator: "M9 4h6v3a2 2 0 1 0 0 4v0h3v6h-3a2 2 0 1 0-4 0H6v-6h3a2 2 0 1 0 0-4z",
  argo: "M20 12a8 8 0 0 1-14 5.3 M4 12a8 8 0 0 1 14-5.3 M18 3v4h-4 M6 21v-4h4",
  existing: "M14 10a4 4 0 1 0-3.9 4H11v3h3v3h3v-3l-3-3.1A4 4 0 0 0 14 10z",
};
const ICON = {
  workload: "M12 3l8 4.5v9L12 21l-8-4.5v-9z M12 12l8-4.5 M12 12v9 M12 12L4 7.5",
  Service: "M4 8h15 M15 4.5 19 8l-4 3.5 M20 16H5 M9 12.5 5 16l4 3.5",
  Ingress: "M12 3v18 M3 12h18 M9 6l3-3 3 3 M9 18l3 3 3-3 M6 9l-3 3 3 3 M18 9l3 3-3 3",
  ConfigMap: "M7 3h7l4 4v14H7z M14 3v4h4 M9.5 12h6 M9.5 15.5h6",
  Secret: "M6 11h12v9H6z M8.5 11V8a3.5 3.5 0 0 1 7 0v3 M12 14.5v2",
  ServiceAccount: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M4.5 20a7.5 7.5 0 0 1 15 0",
  Role: "M12 3l7 3v5c0 5-3.5 8.5-7 10-3.5-1.5-7-5-7-10V6z M9 12l2 2 4-4",
  RoleBinding: "M10 14a4 4 0 0 0 5.66 0l3-3a4 4 0 0 0-5.66-5.66l-1 1 M14 10a4 4 0 0 0-5.66 0l-3 3a4 4 0 0 0 5.66 5.66l1-1",
  HorizontalPodAutoscaler: "M4 20h16 M7 16v-4 M12 16V8 M17 16V5 M15 7l2-2 2 2",
  NetworkPolicy: "M3 5h18v14H3z M3 9.7h18 M3 14.3h18 M9 5v4.7 M15 5v4.7 M12 9.7v4.6 M6 9.7v4.6 M18 9.7v4.6 M9 14.3V19 M15 14.3V19",
  PodDisruptionBudget: "M12 3l8 4.5v9L12 21l-8-4.5v-9z M8.5 12h7",
  PersistentVolumeClaim: "M5 6c0-1.7 3-3 7-3s7 1.3 7 3v12c0 1.7-3 3-7 3s-7-1.3-7-3z M5 6c0 1.7 3 3 7 3s7-1.3 7-3 M5 12c0 1.7 3 3 7 3s7-1.3 7-3",
  Namespace: "M3 7h18v12H3z M3 7l3-3h6l2 3",
  other: "M12 3l8 4.5v9L12 21l-8-4.5v-9z",
};
ICON.ClusterRole = ICON.Role; ICON.ClusterRoleBinding = ICON.RoleBinding;
const WORKLOADS = new Set(["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod", "ReplicaSet"]);
const SHORT = { HorizontalPodAutoscaler: "HPA", PodDisruptionBudget: "PDB", PersistentVolumeClaim: "PVC", ServiceAccount: "ServiceAcct", NetworkPolicy: "NetPolicy", ClusterRoleBinding: "CRBinding" };

let D = null, cur = 0, mode = "template", file = null, seen = new Set(), layout = null, fullOut = false;
let view = "chart", curBy = { chart: 0, helm: 0, infra: 0 }, seenBy = { chart: new Set(), helm: new Set(), infra: new Set() };
const S = () => (view === "helm" ? D.helm.steps : view === "infra" ? D.infra.steps : D.steps);

// ---------------------------------------------------------------- loading
const relIn = $("#rel"), nsIn = $("#ns");
const NOVALS = () => ({ text: "", files: [], answers: {}, bypass: false });
let src = null, vals = NOVALS();
function b64(str) { let bin = ""; new TextEncoder().encode(str).forEach((x) => (bin += String.fromCharCode(x))); return btoa(bin); }
function hdrs(extra = {}) {
  return Object.assign({ "X-Release": relIn.value.trim(), "X-Namespace": nsIn.value.trim(),
    "X-Values": b64(vals.text), "X-Value-Files": vals.files.join(","),
    "X-Set": b64(Object.entries(vals.answers).filter(([, v]) => v !== "").map(([k, v]) => `${k}=${v}`).join("\n")),
    "X-Bypass": vals.bypass ? "1" : "0" }, extra);
}
// Every way of loading a chart goes through run(), so "Re-render" can repeat it with new values.
function run(source, label, fresh = true) {
  if (fresh) vals = NOVALS();
  src = source;
  const req = () => source.kind === "blob"
    ? fetch("/api/analyze", { method: "POST", body: source.blob, headers: hdrs({ "X-Filename": source.name, "Content-Type": "application/octet-stream" }) })
    : source.kind === "local" ? fetch("/api/local/analyze?path=" + encodeURIComponent(source.path), { headers: hdrs() })
    : fetch("/api/sample", { headers: hdrs() });
  analyse(req, label);
}
async function analyse(makeRequest, label) {
  showErr(""); status(label || "Analysing…");
  $("#drop").style.opacity = .6;
  try {
    const res = await makeRequest();
    const txt = await res.text();
    let j; try { j = JSON.parse(txt); } catch { throw new Error(`Server returned ${res.status}: ${txt.slice(0, 200)}`); }
    if (!res.ok) throw new Error(j.error || res.statusText);
    status(""); load(j);
  } catch (e) {
    status("");
    if (D && !$("#work").classList.contains("hidden")) { openDrawer(); drawerErr(e.message || String(e)); }
    else showErr(e.message || String(e));
  }
  finally { $("#drop").style.opacity = 1; }
}
function uploadBlob(blob, name) {
  run({ kind: "blob", blob, name }, `Uploading ${name} (${Math.max(1, Math.round(blob.size / 1024))} KB)…`);
}
function showErr(m) { const e = $("#err"); e.textContent = m; e.classList.toggle("hidden", !m); }
function status(m) { const s = $("#status"); s.textContent = m; s.classList.toggle("hidden", !m); }
window.addEventListener("error", (e) => showErr("Browser error: " + e.message));
window.addEventListener("unhandledrejection", (e) => showErr("Browser error: " + (e.reason?.message || e.reason)));

// --- folder -> tar (ustar) in the browser, so an unpacked chart folder works too
const SKIP = /(^|\/)(\.git|\.idea|\.vscode|node_modules|\.DS_Store)(\/|$)/;
function tarHeader(path, size) {
  const h = new Uint8Array(512), enc = new TextEncoder();
  let name = path, prefix = "";
  if (enc.encode(name).length > 100) { const i = path.lastIndexOf("/", 154); prefix = path.slice(0, i); name = path.slice(i + 1); }
  const put = (s, off, len) => h.set(enc.encode(s).slice(0, len), off);
  const oct = (n, len) => n.toString(8).padStart(len - 1, "0") + "\0";
  put(name, 0, 100); put(oct(0o644, 8), 100, 8); put(oct(0, 8), 108, 8); put(oct(0, 8), 116, 8);
  put(oct(size, 12), 124, 12); put(oct(Math.floor(Date.now() / 1000), 12), 136, 12);
  put("        ", 148, 8); put("0", 156, 1); put("ustar\0", 257, 6); put("00", 263, 2); put(prefix, 345, 155);
  let sum = 0; for (const b of h) sum += b;
  put(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8);
  return h;
}
async function tarOf(entries) {  // entries: [{path, file}]
  const parts = [];
  for (const { path, file } of entries) {
    const buf = new Uint8Array(await file.arrayBuffer());
    parts.push(tarHeader(path, buf.length), buf, new Uint8Array((512 - (buf.length % 512)) % 512));
  }
  parts.push(new Uint8Array(1024));
  return new Blob(parts, { type: "application/x-tar" });
}
async function uploadFolder(entries) {
  entries = entries.filter((e) => !SKIP.test(e.path));
  if (!entries.length) return showErr("That folder is empty.");
  if (!entries.some((e) => /(^|\/)Chart\.yaml$/.test(e.path))) return showErr("No Chart.yaml found in that folder. Pick the chart's root folder (the one containing Chart.yaml).");
  status(`Packing ${entries.length} files…`);
  const root = entries[0].path.split("/")[0] || "chart";
  uploadBlob(await tarOf(entries), root + ".tar");
}
// read a dropped directory recursively (Chrome/Safari/Firefox all support webkitGetAsEntry)
function walk(entry, prefix = "") {
  return new Promise((resolve) => {
    if (entry.isFile) return entry.file((f) => resolve([{ path: prefix + entry.name, file: f }]), () => resolve([]));
    const reader = entry.createReader(), all = [];
    const next = () => reader.readEntries(async (batch) => {
      if (!batch.length) { const nested = await Promise.all(all.map((e) => walk(e, prefix + entry.name + "/"))); return resolve(nested.flat()); }
      all.push(...batch); next();
    }, () => resolve([]));
    next();
  });
}
async function handleDrop(dt) {
  const item = [...(dt.items || [])].find((i) => i.kind === "file");
  const entry = item && item.webkitGetAsEntry && item.webkitGetAsEntry();
  if (entry && entry.isDirectory) return uploadFolder(await walk(entry));
  const f = dt.files && dt.files[0];
  if (!f) return showErr("Nothing to upload. Try the Choose buttons instead.");
  uploadBlob(f, f.name);
}

$("#btn-pick").onclick = (e) => { e.stopPropagation(); $("#file").click(); };
$("#btn-folder").onclick = (e) => { e.stopPropagation(); $("#folder").click(); };
$("#file").onchange = (e) => { const f = e.target.files[0]; if (f) uploadBlob(f, f.name); e.target.value = ""; };
$("#folder").onchange = (e) => {
  const entries = [...e.target.files].map((f) => ({ path: f.webkitRelativePath || f.name, file: f }));
  e.target.value = ""; uploadFolder(entries);
};
$("#btn-sample").onclick = (e) => { e.stopPropagation(); run({ kind: "sample" }, "Loading sample chart…"); };
$("#btn-new").onclick = () => { closeDrawer(); $("#btn-values").classList.add("hidden"); $("#work").classList.add("hidden"); $("#landing").classList.remove("hidden"); $("#btn-new").classList.add("hidden"); showErr(""); };
// --- charts from the folder mounted into the container (works even when the browser blocks uploads)
async function refreshLocal() {
  const sel = $("#localsel"), hint = $("#localhint");
  try {
    const j = await (await fetch("/api/local")).json();
    $("#ver").textContent = `script loaded · server v${j.version}`;
    if (!j.mounted) { sel.innerHTML = `<option value="">No folder mounted</option>`; hint.textContent = "Mount a folder at /charts (see docker-compose.yml) to open charts without uploading."; hint.classList.remove("hidden"); return; }
    if (!j.charts.length) { sel.innerHTML = `<option value="">No charts found</option>`; hint.textContent = "Put chart folders (with Chart.yaml) or .tgz/.zip files in your mounted charts folder, then press ↻."; hint.classList.remove("hidden"); return; }
    hint.classList.add("hidden");
    sel.innerHTML = j.charts.map((c) => `<option value="${esc(c.path)}">${c.type === "folder" ? "📁 " : "📦 "}${esc(c.path)}</option>`).join("");
  } catch (e) { sel.innerHTML = `<option value="">Unavailable</option>`; }
}
$("#btn-local").onclick = (e) => {
  e.stopPropagation(); const p = $("#localsel").value; if (!p) return;
  run({ kind: "local", path: p }, `Analysing ${p}…`);
};
$("#btn-refresh").onclick = (e) => { e.stopPropagation(); refreshLocal(); };
$(".local").addEventListener("click", (e) => e.stopPropagation());
refreshLocal();

const drop = $("#drop");
drop.addEventListener("click", (e) => { if (e.target === drop || e.target.closest("h2,p,svg")) $("#file").click(); });
drop.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target === drop) $("#file").click(); });
// Stop the browser opening a dropped file anywhere on the page (that replaces the app)
let depth = 0;
window.addEventListener("dragenter", (e) => { e.preventDefault(); depth++; drop.classList.add("over"); });
window.addEventListener("dragleave", (e) => { e.preventDefault(); if (--depth <= 0) { depth = 0; drop.classList.remove("over"); } });
window.addEventListener("dragover", (e) => { e.preventDefault(); if (e.dataTransfer) e.dataTransfer.dropEffect = "copy"; });
window.addEventListener("drop", (e) => {
  e.preventDefault(); depth = 0; drop.classList.remove("over");
  if (!$("#landing").classList.contains("hidden") || confirm("Load this chart instead of the current one?")) handleDrop(e.dataTransfer);
});

function load(data) {
  D = data; cur = 0; file = null;
  D.helm = D.helm || { steps: [], pipeline: { nodes: [], edges: [] } };
  D.infra = D.infra || { steps: [], diagram: { nodes: [], edges: [], lanes: [], side: [] } };
  curBy = { chart: 0, helm: 0, infra: 0 }; seenBy = { chart: new Set(), helm: new Set(), infra: new Set() };
  seen = seenBy[view];
  $("#views").classList.remove("hidden");
  D.byId = Object.fromEntries(D.resources.map((r) => [r.id, r]));
  D.findById = Object.fromEntries(D.findings.map((f) => [f.id, f]));
  D.externals = D.externals || [];
  D.nodes = D.resources.concat(D.externals.map((x) => ({
    id: x.id, kind: "External", name: x.label, tier: 5, ext: true, category: x.category, detail: x.detail,
    links: x.consumers.map((c) => ({ to: c, label: "needed by" })), findings: [], source: "outside the chart",
  })));
  D.byId = Object.fromEntries(D.nodes.map((r) => [r.id, r]));
  $("#landing").classList.add("hidden"); $("#work").classList.remove("hidden"); $("#btn-new").classList.remove("hidden");
  const c = D.chart;
  $("#crumb").innerHTML = `${esc(c.name)} <span>/</span> v${esc(c.version)} <span>/</span> release <b>${esc(D.release)}</b> in <b>${esc(D.namespace)}</b>`;
  renderSide(); renderScore(); buildGraph(); go(curBy[view]);
  renderDrawer();
  if (D.renderError) openDrawer(); else closeDrawer();
}

// ---------------------------------------------------------------- values drawer
function openDrawer() { $("#drawer").classList.remove("hidden"); }
function closeDrawer() { $("#drawer").classList.add("hidden"); }
function drawerErr(msg, intro) {
  const e = $("#dr-err");
  e.innerHTML = msg ? `${intro || "<b>Render failed.</b>"}<pre>${esc(msg)}</pre>` : "";
  e.classList.toggle("hidden", !msg);
}
function renderDrawer() {
  $("#btn-values").classList.remove("hidden");
  const badge = $("#vals-badge");
  badge.classList.toggle("hidden", !D.renderError && !vals.text && !vals.files.length);
  badge.classList.toggle("ok", !D.renderError);
  const failed = /\bfail|required\b|must be set|nil pointer/i.test(D.renderError || "");
  drawerErr(D.renderError, failed
    ? "<b>The chart stopped itself rendering.</b> It uses <code>fail</code>/<code>required</code> to insist on values that ArgoCD normally supplies (Application <code>spec.source.helm.parameters</code>, <code>values</code> or <code>valueFiles</code>). Provide them below and re-render."
    : "<b>helm template failed.</b>");
  const req = $("#dr-req");
  if (D.required && D.required.length) {
    const msg = D.required.find((r) => r.message)?.message;
    req.innerHTML = `<h3>Values the chart needs from outside</h3>
      ${msg ? `<p class="muted">The chart says: “${esc(msg)}”</p>` : ""}
      <p class="muted">Enter real values if you know them. For a visual you can use placeholders; they show up as <span class="ph">setme-…</span> in the render.</p>` +
      D.required.map((r, k) => `<label class="reqf"><span><code>${esc(r.path)}</code>
        ${r.file ? `<button type="button" data-k="${k}" class="lnk">${esc(r.file.split("/").pop())}:${r.line} ↗</button>` : ""}</span>
        <input data-path="${esc(r.path)}" value="${esc(vals.answers[r.path] ?? "")}" placeholder="${esc(r.placeholder)}" spellcheck="false"></label>`).join("") +
      `<div class="row left"><button type="button" id="dr-ph" class="ghost">Fill empty with placeholders</button></div>`;
    req.querySelectorAll("button.lnk").forEach((b) => (b.onclick = () => { const r = D.required[+b.dataset.k]; closeDrawer(); jump(r.file, r.line); }));
    $("#dr-ph").onclick = () => req.querySelectorAll("input[data-path]").forEach((i) => { if (!i.value) i.value = i.placeholder; });
    req.classList.remove("hidden");
  } else req.classList.add("hidden");
  $("#dr-bypass").checked = !!vals.bypass;
  $("#dr-preview").classList.toggle("hidden", !D.renderError);
  const vf = $("#dr-vf");
  if (D.valueFiles && D.valueFiles.length) {
    vf.innerHTML = `<h3>Values files in this chart</h3><p class="muted">Tick the ones your Argo Application lists in <code>valueFiles</code>. They're applied in this order, before your overrides.</p>` +
      D.valueFiles.map((f) => `<label class="vf"><input type="checkbox" value="${esc(f)}" ${D.usedValueFiles.includes(f) ? "checked" : ""}> ${esc(f)}</label>`).join("");
    vf.classList.remove("hidden");
  } else vf.classList.add("hidden");
  $("#dr-text").value = vals.text;
  $("#dr-fill").classList.toggle("hidden", !D.suggested);
}
$("#btn-values").onclick = () => ($("#drawer").classList.contains("hidden") ? openDrawer() : closeDrawer());
$("#dr-close").onclick = closeDrawer;
function collectVals() {
  const answers = {};
  document.querySelectorAll("#dr-req input[data-path]").forEach((i) => (answers[i.dataset.path] = i.value.trim()));
  vals = { text: $("#dr-text").value, files: [...document.querySelectorAll("#dr-vf input:checked")].map((i) => i.value),
    answers, bypass: $("#dr-bypass").checked };
}
// One click: placeholders for every required value, plus bypass so any other checks can't block the diagram
$("#dr-preview").onclick = () => {
  document.querySelectorAll("#dr-req input[data-path]").forEach((i) => { if (!i.value) i.value = i.placeholder; });
  $("#dr-bypass").checked = true;
  collectVals(); drawerErr("");
  if (src) run(src, "Rendering preview…", false);
};
$("#dr-clear").onclick = () => { $("#dr-text").value = ""; };
$("#dr-fill").onclick = () => {
  const t = $("#dr-text"); t.value = (t.value.trim() ? t.value.trim() + "\n" : "") + D.suggested; t.focus();
};
$("#dr-run").onclick = () => {
  collectVals();
  drawerErr("");
  if (src) run(src, "Re-rendering…", false);
};

// ---------------------------------------------------------------- sidebar
function renderSide() {
  let html = "", g = null;
  S().forEach((s, i) => {
    if (s.group !== g) { g = s.group; html += `<div class="grp">${esc(g)}</div>`; }
    const bad = (s.id === "s-summary" ? [] : s.findings).filter((f) => f.sev === "critical" || f.sev === "high").length;
    const badge = s.badge ? `<span class="c ${esc(s.badge.cls)}">${esc(s.badge.text)}</span>` : bad ? `<span class="b">${bad}</span>` : "";
    html += `<button class="step ${s.dim ? "dim" : ""}" data-i="${i}"><span class="n">${String(i + 1).padStart(2, "0")}</span><span class="t">${esc(s.title)}</span>${badge}<span class="r"></span></button>`;
  });
  $("#steps").innerHTML = html;
  $("#steps").querySelectorAll(".step").forEach((b) => (b.onclick = () => go(+b.dataset.i)));
}
function renderScore() {
  if (D.renderError && !D.resources.length) {
    $("#scorebox").innerHTML = `<div><div class="lbl">Hardening score</div><div class="val">Not rendered yet</div><div class="lbl">Supply values to check the chart</div></div>`;
    $("#scorebox").classList.remove("hidden"); return;
  }
  const s = D.score, col = s >= 80 ? "var(--green)" : s >= 55 ? "var(--med)" : "var(--high)";
  const counts = {}; D.findings.forEach((f) => (counts[f.sev] = (counts[f.sev] || 0) + 1));
  const C = 2 * Math.PI * 22;
  $("#scorebox").innerHTML = `<svg class="ring" viewBox="0 0 56 56"><circle cx="28" cy="28" r="22" fill="none" stroke="#2c323d" stroke-width="6"/>
    <circle cx="28" cy="28" r="22" fill="none" stroke="${col}" stroke-width="6" stroke-linecap="round" stroke-dasharray="${(C * s) / 100} ${C}" transform="rotate(-90 28 28)"/>
    <text x="28" y="33" text-anchor="middle" fill="#fff" font-size="15" font-weight="700">${s}</text></svg>
    <div><div class="lbl">Hardening score</div><div class="val">${D.findings.length} findings</div>
    <div class="sevrow">${Object.keys(SEV_ORDER).filter((k) => counts[k]).map((k) => `<span class="pill ${k}">${counts[k]} ${k}</span>`).join("")}</div></div>`;
  $("#scorebox").classList.remove("hidden");
}

// ---------------------------------------------------------------- graph
function buildGraph() {
  if (view === "helm") return buildPipeline();
  if (view === "infra") return buildInfra();
  const svg = $("#graph"), W = svg.clientWidth || 900, H = svg.clientHeight || 360;
  const tiers = [...new Set(D.nodes.map((r) => r.tier))].sort((a, b) => (a === 5 ? -1 : b === 5 ? 1 : a - b));
  const cols = {}; D.nodes.forEach((r) => (cols[r.tier] ||= []).push(r));
  const x0 = 80, x1 = W - 80, top = 112, bot = H - 64;
  const pos = {};
  const size = 50, rowH = size + 44;                       // node + two label lines
  const cap = Math.max(1, Math.floor((bot - top) / rowH) + 1);
  const columns = [];                                     // a tier wraps into extra columns when it is too tall
  tiers.forEach((t) => { for (let i = 0; i < cols[t].length; i += cap) columns.push(cols[t].slice(i, i + cap)); });
  columns.forEach((list, ci) => {
    const x = columns.length === 1 ? W / 2 : x0 + ((x1 - x0) * ci) / (columns.length - 1);
    const n = list.length;
    const gap = n === 1 ? 0 : Math.min(110, (bot - top) / (n - 1));
    const start = (top + bot) / 2 - (gap * (n - 1)) / 2;
    list.forEach((r, i) => (pos[r.id] = { x, y: start + gap * i }));
  });
  layout = { pos, size };
  $("#legend").innerHTML = tiers.map((t) => `<span><i style="background:${TIER_COLOR[t]}"></i>${TIER_NAME[t]}</span>`).join("");

  let edges = "", nodes = "";
  D.nodes.forEach((r) => r.links.forEach((l) => {
    const a = pos[r.id], b = pos[l.to]; if (!a || !b) return;
    edges += `<path class="edge${r.ext ? " ext" : ""}" data-a="${r.id}" data-b="${l.to}" d="${route(a, b)}"/>`;
  }));
  D.nodes.forEach((r) => {
    const p = pos[r.id], h = size / 2, col = TIER_COLOR[r.tier] || "#888";
    const icon = r.ext ? EXT_ICON[r.category] || ICON.other : ICON[r.kind] || (WORKLOADS.has(r.kind) ? ICON.workload : ICON.other);
    const bad = r.findings.map((id) => D.findById[id]).filter((f) => f.sev === "critical" || f.sev === "high").length;
    const nm = r.name.length > 18 ? r.name.slice(0, 17) + "…" : r.name;
    nodes += `<g class="node${r.ext ? " ext" : ""}" data-id="${r.id}" transform="translate(${p.x},${p.y})">
      <rect class="box" x="${-h}" y="${-h}" width="${size}" height="${size}" rx="${size * 0.22}" style="--c:${col}"/>
      <g transform="translate(-12,-12) scale(1)"><path class="ico" d="${icon}"/></g>
      ${bad ? `<circle cx="${h - 2}" cy="${-h + 2}" r="8" fill="var(--crit)"/><text class="badge" x="${h - 2}" y="${-h + 5.5}">${bad}</text>` : ""}
      <text y="${h + 15}">${r.ext ? "External" : esc(SHORT[r.kind] || r.kind)}${r.hook ? " · hook" : ""}</text>
      <text class="nm" y="${h + 29}">${esc(nm)}</text></g>`;
  });
  svg.innerHTML = `<defs>
      <linearGradient id="flow" x1="0" x2="1"><stop offset="0" stop-color="#b65cff"/><stop offset="1" stop-color="#1e9bff"/></linearGradient>
      <radialGradient id="halo"><stop offset="0" stop-color="var(--hc)" stop-opacity=".22"/><stop offset=".7" stop-color="var(--hc)" stop-opacity=".07"/><stop offset="1" stop-color="var(--hc)" stop-opacity="0"/></radialGradient>
      <filter id="glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="6"/></filter>
    </defs>
    <g id="halo-g" class="halo" opacity="0"><circle r="115" fill="url(#halo)"/><circle r="115" fill="none" stroke="var(--hc)" stroke-width="2" stroke-dasharray="3 5" opacity=".8"/></g>
    <g>${edges}</g><g>${nodes}</g><g id="tag" class="tag" opacity="0"><rect rx="16" height="32"/><text y="21"></text></g>`;
  svg.querySelectorAll(".node").forEach((g) => {
    g.onclick = () => {
      const i = D.steps.findIndex((s) => s.node === g.dataset.id || (s.externals || []).includes(g.dataset.id));
      if (i >= 0) go(i);
    };
    g.onmousemove = (e) => tip(e, g.dataset.id); g.onmouseleave = () => $("#tip").classList.add("hidden");
  });
  if (D.resources.length === 0) svg.insertAdjacentHTML("beforeend", `<text x="${D.externals.length ? W / 2 + 70 : W / 2}" y="${H / 2}" fill="#8a93a3" text-anchor="${D.externals.length ? "start" : "middle"}" font-size="14">No resources rendered${D.renderError ? ": the chart needs values from outside (see Values)" : ""}</text>`);
  paintGraph();
}
function route(a, b) {
  if (Math.abs(a.x - b.x) < 30) { const off = 60, sx = a.x + off; return `M${a.x} ${a.y} C${sx} ${a.y} ${sx} ${b.y} ${b.x} ${b.y}`; }
  if (Math.abs(a.y - b.y) < 4) return `M${a.x} ${a.y} H${b.x}`;
  const mx = (a.x + b.x) / 2, r = Math.min(16, Math.abs(b.y - a.y) / 2, Math.abs(b.x - a.x) / 2);
  const sx = Math.sign(b.x - a.x), sy = Math.sign(b.y - a.y);
  return `M${a.x} ${a.y} H${mx - r * sx} Q${mx} ${a.y} ${mx} ${a.y + r * sy} V${b.y - r * sy} Q${mx} ${b.y} ${mx + r * sx} ${b.y} H${b.x}`;
}
function paintGraph() {
  if (!layout) return;
  const step = S()[cur], svg = $("#graph");
  const multi = new Set(step.externals || []);
  const id = step.node || null, focus = !!id || multi.size > 0;
  const near = new Set(id ? [id] : [...multi]);
  D.nodes.forEach((r) => r.links.forEach((l) => {
    if (r.id === id || multi.has(r.id)) near.add(l.to);
    if (l.to === id) near.add(r.id);
  }));
  svg.querySelectorAll(".node").forEach((g) => {
    const on = g.dataset.id === id || multi.has(g.dataset.id), r = D.byId[g.dataset.id], col = TIER_COLOR[r.tier];
    g.classList.toggle("on", on); g.classList.toggle("dim", focus && !near.has(g.dataset.id));
    const box = g.querySelector("rect.box");
    box.style.fill = on ? col : ""; box.style.stroke = on ? col : near.has(g.dataset.id) && id ? col : "";
    box.style.filter = on ? `drop-shadow(0 0 14px ${col})` : "";
  });
  svg.querySelectorAll(".edge").forEach((p) => {
    const on = (!!id && (p.dataset.a === id || p.dataset.b === id)) || multi.has(p.dataset.a);
    p.classList.toggle("on", on); p.classList.toggle("dim", focus && !on);
  });
  const halo = svg.querySelector("#halo-g"), tag = svg.querySelector("#tag");
  if (id && layout.pos[id]) {
    const p = layout.pos[id], r = D.byId[id];
    halo.setAttribute("transform", `translate(${p.x},${p.y})`); halo.style.setProperty("--hc", TIER_COLOR[r.tier]); halo.setAttribute("opacity", 1);
    const label = r.kind, w = label.length * 8 + 34, W = svg.clientWidth;
    let tx = p.x - layout.size / 2 - w - 14; if (tx < 10) tx = p.x + layout.size / 2 + 14; if (tx + w > W - 10) tx = W - w - 10;
    tag.setAttribute("transform", `translate(${tx},${p.y - 16})`);
    tag.querySelector("rect").setAttribute("width", w); const t = tag.querySelector("text"); t.setAttribute("x", w / 2); t.textContent = label;
    tag.setAttribute("opacity", 1);
  } else { halo.setAttribute("opacity", 0); tag.setAttribute("opacity", 0); }
}
function tip(e, id) {
  const r = D.byId[id], t = $("#tip");
  t.innerHTML = r.ext ? `<b>${esc(r.name)}</b><br><span class="muted">${md(r.detail, true)}</span>`
    : `<b>${esc(r.kind)}</b> ${esc(r.name)}<br><span class="muted">${esc(r.source)} · ${r.findings.length} findings</span>`;
  t.style.left = e.clientX + 14 + "px"; t.style.top = e.clientY + 14 + "px"; t.classList.remove("hidden");
}
let rz; window.addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(() => D && buildGraph(), 120); });

// ---------------------------------------------------------------- views (Chart / Helm concepts / Infrastructure)
const VICON = {
  file: "M7 3h7l4 4v14H7z M14 3v4h4", sliders: "M4 6h10 M18 6h2 M4 12h4 M12 12h8 M4 18h12 M16 4v4 M10 10v4",
  cube: ICON.workload, gear: "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z M12 2v3 M12 19v3 M2 12h3 M19 12h3 M5 5l2 2 M17 17l2 2 M5 19l2-2 M17 7l2-2",
  puzzle: "M9 4h6v3a2 2 0 1 0 0 4h3v6h-3a2 2 0 1 0-4 0H6v-6h3a2 2 0 1 0 0-4z", brackets: "M8 5 4 12l4 7 M16 5l4 7-4 7",
  doc: "M6 3h12v18H6z M9 8h6 M9 12h6 M9 16h4", k8s: "M12 3l7.5 4v10L12 21l-7.5-4V7z M12 8v8 M8.5 10l7 4 M15.5 10l-7 4",
  globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M3 12h18 M12 3c3 3 3 15 0 18 M12 3c-3 3-3 15 0 18",
  arrows: ICON.Ingress, swap: ICON.Service, wall: ICON.NetworkPolicy, user: ICON.ServiceAccount, shield: ICON.Role, link: ICON.RoleBinding,
  lock: ICON.Secret, chart: ICON.HorizontalPodAutoscaler, disk: "M4 7h16v10H4z M8 12h.01 M12 12h5",
  db: ICON.PersistentVolumeClaim, queue: "M4 6h16 M4 12h16 M4 18h10 M18 16l2 2-2 2", bucket: "M5 7h14l-1.5 13h-11z M5 7c0-2 3-3 7-3s7 1 7 3",
  cloud: "M7 18a4 4 0 0 1-.5-8 6 6 0 0 1 11.5 1.5A3.5 3.5 0 0 1 17.5 18z", log: "M5 4h14v16H5z M8 8h8 M8 12h8 M8 16h5",
};
let vlayout = null;
function setView(v) {
  if (!D || v === view) return;
  view = v; document.body.dataset.view = v; seen = seenBy[v];
  document.querySelectorAll("#views button").forEach((b) => b.classList.toggle("on", b.dataset.v === v));
  $("#crumb").innerHTML = $("#crumb").innerHTML.replace(/ <span>\/<\/span> <b class="vname">.*?<\/b>$/, "") +
    (v === "chart" ? "" : ` <span>/</span> <b class="vname">${v === "helm" ? "Helm concepts" : "Infrastructure"}</b>`);
  document.querySelector(".seg").style.visibility = "visible";
  renderSide(); buildGraph(); go(curBy[v]);
}
document.querySelectorAll("#views button").forEach((b) => (b.onclick = () => setView(b.dataset.v)));

function renderExtra(s) {
  const el = $("#ex-extra");
  let h = "";
  if (view === "helm") {
    if (s.items && s.items.length) {
      h += `<div class="xh">In this chart</div><div class="chips">` + s.items.map((it, k) =>
        it.file ? `<button class="chip" data-k="${k}">${esc(it.label)}${it.hint ? ` <i>${esc(it.hint)}</i>` : ""}</button>`
                : `<span class="chip">${esc(it.label)}${it.hint ? ` <i>${esc(it.hint)}</i>` : ""}</span>`).join("") + `</div>`;
    }
    h += `<div class="xh">Learn more</div><a class="doclink" href="${esc(s.doc)}" target="_blank" rel="noopener noreferrer">helm.sh: ${esc(s.title)} ↗</a>`;
  } else if (view === "infra") {
    h += `<table class="tbl">` + s.rows.map((r, k) => `<tr class="${r.ptr ? "go" : ""}" data-k="${k}"><td>${esc(r.k)}${r.inferred ? `<span class="inf">inferred</span>` : ""}</td>
      <td>${md(r.v, true)}</td><td><span class="st ${r.st}">${{ ok: "ok", warn: "check", bad: "issue", ext: "external", none: "n/a" }[r.st]}</span></td></tr>`).join("") + `</table>`;
  }
  el.innerHTML = h;
  el.querySelectorAll("button.chip").forEach((b) => (b.onclick = () => { const it = s.items[+b.dataset.k]; jump(it.file, it.line); }));
  el.querySelectorAll("tr.go").forEach((tr) => (tr.onclick = () => { const p = s.rows[+tr.dataset.k].ptr; jump(p.file, p.line); }));
}

function vnode(n, x, y, size, extraCls = "", maxChars = 24) {
  const h = size / 2, icon = VICON[n.ic] || ICON.other;
  const cut = (t) => (t.length > maxChars ? t.slice(0, Math.max(4, maxChars - 1)) + "…" : t);
  // chart resources: kind on line 1, name on line 2
  let l1 = n.l, l2 = n.s;
  if (n.res && !n.s && n.l.includes(" ")) { l1 = n.l.split(" ")[0]; l2 = n.l.slice(l1.length + 1); }
  const lbl = cut(l1); n = Object.assign({}, n, { s: l2 ? cut(l2) : "" });
  return `<g class="node ${n.ext ? "ext" : ""} ${extraCls}" data-id="${esc(n.id)}" transform="translate(${x},${y})">
    <rect class="box" x="${-h}" y="${-h}" width="${size}" height="${size}" rx="${size * 0.22}"/>
    <g transform="translate(-12,-12)"><path class="ico" d="${icon}"/></g>
    ${n.inferred ? `<circle cx="${h - 2}" cy="${-h + 2}" r="7" fill="#ffb27a"/><text class="q" x="${h - 2}" y="${-h + 5.5}" text-anchor="middle">?</text>` : ""}
    <text class="nm" y="${h + 14}">${esc(lbl)}</text>${n.s ? `<text y="${h + 27}">${esc(n.s)}</text>` : ""}</g>`;
}
function vedges(edges, pos, extIds) {
  return edges.map(([a, b]) => {
    const p = pos[a], q = pos[b]; if (!p || !q) return "";
    return `<path class="edge ${extIds.has(a) || extIds.has(b) ? "ext" : ""}" data-a="${esc(a)}" data-b="${esc(b)}" d="${route(p, q)}"/>`;
  }).join("");
}
function buildPipeline() {
  const svg = $("#graph"), W = svg.clientWidth || 900, H = svg.clientHeight || 360, G = D.helm.pipeline;
  const top = 70, h = H - top - 40, X = (x) => 50 + x * (W - 100), Y = (y) => top + y * h;
  const pos = Object.fromEntries(G.nodes.map((n) => [n.id, { x: X(n.x), y: Y(n.y) }]));
  const ext = new Set(G.nodes.filter((n) => n.ext).map((n) => n.id));
  vlayout = { pos, edges: G.edges };
  $("#legend").innerHTML = `<span><i style="background:var(--purple)"></i>Render pipeline</span><span><i style="background:#ff8a3d"></i>Outside the chart</span>`;
  svg.innerHTML = `<g>${vedges(G.edges, pos, ext)}</g><g>${G.nodes.map((n) => vnode(n, pos[n.id].x, pos[n.id].y, 48, n.on ? "" : "off")).join("")}</g>`;
  svg.querySelectorAll(".node").forEach((g) => (g.onclick = () => {
    const i = D.helm.steps.findIndex((s) => (s.nodes || []).includes(g.dataset.id) && !s.dim);
    go(i >= 0 ? i : D.helm.steps.findIndex((s) => (s.nodes || []).includes(g.dataset.id)));
  }));
  paintView(S()[cur] || {});
}
function buildInfra() {
  const svg = $("#graph"), W = svg.clientWidth || 900, H = svg.clientHeight || 360, G = D.infra.diagram;
  const top = 66, bottom = H - 12, sideW = Math.max(120, W * 0.14), x0 = sideW + 20, x1 = W - sideW - 20;
  const lanes = G.lanes.filter((l) => G.nodes.some((n) => n.lane === l.id));
  const lh = (bottom - top) / Math.max(1, lanes.length), pos = {};
  const size = Math.max(36, Math.min(46, lh - 46));
  let out = "";
  lanes.forEach((l, i) => {
    const y0 = top + i * lh, ns = G.nodes.filter((n) => n.lane === l.id);
    out += `<g class="lane" data-lane="${l.id}"><rect x="${x0 - 10}" y="${y0 + 2}" width="${x1 - x0 + 20}" height="${lh - 6}" rx="12"/><text x="${x0}" y="${y0 + 16}">${esc(l.l)}</text></g>`;
    ns.forEach((n, k) => (pos[n.id] = { x: x0 + ((k + 1) * (x1 - x0)) / (ns.length + 1), y: y0 + lh / 2 + 2, room: (x1 - x0) / (ns.length + 1) }));
  });
  const sideTop = lanes.length > 1 ? top + lh : top;
  G.side.forEach((sd, si) => {
    const ns = G.nodes.filter((n) => n.lane === sd.id); if (!ns.length) return;
    const sx = si === 0 ? 10 : W - sideW - 10, gap = (bottom - sideTop - 20) / (ns.length + 1);
    out += `<g class="lane" data-lane="${sd.id}"><rect x="${sx}" y="${sideTop + 2}" width="${sideW}" height="${bottom - sideTop - 6}" rx="12"/><text x="${sx + 10}" y="${sideTop + 16}">${esc(sd.l)}</text></g>`;
    ns.forEach((n, k) => (pos[n.id] = { x: sx + sideW / 2, y: sideTop + 10 + gap * (k + 1), room: sideW }));
  });
  const ext = new Set(G.nodes.filter((n) => n.ext).map((n) => n.id));
  vlayout = { pos, edges: G.edges };
  $("#legend").innerHTML = `<span><i style="background:var(--teal)"></i>In the chart</span><span><i style="background:#ff8a3d"></i>Outside / inferred (?)</span>`;
  out += `<g>${vedges(G.edges, pos, ext)}</g><g>${G.nodes.filter((n) => pos[n.id]).map((n) => vnode(n, pos[n.id].x, pos[n.id].y, size, "", Math.max(8, Math.floor(pos[n.id].room / 6.6)))).join("")}</g>`;
  if (!G.nodes.length) out += `<text x="${W / 2}" y="${H / 2}" fill="#8a93a3" text-anchor="middle" font-size="14">Nothing rendered yet. Supply values to see the infrastructure</text>`;
  svg.innerHTML = out;
  svg.querySelectorAll(".node").forEach((g) => {
    const n = G.nodes.find((x) => x.id === g.dataset.id);
    g.onclick = () => {
      if (n.res) { setView("chart"); go(D.steps.findIndex((s) => s.node === n.res)); return; }
      const i = D.infra.steps.findIndex((s) => s.nodes.includes(n.id)); if (i >= 0) go(i);
    };
    g.onmousemove = (e) => { const t = $("#tip"); t.innerHTML = `<b>${esc(n.l)}</b><br><span class="muted">${n.res ? "click: open in Chart view" : n.inferred ? "inferred, not declared in the chart" : n.ext ? "provided outside the chart" : ""}</span>`; t.style.left = e.clientX + 14 + "px"; t.style.top = e.clientY + 14 + "px"; t.classList.remove("hidden"); };
    g.onmouseleave = () => $("#tip").classList.add("hidden");
  });
  paintView(S()[cur] || {});
}
function paintView(s) {
  if (!vlayout) return;
  const on = new Set(s.nodes || []), focus = on.size > 0, near = new Set(on), svg = $("#graph");
  vlayout.edges.forEach(([a, b]) => { if (on.has(a)) near.add(b); if (on.has(b)) near.add(a); });
  svg.querySelectorAll(".node").forEach((g) => {
    g.classList.toggle("von", on.has(g.dataset.id));
    g.classList.toggle("dim", focus && !near.has(g.dataset.id));
  });
  svg.querySelectorAll(".edge").forEach((p) => {
    const hit = on.has(p.dataset.a) || on.has(p.dataset.b);
    p.classList.toggle("von", focus && hit); p.classList.toggle("dim", focus && !hit);
  });
  svg.querySelectorAll(".lane").forEach((l) => l.classList.toggle("on", l.dataset.lane === s.lane));
}

// ---------------------------------------------------------------- step
function go(i) {
  if (!D) return;
  const steps = S();
  if (!steps.length) { $("#ex-title").textContent = "Nothing to show"; $("#ex-body").innerHTML = ""; return; }
  cur = Math.max(0, Math.min(steps.length - 1, i)); curBy[view] = cur; seen.add(cur);
  const s = steps[cur];
  document.querySelectorAll(".step").forEach((b, j) => { b.classList.toggle("on", j === cur); b.classList.toggle("seen", seen.has(j) && j !== cur); });
  document.querySelector(".step.on")?.scrollIntoView({ block: "nearest" });
  $("#stepnum").textContent = `${cur + 1} / ${steps.length}`;
  $("#prev").disabled = cur === 0; $("#next").disabled = cur === steps.length - 1;
  $("#ex-kicker").textContent = view === "helm" ? `Helm concept ${cur + 1} of ${steps.length}`
    : view === "infra" ? `Infrastructure · ${s.title}`
    : s.node ? `Step ${cur + 1} · ${D.byId[s.node].source}` : `Step ${cur + 1} · ${s.group}`;
  $("#ex-title").textContent = s.title;
  $("#ex-body").innerHTML = md(s.explain);
  renderExtra(s);
  // pointers
  const ptrs = view === "chart" ? s.pointers.filter((p) => p.tone !== "soft" || p.file === R) : [];
  $("#ex-ptrs").innerHTML = ptrs.map((p, k) => `<button class="ptr ${p.tone}" data-k="${k}" title="${esc(p.file === R ? "rendered output" : p.file)}:${p.start}">${esc(p.label.replace(/`/g, ""))} <span class="muted">${p.file === R ? "out" : esc(p.file.split("/").pop())}:${p.start}</span></button>`).join("");
  $("#ex-ptrs").querySelectorAll(".ptr").forEach((b) => (b.onclick = () => jump(ptrs[+b.dataset.k].file, ptrs[+b.dataset.k].start)));
  renderFindings(s);
  if (view === "chart") paintGraph(); else paintView(s);
  // pick file
  const tpl = s.pointers.find((p) => p.file !== R);
  fullOut = false;
  file = mode === "rendered" ? R : tpl ? tpl.file : "Chart.yaml" in D.files ? "Chart.yaml" : Object.keys(D.files)[0];
  renderCode(true);
}
function renderFindings(s) {
  const list = (s.id === "s-summary" ? D.findings : s.findings).slice().sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  const el = $("#ex-find");
  if (!list.length) { el.innerHTML = s.node ? `<div class="ok">✓ No issues found on this resource.</div>` : ""; return; }
  el.innerHTML = `<h3>${s.id === "s-summary" ? "All findings" : "Security & best-practice checks"}</h3>` + list.map((f, k) => `
    <div class="find ${f.sev}"><div class="hd"><span class="pill ${f.sev}">${f.sev}</span><span>${esc(f.title)}</span></div>
    ${s.id === "s-summary" && f.resource ? `<div class="muted" style="font-size:12px;margin-top:4px">${esc(D.byId[f.resource].kind)}/${esc(D.byId[f.resource].name)}</div>` : ""}
    <p>${md(f.detail, true)}</p>
    <div class="acts">${f.tpl ? `<button data-k="${k}" data-w="tpl">Show in template ↗</button><button data-k="${k}" data-w="out">Show rendered ↗</button>` : ""}
    ${f.fix ? `<button data-k="${k}" data-w="fix">How to fix</button>` : ""}${s.id === "s-summary" && f.resource ? `<button data-k="${k}" data-w="go">Go to step</button>` : ""}</div>
    ${f.fix ? `<pre class="hidden" id="fix-${k}">${esc(f.fix)}</pre>` : ""}</div>`).join("");
  el.querySelectorAll(".acts button").forEach((b) => (b.onclick = () => {
    const f = list[+b.dataset.k], w = b.dataset.w;
    if (w === "fix") return $("#fix-" + b.dataset.k).classList.toggle("hidden");
    if (w === "go") return go(D.steps.findIndex((x) => x.node === f.resource));
    const loc = f[w]; if (loc) { if (s.id === "s-summary") jumpFinding(f, loc); else jump(loc.file, loc.line); }
  }));
}
function jumpFinding(f, loc) {
  if (loc.file === R) { fullOut = true; if (mode === "template") setMode("rendered", false); } else { file = loc.file; if (mode === "rendered") setMode("template", false); }
  renderCode(false, [{ file: loc.file, start: loc.line, end: loc.line, tone: "f-" + f.sev, label: f.title }]); flash(loc.file, loc.line);
}

// ---------------------------------------------------------------- code
function lineMarks(extra = []) {
  const s = S()[cur], marks = {};
  const set = (ln, cls, note) => { const m = (marks[ln] ||= { cls: [], notes: [] }); m.cls.push(cls); if (note) m.notes.push(note); };
  for (const p of [...s.pointers, ...extra]) if (p.file === file) for (let l = p.start; l <= p.end; l++) set(l, p.tone, l === p.start && p.tone !== "soft" ? p.label.replace(/`/g, "") : "");
  const fl = s.id === "s-summary" ? [] : s.findings;
  for (const f of fl) for (const loc of [f.tpl, f.out]) if (loc && loc.file === file) set(loc.line, "f-" + f.sev, "⚠ " + f.title);
  return marks;
}
function renderCode(auto, extra = []) {
  const s = S()[cur];
  const node = s.node ? D.byId[s.node] : null;
  // which template file to show (left pane in split mode)
  let tplFile = file !== R ? file : (s.pointers.find((p) => p.file !== R) || {}).file || "Chart.yaml";
  const stepFiles = [...new Set(s.pointers.map((p) => p.file))].filter((f) => f !== R);
  const base = ["Chart.yaml", "values.yaml"].filter((f) => D.files[f]);
  const tabs = [...new Set([...stepFiles, ...base, tplFile])].filter((f) => D.files[f] !== undefined);
  const showTpl = mode !== "rendered" && file !== R || mode === "split";
  const showOut = mode === "rendered" || mode === "split" || file === R;
  $("#tabs").innerHTML = tabs.map((f) => `<button class="tab ${showTpl && f === tplFile ? "on" : ""}" data-f="${esc(f)}">${esc(f)}</button>`).join("")
    + (D.rendered ? `<button class="tab r ${showOut ? "on" : ""}" data-f="${R}">⚙ rendered (helm template)</button>` : "")
    + `<select class="tab" id="allfiles" aria-label="Open any file"><option value="">All files…</option>${Object.keys(D.files).map((f) => `<option>${esc(f)}</option>`).join("")}</select>`;
  $("#tabs").querySelectorAll("button.tab").forEach((b) => (b.onclick = () => {
    file = b.dataset.f;
    if (mode !== "split") setMode(file === R ? "rendered" : "template", false);
    renderCode(true);
  }));
  $("#allfiles").onchange = (e) => { if (e.target.value) { file = e.target.value; if (mode === "rendered") setMode("template", false); renderCode(true); } };
  $("#allfiles").style.background = "transparent"; $("#allfiles").style.border = "0";

  const panes = [];
  if (showTpl) panes.push(paneHTML(tplFile, D.files[tplFile] ?? "", lineMarks(tplFile, extra), null,
    mode === "split" ? `<b>Template</b> · ${esc(tplFile)}` : ""));
  if (showOut) {
    const range = node && !fullOut ? [node.outStart, node.outEnd] : null;
    const head = !D.rendered ? `<b>Rendered</b> · nothing rendered${D.renderError ? " (see Values)" : ""}`
      : range ? `<b>Rendered</b> · ${esc(node.kind)}/${esc(node.name)} only <button class="lnk" id="full-out">show full output</button>`
      : `<b>Rendered</b> · full <code>helm template</code> output${node ? ` <button class="lnk" id="full-out">show only ${esc(node.kind)}</button>` : ""}`;
    panes.push(paneHTML(R, D.rendered || "", lineMarks(R, extra), range, head));
  }
  const cv = $("#codeview");
  cv.classList.toggle("split", panes.length > 1);
  cv.innerHTML = panes.join("");
  const fo = $("#full-out"); if (fo) fo.onclick = () => { fullOut = !fullOut; renderCode(true); };
  if (auto) cv.querySelectorAll(".pane").forEach((p) => autoScroll(p));
}
function paneHTML(fname, text, marks, range, head) {
  const lines = text.split("\n");
  const [a, b] = range || [1, lines.length];
  let html = "";
  for (let i = a; i <= Math.min(b, lines.length); i++) {
    const ln = lines[i - 1], m = marks[i], cls = m ? m.cls.sort((x, y) => rank(x) - rank(y))[0] : "";
    const note = m && m.notes.length ? `<span class="note">${esc(m.notes[0])}${m.notes.length > 1 ? ` +${m.notes.length - 1}` : ""}</span>` : "";
    html += `<div class="ln ${cls}" data-l="${i}"${m && m.notes.length ? ` title="${esc(m.notes.join("\n"))}"` : ""}><span class="no">${i}</span><span>${hl(ln) || " "}</span>${note}</div>`;
  }
  return `<div class="pane" data-f="${esc(fname)}">${head ? `<div class="pane-h">${head}</div>` : ""}<div class="pane-b">${html}</div></div>`;
}
function lineMarks(fname, extra = []) {
  const s = S()[cur], marks = {};
  const set = (ln, cls, note) => { const m = (marks[ln] ||= { cls: [], notes: [] }); m.cls.push(cls); if (note) m.notes.push(note); };
  for (const p of [...s.pointers, ...extra]) if (p.file === fname) for (let l = p.start; l <= p.end; l++) set(l, p.tone, l === p.start && p.tone !== "soft" ? p.label.replace(/`/g, "") : "");
  const fl = s.id === "s-summary" ? [] : s.findings;
  for (const f of fl) for (const loc of [f.tpl, f.out]) if (loc && loc.file === fname) set(loc.line, "f-" + f.sev, "⚠ " + f.title);
  return marks;
}
function autoScroll(pane) {
  const marks = [...pane.querySelectorAll(".ln")];
  const order = ["f-critical", "f-high", "focus", "info", "f-medium", "f-low", "f-info", "soft"];
  let target = null;
  for (const c of order) { target = marks.find((el) => el.classList.contains(c)); if (target) break; }
  const soft = marks.find((el) => el.classList.contains("soft"));
  const el = soft && target && +target.dataset.l - +soft.dataset.l < 18 ? soft : target;
  const body = pane.querySelector(".pane-b");
  body.scrollTop = el ? Math.max(0, el.offsetTop - body.offsetTop - 60) : 0;
}
const rank = (c) => ({ "f-critical": 0, "f-high": 1, "f-medium": 2, focus: 3, info: 4, "f-low": 5, "f-info": 6, soft: 7 }[c] ?? 9);
function lineEl(f, l) { return document.querySelector(`#codeview .pane[data-f="${CSS.escape(f)}"] .ln[data-l="${l}"]`); }
function flash(f, l) {
  const el = lineEl(f, l); if (!el) return;
  const body = el.closest(".pane-b"); body.scrollTop = Math.max(0, el.offsetTop - body.offsetTop - 60);
  el.classList.remove("flash"); void el.offsetWidth; el.classList.add("flash");
}
function jump(f, l) {
  if (f === R) {
    const node = S()[cur].node && D.byId[S()[cur].node];
    if (node && (l < node.outStart || l > node.outEnd)) fullOut = true;
    if (mode === "template") setMode("rendered", false);
  } else {
    file = f;
    if (mode === "rendered") setMode("template", false);
  }
  renderCode(false); flash(f, l);
}
function setMode(m, rerender = true) {
  mode = m;
  document.querySelectorAll(".seg button").forEach((x) => x.classList.toggle("on", x.dataset.mode === m));
  if (rerender && D) go(cur);
}

// YAML + Go template highlighter (escapes first, then wraps)
function hl(line) {
  if (/^\s*#/.test(line)) return `<span class="c">${esc(line)}</span>`;
  return line.split(/(\{\{.*?\}\})/g).map((part, i) => {
    if (i % 2) return `<span class="tp">${esc(part).replace(/(&quot;.*?&quot;)/g, '<span class="s">$1</span>')}</span>`;
    let e = esc(part);
    e = e.replace(/^(\s*-?\s*)([\w.\/"'-]+)(:)(?=\s|$)/, '$1<span class="k">$2</span>$3');
    e = e.replace(/(&quot;[^&]*?&quot;|&#39;[^&]*?&#39;)/g, '<span class="s">$1</span>');
    e = e.replace(/(:\s+)(true|false|null|-?\d+(?:\.\d+)?[a-zA-Z]*)\s*$/, '$1<span class="nm">$2</span>');
    e = e.replace(/(\s)(#.*)$/, '$1<span class="c">$2</span>');
    e = e.replace(/(setme-[a-z0-9-]+)/g, '<span class="ph">$1</span>');
    return e;
  }).join("");
}
// tiny markdown: paragraphs, **bold**, `code`, ```blocks```
function md(s, inline) {
  const blocks = String(s || "").split(/```/);
  const out = blocks.map((b, i) => {
    if (i % 2) return `<pre>${esc(b.replace(/^\n|\n$/g, ""))}</pre>`;
    const f = (t) => esc(t).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/`([^`]+)`/g, "<code>$1</code>");
    return inline ? f(b) : b.split(/\n\n+/).filter((p) => p.trim()).map((p) => `<p>${f(p)}</p>`).join("");
  });
  return out.join("");
}

// ---------------------------------------------------------------- controls
$("#prev").onclick = () => go(cur - 1);
$("#next").onclick = () => go(cur + 1);
document.querySelectorAll(".seg button").forEach((b) => (b.onclick = () => {
  setMode(b.dataset.mode);
}));
document.addEventListener("keydown", (e) => {
  if (!D || /INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)) return;
  if (e.key === "ArrowRight" || e.key === "j") go(cur + 1);
  if (e.key === "ArrowLeft" || e.key === "k") go(cur - 1);
  if (e.key === "1") setView("chart");
  if (e.key === "2") setView("helm");
  if (e.key === "3") setView("infra");
  if (e.key === "t") setMode({ template: "rendered", rendered: "split", split: "template" }[mode]);
});

if (window.__PRELOAD__) load(window.__PRELOAD__);
})();
