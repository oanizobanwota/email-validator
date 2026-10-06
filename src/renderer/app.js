"use strict";

const $ = (id) => document.getElementById(id);
const api = window.validator;

const els = {
  net: $("net"), netText: $("netText"),
  singleForm: $("singleForm"), singleInput: $("singleInput"), singleBtn: $("singleBtn"), singleResult: $("singleResult"),
  bulkInput: $("bulkInput"), importBtn: $("importBtn"), clearBtn: $("clearBtn"), count: $("count"),
  optSmtp: $("optSmtp"), optCatchAll: $("optCatchAll"), optConc: $("optConc"),
  runBtn: $("runBtn"), stopBtn: $("stopBtn"), progress: $("progress"), bar: $("bar"),
  resultsPanel: $("resultsPanel"), summary: $("summary"), filter: $("filter"), tbody: $("tbody"),
  netNote: $("netNote"), progressText: $("progressText"),
  licenseGate: $("licenseGate"), licenseForm: $("licenseForm"), licenseInput: $("licenseInput"), licenseError: $("licenseError"), licenseBtn: $("licenseBtn"), licenseHint: $("licenseHint"),
  userBox: $("userBox"), userName: $("userName"), logoutBtn: $("logoutBtn"),
  copyValidBtn: $("copyValidBtn"), copyUnknownBtn: $("copyUnknownBtn"), exportBtn: $("exportBtn"), clearResultsBtn: $("clearResultsBtn"),
};

let results = [];      // current bulk results (input order)
let running = false;
let currentRunId = null;
const counts = { valid: 0, invalid: 0, risky: 0, unknown: 0, pending: 0 };
const ROW_CAP = 400;   // rows drawn at once; the rest are reachable through the filter / export
let shown = 0;         // how many matching rows are currently drawn
let summaryTimer = null;
let runStarted = 0;
let runFinished = 0;
let runTotal = 0;
let progressTimer = null;
let runDurationText = "";

function renderProgressText() {
  if (!running) return;
  const elapsed = (Date.now() - runStarted) / 1000;
  const rate = runFinished / Math.max(elapsed, 0.001);
  const left = runTotal - runFinished;
  const eta = runFinished >= 5 && rate > 0 ? ` · about ${fmtSecs(left / rate)} left` : "";
  els.progressText.textContent = `${runFinished} of ${runTotal} checked · ${fmtSecs(elapsed)} elapsed${eta}`;
}
function fmtSecs(s) {
  s = Math.round(s);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return m < 60 ? `${m}m ${s % 60}s` : `${Math.floor(m / 60)}h ${m % 60}m`;
}

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function options() {
  return {
    smtp: els.optSmtp.checked,
    catchAll: els.optCatchAll.checked,
    concurrency: Math.max(1, Math.min(50, parseInt(els.optConc.value, 10) || 12)),
  };
}

function flagsHtml(r) {
  const f = [];
  if (r.disposable) f.push("disposable");
  if (r.role) f.push("role");
  if (r.catchAll) f.push("catch-all");
  if (r.suggestion) f.push("typo?");
  if (r.smtp === "full") f.push("full");
  return f.map((x) => `<span class="flag">${x}</span>`).join("");
}

// ---------- network indicator ----------
async function checkNetwork() {
  try {
    const r = await api.checkNetwork();
    els.net.classList.toggle("ok", r.ok);
    els.net.classList.toggle("bad", !r.ok);
    els.netText.textContent = r.ok ? "Outbound SMTP OK — mailboxes can be probed" : "Port 25 blocked — only syntax + DNS checks will be conclusive";
    if (!r.ok) {
      els.optSmtp.checked = false;
      els.netNote.textContent = "This network blocks outbound port 25, so mail servers cannot be asked whether a mailbox exists. Mailbox probing has been switched off: you still get syntax, typo, disposable and mail-server (MX) checks, and the run finishes quickly. Tick \"Probe mailbox\" to force probing anyway (each domain then waits for a timeout).";
      els.netNote.classList.remove("hidden");
    }
  } catch {
    els.netText.textContent = "Network check failed";
  }
}

// ---------- single ----------
els.singleForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = els.singleInput.value.trim();
  if (!email) return;
  els.singleBtn.disabled = true;
  els.singleResult.classList.remove("hidden");
  els.singleResult.innerHTML = `<div class="head"><span class="badge checking">checking…</span><span class="email">${esc(email)}</span></div>`;
  try {
    const r = await api.validateOne(email, options());
    renderSingle(r);
  } catch (err) {
    els.singleResult.innerHTML = `<div class="head"><span class="badge unknown">error</span><span>${esc(err.message)}</span></div>`;
  } finally {
    els.singleBtn.disabled = false;
  }
});

function renderSingle(r) {
  const yn = (v) => (v === true ? "yes" : v === false ? "no" : "—");
  els.singleResult.innerHTML = `
    <div class="head"><span class="badge ${r.status}">${r.status}</span><span class="email">${esc(r.email)}</span>${flagsHtml(r)}</div>
    <div class="reason">${esc(r.reason)}</div>
    <div class="checks">
      <div>Syntax: <b>${yn(r.syntax)}</b></div>
      <div>Mail servers (MX): <b>${yn(r.mx)}</b></div>
      <div>SMTP probe: <b>${esc(r.smtp || "—")}</b></div>
      <div>Catch-all domain: <b>${yn(r.catchAll)}</b></div>
      <div>Disposable: <b>${yn(r.disposable)}</b></div>
      <div>Role account: <b>${yn(r.role)}</b></div>
      <div>Time: <b>${r.elapsedMs} ms</b></div>
    </div>
    ${r.mxHosts?.length || r.smtpDetail ? `<details><summary>Details</summary><pre>${esc([
      r.mxHosts?.length ? "MX: " + r.mxHosts.join(", ") : "",
      r.resolver ? "DNS via: " + r.resolver : "",
      r.smtpHost ? "Probed: " + r.smtpHost : "",
      r.smtpDetail ? "Reply: " + r.smtpDetail : "",
    ].filter(Boolean).join("\n"))}</pre></details>` : ""}
  `;
}

// ---------- bulk ----------
let countTimer = null;
els.bulkInput.addEventListener("input", () => {
  clearTimeout(countTimer);
  countTimer = setTimeout(updateCount, 400);
});
async function updateCount() {
  const list = await api.extractEmails(els.bulkInput.value);
  els.count.textContent = `${list.length} address${list.length === 1 ? "" : "es"}`;
  return list;
}

els.importBtn.addEventListener("click", async () => {
  const r = await api.openFile();
  if (!r) return;
  const existing = els.bulkInput.value.trim();
  els.bulkInput.value = (existing ? existing + "\n" : "") + r.emails.join("\n");
  updateCount();
});

els.clearBtn.addEventListener("click", () => {
  els.bulkInput.value = "";
  updateCount();
  if (!running) clearResults();
});

function clearResults() {
  results = [];
  counts.valid = counts.invalid = counts.risky = counts.unknown = counts.pending = 0;
  runDurationText = "";
  shown = 0;
  els.tbody.innerHTML = "";
  els.summary.innerHTML = "";
  const note = document.getElementById("capNote");
  if (note) note.textContent = "";
  els.resultsPanel.classList.add("hidden");
  els.progressText.classList.add("hidden");
  els.progress.classList.add("hidden");
  refreshCopyLabels();
}
els.clearResultsBtn.addEventListener("click", () => { if (!running) clearResults(); });

// One copy button per status: label carries the live count, flashes "Copied N", then restores.
const COPY_BUTTONS = [
  { el: () => els.copyValidBtn, status: "valid", label: "Copy valid", timer: null },
  { el: () => els.copyUnknownBtn, status: "unknown", label: "Copy unknown", timer: null },
];
function refreshCopyLabels() {
  for (const b of COPY_BUTTONS) if (!b.timer) b.el().textContent = `${b.label} (${counts[b.status] || 0})`;
}

els.runBtn.addEventListener("click", async () => {
  if (running) return;
  const emails = await updateCount();
  if (!emails.length) { els.bulkInput.focus(); return; }
  startRun(emails);
});

els.stopBtn.addEventListener("click", () => { api.stop(); els.stopBtn.disabled = true; });

async function startRun(emails) {
  running = true;
  results = emails.map((email) => ({ email, status: "pending", reason: "", mxHosts: [], elapsedMs: null }));
  counts.valid = counts.invalid = counts.risky = counts.unknown = 0;
  counts.pending = results.length;
  els.runBtn.disabled = true;
  els.stopBtn.classList.remove("hidden");
  els.stopBtn.disabled = false;
  els.progress.classList.remove("hidden");
  els.bar.style.width = "0%";
  runStarted = Date.now(); runFinished = 0; runTotal = emails.length; runDurationText = "";
  els.progressText.textContent = "Starting…";
  els.progressText.classList.remove("hidden");
  progressTimer = setInterval(renderProgressText, 1000);
  els.resultsPanel.classList.remove("hidden");
  renderTable();
  renderSummary();
  try {
    const res = await api.validateMany(emails, options());
    currentRunId = res.runId;
    res.results.forEach((r, i) => { if (r) applyResult(i, r); });
    results.forEach((r, i) => { if (r.status === "pending") applyResult(i, { ...r, status: "unknown", reason: "Stopped before this address was checked" }); });
  } catch (err) {
    alert("Validation failed: " + err.message);
  } finally {
    running = false;
    els.runBtn.disabled = false;
    els.stopBtn.classList.add("hidden");
    els.bar.style.width = "100%";
    clearInterval(progressTimer);
    runDurationText = fmtSecs((Date.now() - runStarted) / 1000);
    els.progressText.textContent = `${results.length} checked in ${runDurationText}`;
    els.clearResultsBtn.disabled = false;
    setTimeout(() => els.progress.classList.add("hidden"), 600);
    renderTable();
    renderSummary();
  }
}

function applyResult(i, r) {
  const prev = results[i];
  if (prev && counts[prev.status] !== undefined) counts[prev.status]--;
  results[i] = r;
  counts[r.status] = (counts[r.status] || 0) + 1;
}

api.onProgress(({ items, total }) => {
  if (!running) return;
  let finished = 0;
  const touched = [];
  for (const { result, index, finished: f } of items) {
    applyResult(index, result);
    touched.push(index);
    finished = Math.max(finished, f);
  }
  runFinished = Math.max(runFinished, finished);
  els.bar.style.width = `${Math.round((finished / total) * 100)}%`;
  renderProgressText();
  updateRows(touched);
  scheduleSummary();
});

function rowHtml(r, i) {
  const pending = r.status === "pending";
  return `
    <td class="num">${i + 1}</td>
    <td class="email">${esc(r.email)}</td>
    <td><span class="badge ${pending ? "checking" : r.status}">${pending ? "…" : r.status}</span></td>
    <td class="reason">${esc(r.reason)}</td>
    <td>${pending ? "" : flagsHtml(r)}</td>
    <td class="mx" title="${esc((r.mxHosts || []).join(", "))}">${esc((r.mxHosts || [])[0] || "")}</td>
    <td class="num">${r.elapsedMs ?? ""}</td>`;
}

function visible(r) {
  const f = els.filter.value;
  return f === "all" || r.status === f;
}

function renderTable() {
  const rows = [];
  shown = 0;
  for (let i = 0; i < results.length && shown < ROW_CAP; i++) {
    const r = results[i];
    if (!visible(r)) continue;
    rows.push(`<tr data-i="${i}" class="${r.status === "pending" ? "pending" : ""}">${rowHtml(r, i)}</tr>`);
    shown++;
  }
  els.tbody.innerHTML = rows.join("");
  renderCapNote();
}

function renderCapNote() {
  const matching = els.filter.value === "all" ? results.length : (counts[els.filter.value] || 0);
  let note = document.getElementById("capNote");
  if (!note) {
    note = document.createElement("div");
    note.id = "capNote";
    note.className = "muted";
    note.style.padding = "8px 10px";
    els.tbody.parentElement.parentElement.appendChild(note);
  }
  note.textContent = matching > shown ? `Showing the first ${shown} of ${matching} matching rows — narrow with the filter, or export everything to CSV.` : "";
}

// Update only rows that are drawn; rows beyond the cap are counted but not painted.
function updateRows(indices) {
  if (!indices.length) return;
  const f = els.filter.value;
  for (const i of indices) {
    const r = results[i];
    const tr = els.tbody.querySelector(`tr[data-i="${i}"]`);
    if (tr) {
      if (!visible(r)) { tr.remove(); shown--; continue; }
      tr.className = "";
      tr.innerHTML = rowHtml(r, i);
    } else if (f !== "all" && visible(r) && shown < ROW_CAP) {
      els.tbody.insertAdjacentHTML("beforeend", `<tr data-i="${i}">${rowHtml(r, i)}</tr>`);
      shown++;
    }
  }
  renderCapNote();
}

function scheduleSummary() {
  if (summaryTimer) return;
  summaryTimer = setTimeout(() => { summaryTimer = null; renderSummary(); }, 500);
}

function renderSummary() {
  const c = counts;
  refreshCopyLabels();
  els.clearResultsBtn.disabled = running;
  els.summary.innerHTML = `
    <span class="valid"><b>${c.valid}</b> valid</span>
    <span class="invalid"><b>${c.invalid}</b> invalid</span>
    <span class="risky"><b>${c.risky}</b> risky</span>
    <span class="unknown"><b>${c.unknown}</b> unknown</span>
    ${c.pending ? `<span><b>${c.pending}</b> pending</span>` : ""}
    <span>${results.length} total</span>
    ${runDurationText ? `<span title="Total time for this run">⏱ <b>${runDurationText}</b></span>` : running ? `<span>⏱ <b>${fmtSecs((Date.now() - runStarted) / 1000)}</b></span>` : ""}`;
}

els.filter.addEventListener("change", renderTable);

// Clipboard: the async API only exists on https/localhost; fall back to the classic
// selection + execCommand path (works over plain http, e.g. the web version on a VPS).
async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); return true; }
  } catch { /* fall through */ }
  const ta = document.createElement("textarea");
  ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.opacity = "0";
  document.body.appendChild(ta); ta.select();
  let ok = false;
  try { ok = document.execCommand("copy"); } catch { ok = false; }
  document.body.removeChild(ta);
  return ok;
}

for (const b of COPY_BUTTONS) {
  b.el().addEventListener("click", async () => {
    const list = results.filter((r) => r.status === b.status).map((r) => r.normalized || r.email);
    const ok = await copyText(list.join("\n"));
    clearTimeout(b.timer);
    b.el().textContent = ok ? `Copied ${list.length}` : "Copy failed — use Export CSV";
    b.timer = setTimeout(() => { b.timer = null; refreshCopyLabels(); }, ok ? 1500 : 3000);
  });
}

els.exportBtn.addEventListener("click", async () => {
  const done = results.filter((r) => r.status !== "pending");
  if (!done.length) return;
  const p = await api.exportCsv(done);
  if (p) {
    const old = els.exportBtn.textContent;
    els.exportBtn.textContent = "Saved";
    setTimeout(() => (els.exportBtn.textContent = old), 1500);
  }
});

// Keyboard: ⌘/Ctrl+Enter in the textarea runs the list.
els.bulkInput.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); els.runBtn.click(); }
});

// ---------- desktop license gate ----------
function showLicenseGate(msg) {
  els.licenseGate.classList.remove("hidden");
  document.body.classList.add("locked");
  if (msg) { els.licenseError.textContent = msg; els.licenseError.classList.remove("hidden"); } else els.licenseError.classList.add("hidden");
  setTimeout(() => els.licenseInput.focus(), 50);
}
function hideLicenseGate(lic) {
  els.licenseGate.classList.add("hidden");
  document.body.classList.remove("locked");
  if (lic) {
    els.userName.textContent = `Licensed to ${lic.name}${lic.expires ? ` · until ${lic.expires}` : ""}`;
    els.logoutBtn.textContent = "Change key";
    els.userBox.classList.remove("hidden");
  }
}
async function initLicense() {
  if (!api.license) return;                       // web version: the server handles sign-in instead
  const st = await api.license.status();
  if (st.valid) hideLicenseGate(st.license);
  else showLicenseGate(st.reason === "No license key entered yet" ? "" : st.reason);
  els.licenseForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    els.licenseBtn.disabled = true;
    try {
      const r = await api.license.activate(els.licenseInput.value);
      if (r.valid) { els.licenseInput.value = ""; hideLicenseGate(r.license); }
      else showLicenseGate(r.reason || "Invalid license key");
    } finally { els.licenseBtn.disabled = false; }
  });
  els.logoutBtn.addEventListener("click", async () => {
    if (!confirm("Remove the stored license key from this computer? You will need to enter a key again.")) return;
    await api.license.remove();
    els.userBox.classList.add("hidden");
    showLicenseGate("");
  });
}
initLicense();

// Give the window a moment to settle before the network check (first launch after an
// install is already busy with Defender scanning the fresh files).
setTimeout(checkNetwork, 1500);
updateCount();
