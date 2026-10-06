"use strict";

// Browser replacement for the Electron preload bridge: same window.validator interface,
// implemented over fetch + Server-Sent Events, so app.js runs unchanged in a web page.
(() => {
  document.body.classList.add("web");

  let currentRun = null;
  const listeners = [];
  const $ = (id) => document.getElementById(id);

  // ----- sign-in gate -----
  let loginWaiters = [];
  function showLogin(msg) {
    $("loginGate").classList.remove("hidden");
    document.body.classList.add("locked");
    const err = $("loginError");
    if (msg) { err.textContent = msg; err.classList.remove("hidden"); } else err.classList.add("hidden");
    setTimeout(() => ($("loginUser").value ? $("loginPass") : $("loginUser")).focus(), 50);
    return new Promise((resolve) => loginWaiters.push(resolve));
  }
  function hideLogin(user) {
    $("loginGate").classList.add("hidden");
    document.body.classList.remove("locked");
    $("userName").textContent = user;
    $("userBox").classList.remove("hidden");
    loginWaiters.splice(0).forEach((r) => r());
  }
  $("loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = $("loginBtn"); btn.disabled = true;
    try {
      const res = await fetch("/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin",
        body: JSON.stringify({ username: $("loginUser").value, password: $("loginPass").value }) });
      const data = await res.json().catch(() => ({}));
      if (res.ok) { $("loginPass").value = ""; hideLogin(data.user); }
      else if (res.status === 429) showLogin("Too many failed attempts — wait 15 minutes and try again.");
      else showLogin("Wrong username or password.");
    } catch { showLogin("Could not reach the server."); }
    finally { btn.disabled = false; }
  });
  $("logoutBtn").addEventListener("click", async () => {
    await fetch("/api/logout", { method: "POST", credentials: "same-origin" }).catch(() => {});
    $("userBox").classList.add("hidden");
    $("userName").textContent = "";
    showLogin("");
  });
  // Who am I? Open access (no accounts configured) → no gate at all.
  fetch("/api/me", { credentials: "same-origin" }).then(async (r) => {
    if (r.ok) { const d = await r.json(); if (d.user !== "local") hideLogin(d.user); }
    else showLogin("");
  }).catch(() => {});

  async function api(method, path, body) {
    for (;;) {
      const res = await fetch(path, { method, headers: { "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin" });
      if (res.status === 401) { await showLogin(""); continue; }
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error === "TOO_MANY" ? `Too many addresses — the server accepts up to ${data.max} per run` : data.error || `HTTP ${res.status}`);
      return data;
    }
  }

  const EMAIL_RE = /[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
  function extractEmails(text) {
    const seen = new Set(), out = [];
    for (const m of String(text || "").matchAll(EMAIL_RE)) {
      const e = m[0].replace(/^[.]+|[.]+$/g, ""); const k = e.toLowerCase();
      if (!seen.has(k)) { seen.add(k); out.push(e); }
    }
    return out;
  }
  function toCsv(results) {
    const esc = (v) => { const s = v == null ? "" : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
    const header = ["email", "status", "reason", "syntax", "mx", "mx_hosts", "smtp", "catch_all", "disposable", "role", "suggestion", "smtp_detail", "elapsed_ms"];
    const rows = results.map((r) => [r.email, r.status, r.reason, r.syntax, r.mx, (r.mxHosts || []).join(" "), r.smtp, r.catchAll, r.disposable, r.role, r.suggestion, r.smtpDetail, r.elapsedMs].map(esc).join(","));
    return [header.join(","), ...rows].join("\n") + "\n";
  }

  window.validator = {
    defaults: () => api("GET", "/api/defaults"),
    checkNetwork: () => api("GET", "/api/network"),
    validateOne: (email, options) => api("POST", "/api/validate", { email, options }),

    validateMany: async (emails, options) => {
      const { runId } = await api("POST", "/api/validate-many", { emails, options });
      currentRun = runId;
      return new Promise((resolve, reject) => {
        const es = new EventSource(`/api/runs/${runId}/events`);
        es.addEventListener("progress", (e) => { const p = JSON.parse(e.data); listeners.forEach((cb) => cb(p)); });
        es.addEventListener("done", (e) => { es.close(); resolve(JSON.parse(e.data)); });
        es.addEventListener("error", (e) => { if (e.data) { es.close(); reject(new Error(JSON.parse(e.data).message)); } });
        es.onerror = async () => {
          // Connection dropped: see whether the run finished meanwhile; EventSource retries otherwise.
          try { const r = await api("GET", `/api/runs/${runId}/result`); if (r.done) { es.close(); resolve({ runId, results: r.results, stopped: r.stopped }); } } catch { /* keep retrying */ }
        };
      });
    },

    stop: () => (currentRun ? api("POST", `/api/runs/${currentRun}/stop`) : Promise.resolve(true)),

    openFile: () => new Promise((resolve) => {
      const input = document.createElement("input");
      input.type = "file"; input.accept = ".txt,.csv,.tsv,.lst,.md,text/*";
      input.onchange = async () => {
        const f = input.files && input.files[0];
        if (!f) return resolve(null);
        resolve({ path: f.name, emails: extractEmails(await f.text()) });
      };
      input.click();
    }),

    exportCsv: async (results) => {
      const name = `email-validation-${new Date().toISOString().slice(0, 10)}.csv`;
      const blob = new Blob([toCsv(results)], { type: "text/csv;charset=utf-8" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = name; a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      return name;
    },

    extractEmails: async (text) => extractEmails(text),
    onProgress: (cb) => { listeners.push(cb); return () => { const i = listeners.indexOf(cb); if (i >= 0) listeners.splice(i, 1); }; },
  };
})();
