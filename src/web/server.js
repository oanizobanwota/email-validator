#!/usr/bin/env node
"use strict";

/**
 * Web version: the same validation engine behind a small HTTP server, serving the same
 * page as the desktop app. Open it from any browser; the heavy lifting (DNS + SMTP)
 * runs on the server, which is also where port 25 must be open.
 *
 *   WEB_PASSWORD=secret PORT=8080 node src/web/server.js
 *
 * Endpoints (JSON):
 *   GET  /api/defaults            engine defaults
 *   GET  /api/network             is outbound port 25 open from this server (cached 60 s)
 *   POST /api/validate            { email, options }           -> result
 *   POST /api/validate-many       { emails[], options }        -> { runId }
 *   GET  /api/runs/:id/events     Server-Sent Events: "progress" {items,total} … "done" {results,stopped}
 *   POST /api/runs/:id/stop
 * Access: username + password accounts (node src/web/users.js add <name> <password>);
 *         POST /api/login sets a signed HttpOnly session cookie (7 days), POST /api/logout clears it.
 */

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { createSession, checkOutboundSmtp, extractEmails, DEFAULTS } = require("../main/validator");
const users = require("./users");

const PORT = parseInt(process.env.PORT || "8080", 10);
const HOST = process.env.HOST || "0.0.0.0";
const MAX_EMAILS = parseInt(process.env.MAX_EMAILS || "20000", 10);
const MAX_CONCURRENCY = parseInt(process.env.MAX_CONCURRENCY || "30", 10);
const RUN_TTL_MS = 30 * 60 * 1000;

const RENDERER_DIR = path.join(__dirname, "..", "renderer");
const STATIC = {
  "/app.js": { file: path.join(RENDERER_DIR, "app.js"), type: "text/javascript; charset=utf-8" },
  "/styles.css": { file: path.join(RENDERER_DIR, "styles.css"), type: "text/css; charset=utf-8" },
  "/web-bridge.js": { file: path.join(__dirname, "web-bridge.js"), type: "text/javascript; charset=utf-8" },
};

const runs = new Map(); // runId -> { id, total, results, events: [], done, stopped, subscribers:Set<res>, createdAt, stopFlag }
let networkCache = null;

// ----- sessions: signed, HttpOnly cookie; accounts via users.js -----
const SESSION_COOKIE = "ev_session";
const SESSION_TTL_S = 7 * 24 * 3600;
const SECRET_FILE = process.env.SESSION_SECRET_FILE || path.join(__dirname, "..", "..", ".session-secret");
function sessionSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  try { return fs.readFileSync(SECRET_FILE, "utf8").trim(); } catch { /* create */ }
  const s = crypto.randomBytes(32).toString("hex");
  try { fs.writeFileSync(SECRET_FILE, s, { mode: 0o600 }); } catch { /* read-only fs: in-memory secret */ }
  return s;
}
const SECRET = sessionSecret();
const b64u = (x) => Buffer.from(x).toString("base64url");
function makeSession(user) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_S;
  const body = `${b64u(user)}.${exp}`;
  const mac = crypto.createHmac("sha256", SECRET).update(body).digest("base64url");
  return `${body}.${mac}`;
}
function readSession(req) {
  const m = (req.headers.cookie || "").match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE}=([^;]*)`));
  if (!m) return null;
  const [u, exp, mac] = decodeURIComponent(m[1]).split(".");
  if (!u || !exp || !mac) return null;
  const want = crypto.createHmac("sha256", SECRET).update(`${u}.${exp}`).digest("base64url");
  const A = Buffer.from(mac), B = Buffer.from(want);
  if (A.length !== B.length || !crypto.timingSafeEqual(A, B)) return null;
  if (parseInt(exp, 10) * 1000 < Date.now()) return null;
  return { user: Buffer.from(u, "base64url").toString("utf8") };
}
function setSessionCookie(res, value, maxAge) {
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=${encodeURIComponent(value)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`);
}
// Brute-force brake: 10 failed logins per IP per 15 minutes.
const failures = new Map();
function tooManyFailures(ip) {
  const f = failures.get(ip);
  return f && f.count >= 10 && Date.now() - f.first < 15 * 60 * 1000;
}
function noteFailure(ip) {
  const f = failures.get(ip);
  if (!f || Date.now() - f.first > 15 * 60 * 1000) failures.set(ip, { count: 1, first: Date.now() });
  else f.count++;
}
const OPEN_ACCESS = !users.hasAnyUser();   // no accounts configured at all → open (local use only)

function json(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(data);
}
function readJson(req, limitBytes = 10 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", (c) => { size += c.length; if (size > limitBytes) { reject(Object.assign(new Error("Body too large"), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); } catch { reject(Object.assign(new Error("Invalid JSON"), { status: 400 })); } });
    req.on("error", reject);
  });
}
function cleanOptions(o) {
  const opts = {};
  if (o && typeof o === "object") {
    if (typeof o.smtp === "boolean") opts.smtp = o.smtp;
    if (typeof o.catchAll === "boolean") opts.catchAll = o.catchAll;
    if (Number.isFinite(o.concurrency)) opts.concurrency = Math.max(1, Math.min(MAX_CONCURRENCY, Math.floor(o.concurrency)));
  }
  return opts;
}

function pushEvent(run, event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  run.events.push(payload);
  for (const res of run.subscribers) res.write(payload);
}

async function startRun(emails, options) {
  const run = { id: crypto.randomUUID(), total: emails.length, results: null, events: [], done: false, stopped: false, subscribers: new Set(), createdAt: Date.now(), stopFlag: false };
  runs.set(run.id, run);
  const session = createSession(options);
  let pending = [], timer = null;
  const flush = () => { timer = null; if (pending.length) { pushEvent(run, "progress", { runId: run.id, items: pending, total: run.total }); pending = []; } };
  session.validateMany(emails, (result, index, total, finished) => {
    pending.push({ result, index, finished });
    if (!timer) timer = setTimeout(flush, 400);
  }, () => run.stopFlag).then((results) => {
    if (timer) clearTimeout(timer);
    flush();
    run.results = results; run.done = true; run.stopped = run.stopFlag;
    pushEvent(run, "done", { runId: run.id, results, stopped: run.stopped });
    for (const res of run.subscribers) res.end();
    run.subscribers.clear();
  }).catch((err) => {
    run.done = true;
    pushEvent(run, "error", { message: err.message });
    for (const res of run.subscribers) res.end();
  });
  return run;
}

setInterval(() => {
  const cutoff = Date.now() - RUN_TTL_MS;
  for (const [id, run] of runs) if (run.done && run.createdAt < cutoff) runs.delete(id);
}, 60 * 1000).unref();

function serveIndex(res) {
  let html = fs.readFileSync(path.join(RENDERER_DIR, "index.html"), "utf8");
  html = html.replace('<script src="app.js"></script>', '<script src="web-bridge.js"></script><script src="app.js"></script>');
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
  res.end(html);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  try {
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) return serveIndex(res);
    if (req.method === "GET" && STATIC[url.pathname]) {
      const s = STATIC[url.pathname];
      res.writeHead(200, { "Content-Type": s.type, "Cache-Control": "no-cache" });
      return fs.createReadStream(s.file).pipe(res);
    }
    if (!url.pathname.startsWith("/api/")) { res.writeHead(404); return res.end("Not found"); }

    const ip = req.socket.remoteAddress || "?";
    if (req.method === "POST" && url.pathname === "/api/login") {
      if (tooManyFailures(ip)) return json(res, 429, { error: "TOO_MANY_ATTEMPTS" });
      const body = await readJson(req, 16 * 1024);
      if (users.authenticate(body.username, body.password)) {
        const user = String(body.username).trim().toLowerCase();
        setSessionCookie(res, makeSession(user), SESSION_TTL_S);
        return json(res, 200, { ok: true, user });
      }
      noteFailure(ip);
      return json(res, 401, { error: "BAD_CREDENTIALS" });
    }
    if (req.method === "POST" && url.pathname === "/api/logout") { setSessionCookie(res, "", 0); return json(res, 200, { ok: true }); }
    const session = OPEN_ACCESS ? { user: "local" } : readSession(req);
    if (req.method === "GET" && url.pathname === "/api/me") return json(res, session ? 200 : 401, session ? { user: session.user } : { error: "SIGN_IN_REQUIRED" });
    if (!session) return json(res, 401, { error: "SIGN_IN_REQUIRED" });

    if (req.method === "GET" && url.pathname === "/api/defaults") return json(res, 200, { ...DEFAULTS, maxEmails: MAX_EMAILS, maxConcurrency: MAX_CONCURRENCY });
    if (req.method === "GET" && url.pathname === "/api/network") {
      if (!networkCache || Date.now() - networkCache.at > 60_000) networkCache = { at: Date.now(), value: await checkOutboundSmtp() };
      return json(res, 200, networkCache.value);
    }
    if (req.method === "POST" && url.pathname === "/api/validate") {
      const body = await readJson(req, 64 * 1024);
      const email = String(body.email || "").slice(0, 320);
      return json(res, 200, await createSession(cleanOptions(body.options)).validateEmail(email));
    }
    if (req.method === "POST" && url.pathname === "/api/validate-many") {
      const body = await readJson(req);
      const emails = Array.isArray(body.emails) ? body.emails.map((e) => String(e).slice(0, 320)) : extractEmails(String(body.text || ""));
      if (!emails.length) return json(res, 400, { error: "NO_EMAILS" });
      if (emails.length > MAX_EMAILS) return json(res, 413, { error: "TOO_MANY", max: MAX_EMAILS });
      const run = await startRun(emails, cleanOptions(body.options));
      return json(res, 200, { runId: run.id, total: run.total });
    }
    const m = url.pathname.match(/^\/api\/runs\/([0-9a-f-]{36})\/(events|stop|result)$/);
    if (m) {
      const run = runs.get(m[1]);
      if (!run) return json(res, 404, { error: "RUN_NOT_FOUND" });
      if (req.method === "POST" && m[2] === "stop") { run.stopFlag = true; return json(res, 200, { ok: true }); }
      if (req.method === "GET" && m[2] === "result") return json(res, 200, { done: run.done, stopped: run.stopped, results: run.results });
      if (req.method === "GET" && m[2] === "events") {
        res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive", "X-Accel-Buffering": "no" });
        res.write(": connected\n\n");
        for (const e of run.events) res.write(e);   // replay what this client missed
        if (run.done) return res.end();
        run.subscribers.add(res);
        const keepAlive = setInterval(() => { try { res.write(": ping\n\n"); } catch { /* ignore */ } }, 20_000);
        req.on("close", () => { clearInterval(keepAlive); run.subscribers.delete(res); });
        return;
      }
    }
    json(res, 404, { error: "NOT_FOUND" });
  } catch (err) {
    json(res, err.status || 500, { error: err.message });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Email Validator web version listening on http://${HOST}:${PORT}`);
  if (OPEN_ACCESS) console.log("WARNING: no user accounts configured (users.json / WEB_USERS / WEB_PASSWORD) — anyone who can reach this port can use it. Add one with: node src/web/users.js add <name> <password>");
  else console.log(`Accounts file: ${users.USERS_FILE}`);
});
