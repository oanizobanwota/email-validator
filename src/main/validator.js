"use strict";

/**
 * Email validation core. No third-party dependencies — Node built-ins only.
 *
 * Pipeline per address:
 *   1. syntax        — RFC 5321/5322-ish shape, length limits, label rules
 *   2. typo hint     — common provider misspellings (gmial.com → gmail.com)
 *   3. disposable    — throw-away providers
 *   4. role account  — info@, support@ … (flag, not a failure)
 *   5. DNS           — MX records (A/AAAA fallback, per RFC 5321 §5.1)
 *   6. SMTP probe    — EHLO / MAIL FROM / RCPT TO against the best MX, no mail is sent
 *   7. catch-all     — RCPT TO a random mailbox on the same domain; cached per domain
 *
 * Final status:
 *   valid    syntax ok, MX ok, SMTP accepted the exact mailbox (and not a catch-all)
 *   invalid  bad syntax, no mail servers, or SMTP said the mailbox does not exist
 *   risky    deliverable-ish but unreliable: disposable, catch-all domain, mailbox full
 *   unknown  syntax + MX ok but existence could not be proven (port 25 blocked,
 *            greylisting, provider refuses probes, timeout)
 */

const dns = require("node:dns").promises;
const net = require("node:net");
const os = require("node:os");
const crypto = require("node:crypto");
const { DISPOSABLE_DOMAINS } = require("./disposableDomains");

const ROLE_LOCAL_PARTS = new Set([
  "abuse", "admin", "administrator", "billing", "careers", "contact", "customerservice",
  "enquiries", "enquiry", "help", "hello", "hr", "info", "jobs", "mail", "marketing",
  "newsletter", "no-reply", "noreply", "office", "postmaster", "press", "privacy",
  "root", "sales", "security", "support", "team", "webmaster",
]);

// Likely-intended domain for frequent misspellings.
const TYPO_MAP = {
  "gmai.com": "gmail.com", "gmial.com": "gmail.com", "gmali.com": "gmail.com", "gamil.com": "gmail.com",
  "gmail.co": "gmail.com", "gmail.con": "gmail.com", "gmail.cm": "gmail.com", "gmaill.com": "gmail.com",
  "gnail.com": "gmail.com", "gmail.om": "gmail.com", "gemail.com": "gmail.com", "googlemail.co": "googlemail.com",
  "yaho.com": "yahoo.com", "yahooo.com": "yahoo.com", "yhoo.com": "yahoo.com", "yahoo.co": "yahoo.com",
  "yahoo.con": "yahoo.com", "ymail.co": "ymail.com",
  "hotmai.com": "hotmail.com", "hotmial.com": "hotmail.com", "hotmal.com": "hotmail.com", "hotmail.co": "hotmail.com",
  "hotmail.con": "hotmail.com", "hotmail.cm": "hotmail.com", "homail.com": "hotmail.com",
  "outlok.com": "outlook.com", "outloo.com": "outlook.com", "outlook.co": "outlook.com", "outlook.con": "outlook.com",
  "iclod.com": "icloud.com", "icloud.co": "icloud.com", "icoud.com": "icloud.com",
  "live.co": "live.com", "aol.co": "aol.com", "protonmail.co": "protonmail.com", "proton.m": "proton.me",
};

const DEFAULTS = {
  smtp: true,              // run the SMTP mailbox probe
  catchAll: true,          // detect catch-all domains (one extra RCPT per domain, cached)
  connectTimeoutMs: 8000,
  commandTimeoutMs: 10000,
  dnsTimeoutMs: 8000,
  heloHost: defaultHeloHost(),
  fromAddress: null,       // defaults to verify@<heloHost>
  port: 25,
  concurrency: 5,
};

function defaultHeloHost() {
  const h = (os.hostname() || "").toLowerCase().replace(/[^a-z0-9.-]/g, "");
  if (h && h.includes(".")) return h;
  return (h || "verifier") + ".local";
}

// ---------- 1. syntax ------------------------------------------------------

const LOCAL_ATOM = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/;
const QUOTED_LOCAL = /^"([^"\\]|\\.)*"$/;
const LABEL = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

function checkSyntax(raw) {
  const email = String(raw ?? "").trim();
  if (!email) return { ok: false, reason: "Empty address" };
  if (email.length > 254) return { ok: false, reason: "Longer than 254 characters" };
  const at = email.lastIndexOf("@");
  if (at < 1) return { ok: false, reason: "Missing @ or local part" };
  if ((email.match(/@/g) || []).length > 1 && !email.startsWith('"')) {
    return { ok: false, reason: "More than one @" };
  }
  const local = email.slice(0, at);
  const domain = email.slice(at + 1).toLowerCase();
  if (local.length > 64) return { ok: false, reason: "Local part longer than 64 characters" };
  if (/\s/.test(domain) || (/\s/.test(local) && !local.startsWith('"'))) return { ok: false, reason: "Contains whitespace" };
  if (!(LOCAL_ATOM.test(local) || QUOTED_LOCAL.test(local))) {
    return { ok: false, reason: "Local part has invalid characters or dots" };
  }
  if (!domain) return { ok: false, reason: "Missing domain" };
  if (domain.length > 253) return { ok: false, reason: "Domain too long" };
  if (domain.startsWith("[")) return { ok: false, reason: "IP-literal domains are not supported" };
  const labels = domain.split(".");
  if (labels.length < 2) return { ok: false, reason: "Domain has no top-level domain" };
  for (const l of labels) {
    if (!LABEL.test(l)) return { ok: false, reason: `Invalid domain label "${l}"` };
  }
  const tld = labels[labels.length - 1];
  if (!/^[A-Za-z]{2,63}$/.test(tld) && !/^xn--/i.test(tld)) {
    return { ok: false, reason: `Invalid top-level domain ".${tld}"` };
  }
  return { ok: true, local, domain, normalized: `${local}@${domain}` };
}

// ---------- 5. DNS ----------------------------------------------------------

function withTimeout(promise, ms, label) {
  let t;
  const timeout = new Promise((_, rej) => {
    t = setTimeout(() => rej(Object.assign(new Error(`${label} timed out`), { code: "ETIMEOUT" })), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(t));
}

async function resolveMailHosts(domain, opts) {
  try {
    const mx = await withTimeout(dns.resolveMx(domain), opts.dnsTimeoutMs, "MX lookup");
    const hosts = mx
      .filter((r) => r.exchange && r.exchange !== ".")
      .sort((a, b) => a.priority - b.priority)
      .map((r) => r.exchange.toLowerCase());
    if (hosts.length) return { ok: true, hosts, source: "mx" };
    // RFC 7505 "null MX" (a single "." record) = domain explicitly refuses mail.
    if (mx.length && mx.every((r) => r.exchange === "" || r.exchange === ".")) {
      return { ok: false, hosts: [], reason: "Domain publishes a null MX (does not accept mail)" };
    }
  } catch (e) {
    if (e.code === "ETIMEOUT") return { ok: false, hosts: [], reason: "DNS lookup timed out", transient: true };
    if (!["ENODATA", "ENOTFOUND", "ESERVFAIL", "ENOTIMP"].includes(e.code) && !/queryMx/.test(String(e.message))) {
      return { ok: false, hosts: [], reason: `DNS error (${e.code || e.message})`, transient: true };
    }
    if (e.code === "ENOTFOUND") return { ok: false, hosts: [], reason: "Domain does not exist" };
  }
  // No MX: RFC 5321 falls back to the A/AAAA record of the domain itself.
  try {
    const a = await withTimeout(dns.resolve4(domain), opts.dnsTimeoutMs, "A lookup").catch(() => []);
    const aaaa = a.length ? [] : await withTimeout(dns.resolve6(domain), opts.dnsTimeoutMs, "AAAA lookup").catch(() => []);
    if (a.length || aaaa.length) return { ok: true, hosts: [domain], source: "a" };
  } catch { /* fallthrough */ }
  return { ok: false, hosts: [], reason: "Domain has no mail servers (no MX or A record)" };
}

// ---------- 6. SMTP probe ---------------------------------------------------

class SmtpClient {
  constructor(host, opts) {
    this.host = host;
    this.opts = opts;
    this.buf = "";
    this.waiters = [];
    this.transcript = [];
    this.socket = null;
  }

  connect() {
    return new Promise((resolve, reject) => {
      const sock = net.createConnection({ host: this.host, port: this.opts.port });
      this.socket = sock;
      const onError = (err) => { this._failAll(err); reject(err); };
      sock.setTimeout(this.opts.connectTimeoutMs, () => onError(Object.assign(new Error("Connect timed out"), { code: "ETIMEOUT" })));
      sock.once("error", onError);
      sock.once("connect", () => {
        sock.setTimeout(this.opts.commandTimeoutMs, () => this._failAll(Object.assign(new Error("Command timed out"), { code: "ETIMEOUT" })));
        sock.on("data", (d) => this._onData(d.toString("latin1")));
        sock.on("close", () => this._failAll(Object.assign(new Error("Connection closed"), { code: "ECLOSED" })));
        resolve();
      });
    });
  }

  _onData(chunk) {
    this.buf += chunk;
    let idx;
    while ((idx = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, idx).replace(/\r$/, "");
      this.buf = this.buf.slice(idx + 1);
      this.transcript.push("S: " + line);
      const w = this.waiters[0];
      if (!w) continue;
      w.lines.push(line);
      // "250-foo" continues, "250 foo" (or bare "250") ends the reply.
      if (/^\d{3}(?: |$)/.test(line)) {
        this.waiters.shift();
        const code = parseInt(line.slice(0, 3), 10);
        w.resolve({ code, message: w.lines.map((l) => l.slice(4)).join("\n"), raw: w.lines });
      }
    }
  }

  _failAll(err) {
    const ws = this.waiters.splice(0);
    for (const w of ws) w.reject(err);
  }

  read() {
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject, lines: [] }));
  }

  send(cmd) {
    this.transcript.push("C: " + cmd);
    const p = this.read();
    this.socket.write(cmd + "\r\n");
    return p;
  }

  async end() {
    try { if (this.socket && !this.socket.destroyed) { this.socket.write("QUIT\r\n"); } } catch { /* ignore */ }
    try { this.socket?.destroy(); } catch { /* ignore */ }
  }
}

const NO_MAILBOX_RE = /user unknown|unknown user|does not exist|doesn't exist|no such (user|recipient|mailbox)|mailbox (not found|unavailable|does not exist)|recipient (rejected|not found|unknown)|invalid (recipient|mailbox|address)|address rejected|no mailbox|unrouteable|not exist|unknown recipient|user not found|bad destination|RecipientNotFound|NoSuchUser|5\.1\.1/i;
const BLOCKED_RE = /spamhaus|blacklist|blocklist|block list|listed|reputation|not permitted|denied|access denied|too many|rate limit|try again later|greylist|deferred|policy|refused|not authorized|unverified|PTR|reverse DNS|IP address/i;
const FULL_RE = /mailbox (is )?full|quota|over quota|exceeded storage|5\.2\.2/i;

function classifyRcpt(reply) {
  const { code, message } = reply;
  if (code >= 200 && code < 300) return { result: "accepted" };
  if (code === 552 || (code >= 500 && FULL_RE.test(message))) return { result: "full", detail: message };
  if (code >= 500) {
    if (NO_MAILBOX_RE.test(message) && !BLOCKED_RE.test(message)) return { result: "rejected", detail: message };
    if (BLOCKED_RE.test(message)) return { result: "blocked", detail: message };
    // Generic 550 with no recognisable wording is most often "no such user".
    if (code === 550 || code === 551 || code === 553) return { result: "rejected", detail: message };
    return { result: "blocked", detail: message };
  }
  // 4xx: greylisting / temporary – cannot conclude.
  return { result: "tempfail", detail: message };
}

/**
 * Probe one mail host. Returns { outcome, catchAll, host, detail, transcript }
 * outcome: accepted | rejected | full | blocked | tempfail | connect_failed
 */
async function probeHost(host, email, domain, opts, wantCatchAll) {
  const client = new SmtpClient(host, opts);
  const out = { host, transcript: client.transcript };
  try {
    await client.connect();
    const banner = await client.read();
    if (banner.code !== 220) {
      out.outcome = banner.code >= 500 ? "blocked" : "tempfail";
      out.detail = `Banner ${banner.code}: ${banner.message}`;
      return out;
    }
    let ehlo = await client.send(`EHLO ${opts.heloHost}`);
    if (ehlo.code !== 250) ehlo = await client.send(`HELO ${opts.heloHost}`);
    if (ehlo.code !== 250) {
      out.outcome = ehlo.code >= 500 ? "blocked" : "tempfail";
      out.detail = `EHLO ${ehlo.code}: ${ehlo.message}`;
      return out;
    }
    const from = opts.fromAddress || `verify@${opts.heloHost}`;
    const mf = await client.send(`MAIL FROM:<${from}>`);
    if (mf.code !== 250) {
      out.outcome = mf.code >= 500 ? "blocked" : "tempfail";
      out.detail = `MAIL FROM ${mf.code}: ${mf.message}`;
      return out;
    }
    const rcpt = await client.send(`RCPT TO:<${email}>`);
    const cls = classifyRcpt(rcpt);
    out.outcome = cls.result;
    out.detail = `RCPT ${rcpt.code}: ${rcpt.message}`;
    out.code = rcpt.code;

    if (wantCatchAll && cls.result === "accepted") {
      const rand = `${crypto.randomBytes(9).toString("hex")}-probe@${domain}`;
      try {
        const r2 = await client.send(`RCPT TO:<${rand}>`);
        out.catchAll = classifyRcpt(r2).result === "accepted";
      } catch { out.catchAll = null; }
    }
    return out;
  } catch (err) {
    out.outcome = "connect_failed";
    out.detail = `${err.code || "ERR"}: ${err.message}`;
    out.errorCode = err.code;
    return out;
  } finally {
    await client.end();
  }
}

async function probeSmtp(hosts, email, domain, opts, wantCatchAll) {
  const attempts = [];
  for (const host of hosts.slice(0, 3)) {
    const r = await probeHost(host, email, domain, opts, wantCatchAll);
    attempts.push(r);
    // Only move to the next MX if this one could not be reached at all.
    if (r.outcome !== "connect_failed") return { ...r, attempts };
  }
  const last = attempts[attempts.length - 1];
  return { ...last, attempts };
}

// ---------- orchestration ---------------------------------------------------

function createSession(userOpts = {}) {
  const opts = { ...DEFAULTS, ...userOpts };
  const dnsCache = new Map();      // domain -> resolveMailHosts result
  const catchAllCache = new Map(); // domain -> true | false | null

  async function lookupDomain(domain) {
    if (!dnsCache.has(domain)) dnsCache.set(domain, resolveMailHosts(domain, opts));
    return dnsCache.get(domain);
  }

  async function validateEmail(raw) {
    const started = Date.now();
    const result = {
      email: String(raw ?? "").trim(),
      normalized: null,
      status: "unknown",
      reason: "",
      syntax: false,
      domain: null,
      mx: null,          // true/false/null
      mxHosts: [],
      disposable: false,
      role: false,
      smtp: null,        // accepted | rejected | full | blocked | tempfail | connect_failed | skipped
      smtpDetail: "",
      catchAll: null,
      suggestion: null,
      elapsedMs: 0,
    };
    const done = () => { result.elapsedMs = Date.now() - started; return result; };

    const syn = checkSyntax(result.email);
    if (!syn.ok) {
      result.status = "invalid";
      result.reason = syn.reason;
      return done();
    }
    result.syntax = true;
    result.normalized = syn.normalized;
    result.domain = syn.domain;
    result.role = ROLE_LOCAL_PARTS.has(syn.local.toLowerCase());
    result.disposable = DISPOSABLE_DOMAINS.has(syn.domain);
    if (TYPO_MAP[syn.domain]) result.suggestion = `${syn.local}@${TYPO_MAP[syn.domain]}`;

    const dnsRes = await lookupDomain(syn.domain);
    result.mx = dnsRes.ok;
    result.mxHosts = dnsRes.hosts;
    if (!dnsRes.ok) {
      result.status = dnsRes.transient ? "unknown" : "invalid";
      result.reason = dnsRes.reason;
      return done();
    }

    if (!opts.smtp) {
      result.smtp = "skipped";
      if (result.disposable) { result.status = "risky"; result.reason = "Disposable email provider"; }
      else { result.status = "unknown"; result.reason = "Syntax and mail servers OK (mailbox not probed)"; }
      if (result.suggestion) result.reason += ` — did you mean ${result.suggestion}?`;
      return done();
    }

    const cached = catchAllCache.get(syn.domain);
    const wantCatchAll = opts.catchAll && cached === undefined;
    const probe = await probeSmtp(dnsRes.hosts, syn.normalized, syn.domain, opts, wantCatchAll);
    result.smtp = probe.outcome;
    result.smtpDetail = probe.detail || "";
    result.smtpHost = probe.host;
    if (wantCatchAll && probe.outcome === "accepted" && typeof probe.catchAll === "boolean") {
      catchAllCache.set(syn.domain, probe.catchAll);
    }
    result.catchAll = catchAllCache.get(syn.domain) ?? (probe.outcome === "accepted" ? probe.catchAll ?? null : null);

    switch (probe.outcome) {
      case "accepted":
        if (result.disposable) { result.status = "risky"; result.reason = "Mailbox exists but the provider is disposable"; }
        else if (result.catchAll) { result.status = "risky"; result.reason = "Domain accepts every address (catch-all) — mailbox cannot be confirmed"; }
        else { result.status = "valid"; result.reason = result.role ? "Mailbox exists (role account)" : "Mailbox exists"; }
        break;
      case "rejected":
        result.status = "invalid";
        result.reason = "Mail server says this mailbox does not exist";
        break;
      case "full":
        result.status = "risky";
        result.reason = "Mailbox exists but is full / over quota";
        break;
      case "blocked":
        result.status = "unknown";
        result.reason = "Mail server refused the probe (our IP/sender blocked) — existence unknown";
        break;
      case "tempfail":
        result.status = "unknown";
        result.reason = "Mail server answered with a temporary error (greylisting) — retry later";
        break;
      case "connect_failed":
      default:
        result.status = "unknown";
        result.reason = probe.errorCode === "ETIMEOUT" || probe.errorCode === "ECONNREFUSED" || probe.errorCode === "EHOSTUNREACH"
          ? "Could not reach the mail server on port 25 (your network may block outbound SMTP)"
          : `Could not reach the mail server (${probe.detail})`;
        break;
    }
    if (result.disposable && result.status !== "invalid") {
      result.status = "risky";
      if (!/disposable/i.test(result.reason)) result.reason = "Disposable email provider — " + result.reason;
    }
    if (result.suggestion) result.reason += ` — did you mean ${result.suggestion}?`;
    return done();
  }

  /**
   * Validate many addresses with bounded concurrency.
   * onProgress(result, index, total) is called as each finishes; order of
   * callbacks is completion order, the returned array keeps input order.
   */
  async function validateMany(emails, onProgress, shouldStop) {
    const list = Array.from(emails);
    const results = new Array(list.length);
    let next = 0;
    let finished = 0;
    const worker = async () => {
      while (next < list.length) {
        if (shouldStop && shouldStop()) return;
        const i = next++;
        results[i] = await validateEmail(list[i]);
        finished++;
        if (onProgress) onProgress(results[i], i, list.length, finished);
      }
    };
    const n = Math.max(1, Math.min(opts.concurrency, list.length));
    await Promise.all(Array.from({ length: n }, worker));
    return results;
  }

  return { validateEmail, validateMany, opts };
}

/** Quick test of whether outbound port 25 works from this machine. */
async function checkOutboundSmtp(timeoutMs = 6000) {
  const targets = ["gmail-smtp-in.l.google.com", "mx1.hotmail.com", "mx-eu.mail.am0.yahoodns.net"];
  for (const host of targets) {
    const ok = await new Promise((resolve) => {
      const s = net.createConnection({ host, port: 25 });
      const finish = (v) => { try { s.destroy(); } catch { /* ignore */ } resolve(v); };
      s.setTimeout(timeoutMs, () => finish(false));
      s.once("error", () => finish(false));
      s.once("data", () => finish(true));
      s.once("connect", () => setTimeout(() => finish(true), 1500));
    });
    if (ok) return { ok: true, host };
  }
  return { ok: false };
}

/** Pull addresses out of free text / CSV: dedupe, keep first-seen order. */
function extractEmails(text) {
  const seen = new Set();
  const out = [];
  const re = /[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
  for (const m of String(text || "").matchAll(re)) {
    const e = m[0].replace(/^[.]+|[.]+$/g, "");
    const key = e.toLowerCase();
    if (!seen.has(key)) { seen.add(key); out.push(e); }
  }
  return out;
}

function toCsv(results) {
  const esc = (v) => {
    const s = v == null ? "" : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const header = ["email", "status", "reason", "syntax", "mx", "mx_hosts", "smtp", "catch_all", "disposable", "role", "suggestion", "smtp_detail", "elapsed_ms"];
  const rows = results.map((r) => [
    r.email, r.status, r.reason, r.syntax, r.mx, (r.mxHosts || []).join(" "), r.smtp,
    r.catchAll, r.disposable, r.role, r.suggestion, r.smtpDetail, r.elapsedMs,
  ].map(esc).join(","));
  return [header.join(","), ...rows].join("\n") + "\n";
}

module.exports = {
  DEFAULTS, checkSyntax, resolveMailHosts, probeSmtp, classifyRcpt,
  createSession, checkOutboundSmtp, extractEmails, toCsv,
};
