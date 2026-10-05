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
  connectTimeoutMs: 4000,
  commandTimeoutMs: 8000,
  dnsTimeoutMs: 4000,
  dnsSlowMs: 1500,         // a resolver slower than this twice in a row is demoted
  maxHostsPerDomain: 2,    // MX hosts to try before calling a domain unreachable
  sessionsPerDomain: 2,    // parallel SMTP connections to one domain (be polite)
  rcptPerSession: 25,      // addresses checked per connection before reconnecting
  heloHost: defaultHeloHost(),
  fromAddress: null,       // defaults to verify@<heloHost>
  port: 25,
  concurrency: 12,
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

const https = require("node:https");
const { Resolver } = require("node:dns").promises;

const DNS_SOFT_ERRORS = new Set(["ETIMEOUT", "ESERVFAIL", "EREFUSED", "ECONNREFUSED", "ECANCELLED", "ENOTINITIALIZED", "EBADRESP"]);

function dohQuery(name, type, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = https.get(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, { timeout: timeoutMs, headers: { accept: "application/dns-json" } }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (d) => { body += d; });
      res.on("end", () => {
        try {
          const j = JSON.parse(body);
          if (j.Status === 3) return reject(Object.assign(new Error("NXDOMAIN"), { code: "ENOTFOUND" }));
          if (j.Status !== 0) return reject(Object.assign(new Error(`DoH status ${j.Status}`), { code: "ESERVFAIL" }));
          const typeNum = { MX: 15, A: 1, AAAA: 28 }[type];
          const ans = (j.Answer || []).filter((a) => a.type === typeNum);
          if (!ans.length) return reject(Object.assign(new Error("no data"), { code: "ENODATA" }));
          if (type === "MX") resolve(ans.map((a) => { const [pri, ex] = a.data.split(/\s+/); return { priority: parseInt(pri, 10), exchange: (ex || "").replace(/\.$/, "") }; }));
          else resolve(ans.map((a) => a.data));
        } catch (e) { reject(Object.assign(e, { code: "EBADRESP" })); }
      });
    });
    req.on("timeout", () => { req.destroy(Object.assign(new Error("DoH timed out"), { code: "ETIMEOUT" })); });
    req.on("error", (e) => reject(Object.assign(e, { code: e.code && DNS_SOFT_ERRORS.has(e.code) ? e.code : "ETIMEOUT" })));
  });
}

/**
 * Three ways to ask DNS, tried in order and remembered per session:
 *   system  — the machine's own resolver (c-ares). On Windows with a VPN or a strict
 *             firewall this can time out on every query even though the browser works.
 *   public  — 1.1.1.1 / 8.8.8.8 over UDP.
 *   doh     — DNS-over-HTTPS (dns.google), which works wherever HTTPS works.
 */
function makeResolverTiers(opts) {
  const t = opts.dnsTimeoutMs;
  const pub = new Resolver({ timeout: t, tries: 1 });
  pub.setServers(["1.1.1.1", "8.8.8.8"]);
  const sys = (fn) => (name) => withTimeout(dns[fn](name), t, "DNS");
  const pubq = (fn) => (name) => withTimeout(pub[fn](name), t, "DNS");
  return [
    { name: "system", resolveMx: sys("resolveMx"), resolve4: sys("resolve4"), resolve6: sys("resolve6") },
    { name: "public", resolveMx: pubq("resolveMx"), resolve4: pubq("resolve4"), resolve6: pubq("resolve6") },
    { name: "doh", resolveMx: (n) => dohQuery(n, "MX", t), resolve4: (n) => dohQuery(n, "A", t), resolve6: (n) => dohQuery(n, "AAAA", t) },
  ];
}

// state = { tiers, tier } shared by a session so a working resolver sticks.
async function resolveMailHosts(domain, opts, state) {
  if (!state) state = { tiers: makeResolverTiers(opts), tier: 0 };
  if (!state.tiers) state.tiers = makeResolverTiers(opts);
  let lastSoft = null;
  for (let i = state.tier; i < state.tiers.length; i++) {
    const r = state.tiers[i];
    try {
      const t0 = Date.now();
      const out = await resolveMailHostsWith(r, domain, opts);
      const took = Date.now() - t0;
      state.tier = i;              // this resolver works: keep using it
      // ...unless it is crawling (e.g. a dead first DNS server on the adapter makes every
      // query wait for a retry): demote it after two slow answers so the rest go elsewhere.
      if (took > opts.dnsSlowMs && i + 1 < state.tiers.length) {
        state.slow = (state.slow || 0) + 1;
        if (state.slow >= 2) { state.tier = i + 1; state.slow = 0; }
      } else {
        state.slow = 0;
      }
      out.resolver = r.name;
      out.dnsMs = took;
      return out;
    } catch (e) {
      if (e && e.soft) { lastSoft = e; continue; }   // resolver broken: try the next tier
      throw e;
    }
  }
  return { ok: false, hosts: [], reason: `DNS lookup failed (${lastSoft?.code || "no resolver answered"})`, transient: true };
}

async function resolveMailHostsWith(r, domain, opts) {
  const soft = (e) => Object.assign(e, { soft: true });
  try {
    const mx = await r.resolveMx(domain);
    const hosts = mx
      .filter((x) => x.exchange && x.exchange !== ".")
      .sort((a, b) => a.priority - b.priority)
      .map((x) => x.exchange.toLowerCase());
    if (hosts.length) return { ok: true, hosts, source: "mx" };
    // RFC 7505 "null MX" (a single "." record) = domain explicitly refuses mail.
    if (mx.length) return { ok: false, hosts: [], reason: "Domain publishes a null MX (does not accept mail)" };
  } catch (e) {
    if (e.code === "ENOTFOUND") return { ok: false, hosts: [], reason: "Domain does not exist" };
    if (e.code !== "ENODATA") throw soft(e);
  }
  // No MX: RFC 5321 falls back to the A/AAAA record of the domain itself.
  try {
    const a = await r.resolve4(domain).catch((e) => { if (e.code === "ENODATA" || e.code === "ENOTFOUND") return []; throw e; });
    const aaaa = a.length ? [] : await r.resolve6(domain).catch((e) => { if (e.code === "ENODATA" || e.code === "ENOTFOUND") return []; throw e; });
    if (a.length || aaaa.length) return { ok: true, hosts: [domain], source: "a" };
  } catch (e) {
    throw soft(e);
  }
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
 * One prober per domain for the life of a session. It keeps an SMTP connection
 * open and checks many addresses through it (one RCPT TO each), instead of a
 * full connect/EHLO/MAIL FROM handshake per address. It also remembers what it
 * learned about the domain so later addresses cost nothing:
 *   - unreachable (no MX answered)            → every address: connect_failed
 *   - blocked (server refuses our probes)     → every address: blocked
 *   - catch-all (random mailbox accepted)     → every address: accepted + catchAll
 */
class DomainProber {
  constructor(domain, hosts, opts) {
    this.domain = domain;
    this.hosts = hosts.slice(0, opts.maxHostsPerDomain);
    this.opts = opts;
    this.queue = [];
    this.active = 0;
    this.catchAll = opts.catchAll ? undefined : null;
    this.unreachable = null;
    this.blocked = null;
    this.drops = 0;
    this.host = null;
  }

  check(email) {
    return new Promise((resolve) => {
      this.queue.push({ email, resolve });
      this._pump();
    });
  }

  _pump() {
    // Open another connection only when more addresses are waiting than sessions already serving them.
    while (this.active < this.opts.sessionsPerDomain && this.queue.length > this.active) {
      this.active++;
      this._session().catch(() => {}).finally(() => { this.active--; this._pump(); });
    }
  }

  _drainFast() {
    if (this.unreachable) return this._drain({ outcome: "connect_failed", detail: this.unreachable, errorCode: this.unreachableCode, host: this.host });
    if (this.blocked) return this._drain({ outcome: "blocked", detail: this.blocked, host: this.host });
    if (this.catchAll === true) return this._drain({ outcome: "accepted", detail: "Domain is catch-all (not probed)", host: this.host, catchAll: true });
    return false;
  }

  _drain(result) {
    const jobs = this.queue.splice(0);
    for (const j of jobs) j.resolve({ ...result });
    return true;
  }

  // Try the top MX hosts at the same time; the first completed handshake wins and the
  // others are closed. A dead primary MX then costs nothing extra.
  async _open() {
    const attempts = this.hosts.map((host) => this._openOne(host));
    const errors = [];
    let winner = null;
    await new Promise((done) => {
      let pending = attempts.length;
      attempts.forEach((p) => p.then(
        (res) => { if (winner) { res.client.end(); } else { winner = res; done(); } if (--pending === 0) done(); },
        (err) => { errors.push(err); if (--pending === 0) done(); },
      ));
    });
    if (winner) { this.host = winner.host; return winner.client; }
    const blocked = errors.find((e) => e.kind === "blocked");
    const temp = errors.find((e) => e.kind === "tempfail");
    if (blocked) this.blocked = blocked.detail;
    else if (temp) this._drain({ outcome: "tempfail", detail: temp.detail, host: this.hosts[0] });
    else { const e = errors[0]; this.unreachable = e?.detail || "no hosts"; this.unreachableCode = e?.code; }
    return null;
  }

  async _openOne(host) {
    const client = new SmtpClient(host, this.opts);
    const fail = async (kind, detail, code) => { await client.end(); throw { kind, detail, code }; };
    try {
      await client.connect();
      const banner = await client.read();
      if (banner.code !== 220) return fail(banner.code >= 500 ? "blocked" : "tempfail", `Banner ${banner.code}: ${banner.message}`);
      let ehlo = await client.send(`EHLO ${this.opts.heloHost}`);
      if (ehlo.code !== 250) ehlo = await client.send(`HELO ${this.opts.heloHost}`);
      if (ehlo.code !== 250) return fail(ehlo.code >= 500 ? "blocked" : "tempfail", `EHLO ${ehlo.code}: ${ehlo.message}`);
      const from = this.opts.fromAddress || `verify@${this.opts.heloHost}`;
      const mf = await client.send(`MAIL FROM:<${from}>`);
      if (mf.code !== 250) return fail(mf.code >= 500 ? "blocked" : "tempfail", `MAIL FROM ${mf.code}: ${mf.message}`);
      return { client, host };
    } catch (err) {
      if (err && err.kind) throw err;
      await client.end();
      throw { kind: "connect", detail: `${err.code || "ERR"}: ${err.message}`, code: err.code };
    }
  }

  async _session() {
    if (this._drainFast()) return;
    const client = await this._open();
    if (!client) { this._drainFast(); return; }
    let n = 0;
    try {
      while (this.queue.length && n < this.opts.rcptPerSession) {
        if (this._drainFast()) return;
        const job = this.queue.shift();
        n++;
        let rcpt;
        try {
          rcpt = await client.send(`RCPT TO:<${job.email}>`);
        } catch (err) {
          // Connection dropped mid-session: put the job back and start a fresh session,
          // unless the server keeps dropping us.
          this.queue.unshift(job);
          if (++this.drops >= 3) { this.unreachable = `${err.code || "ERR"}: ${err.message} (repeatedly dropped)`; this.unreachableCode = err.code; }
          return;
        }
        if (n > 1 && (rcpt.code === 452 || (rcpt.code >= 400 && /too many recipients/i.test(rcpt.message)))) {
          this.queue.unshift(job);   // per-session recipient limit reached: continue on a new connection
          return;
        }
        const cls = classifyRcpt(rcpt);
        const out = { outcome: cls.result, detail: `RCPT ${rcpt.code}: ${rcpt.message}`, code: rcpt.code, host: this.host, catchAll: this.catchAll ?? null };
        if (cls.result === "accepted" && this.catchAll === undefined) {
          const rand = `${crypto.randomBytes(9).toString("hex")}-probe@${this.domain}`;
          try {
            const r2 = await client.send(`RCPT TO:<${rand}>`);
            this.catchAll = classifyRcpt(r2).result === "accepted";
          } catch { this.catchAll = null; }
          out.catchAll = this.catchAll;
        }
        if (cls.result === "blocked") this.blocked = cls.detail || out.detail;
        job.resolve(out);
        if (this.blocked) return;
      }
    } finally {
      await client.end();
    }
  }
}

/** Single-shot probe (used by tests and quick checks). */
function probeSmtp(hosts, email, domain, opts, wantCatchAll = true) {
  const full = { ...DEFAULTS, ...opts, catchAll: wantCatchAll };
  return new DomainProber(domain, hosts, full).check(email);
}

// ---------- orchestration ---------------------------------------------------

function createSession(userOpts = {}) {
  const opts = { ...DEFAULTS, ...userOpts };
  const dnsCache = new Map();    // domain -> Promise<resolveMailHosts result>
  const probers = new Map();     // domain -> DomainProber
  const dnsState = { tiers: opts.resolverTiers || makeResolverTiers(opts), tier: 0 };

  function lookupDomain(domain) {
    if (!dnsCache.has(domain)) dnsCache.set(domain, resolveMailHosts(domain, opts, dnsState));
    return dnsCache.get(domain);
  }

  function proberFor(domain, hosts) {
    let p = probers.get(domain);
    if (!p) { p = new DomainProber(domain, hosts, opts); probers.set(domain, p); }
    return p;
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
    const hint = () => { if (result.suggestion) result.reason += ` — did you mean ${result.suggestion}?`; };

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
    result.resolver = dnsRes.resolver || null;
    if (!dnsRes.ok) {
      result.status = dnsRes.transient ? "unknown" : "invalid";
      result.reason = dnsRes.reason;
      hint();
      return done();
    }

    // A disposable mailbox is "risky" whatever the server says — don't spend a probe on it.
    if (result.disposable) {
      result.smtp = "skipped";
      result.status = "risky";
      result.reason = "Disposable email provider";
      hint();
      return done();
    }

    if (!opts.smtp) {
      result.smtp = "skipped";
      result.status = "unknown";
      result.reason = "Syntax and mail servers OK (mailbox not probed)";
      hint();
      return done();
    }

    const probe = await proberFor(syn.domain, dnsRes.hosts).check(syn.normalized);
    result.smtp = probe.outcome;
    result.smtpDetail = probe.detail || "";
    result.smtpHost = probe.host;
    result.catchAll = probe.catchAll ?? null;

    switch (probe.outcome) {
      case "accepted":
        if (result.catchAll) { result.status = "risky"; result.reason = "Domain accepts every address (catch-all) — mailbox cannot be confirmed"; }
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
        result.reason = ["ETIMEOUT", "ECONNREFUSED", "EHOSTUNREACH", "ENETUNREACH"].includes(probe.errorCode)
          ? "Could not reach the mail server on port 25 (your network may block outbound SMTP)"
          : `Could not reach the mail server (${probe.detail})`;
        break;
    }
    hint();
    return done();
  }

  /**
   * Validate many addresses with bounded concurrency. Work is interleaved by
   * domain so that at any moment the in-flight set spans many mail servers
   * instead of queueing behind one; results are returned in input order.
   * onProgress(result, index, total, finished) fires in completion order.
   */
  async function validateMany(emails, onProgress, shouldStop) {
    const list = Array.from(emails);
    const byDomain = new Map();
    list.forEach((e, i) => {
      const syn = checkSyntax(e);
      const key = syn.ok ? syn.domain : "";
      if (!byDomain.has(key)) byDomain.set(key, []);
      byDomain.get(key).push(i);
    });
    const order = [];
    const lanes = Array.from(byDomain.values());
    for (let more = true; more;) {
      more = false;
      for (const lane of lanes) if (lane.length) { order.push(lane.shift()); more = true; }
    }

    const results = new Array(list.length);
    let next = 0;
    let finished = 0;
    const worker = async () => {
      while (next < order.length) {
        if (shouldStop && shouldStop()) return;
        const i = order[next++];
        results[i] = await validateEmail(list[i]);
        finished++;
        if (onProgress) onProgress(results[i], i, list.length, finished);
      }
    };
    const n = Math.max(1, Math.min(opts.concurrency, list.length));
    await Promise.all(Array.from({ length: n }, worker));
    return results;
  }

  return { validateEmail, validateMany, opts, dnsState };
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
  DEFAULTS, checkSyntax, resolveMailHosts, makeResolverTiers, probeSmtp, classifyRcpt, DomainProber,
  createSession, checkOutboundSmtp, extractEmails, toCsv,
};
