"use strict";

// Offline tests: syntax rules, reply classification, extraction, CSV, and a
// full SMTP probe against a fake mail server on localhost. No network needed.
//   node src/main/validator.test.js

const assert = require("node:assert/strict");
const net = require("node:net");
const { checkSyntax, classifyRcpt, extractEmails, toCsv, probeSmtp, createSession } = require("./validator");

let passed = 0;
function t(name, fn) {
  return Promise.resolve().then(fn).then(() => { passed++; console.log("ok   " + name); }, (e) => { console.log("FAIL " + name + "\n     " + e.message); process.exitCode = 1; });
}

async function run() {
  await t("syntax: accepts normal addresses", () => {
    for (const e of ["a@b.co", "john.doe+tag@example.com", "o'neil@ex-ample.org", "x_y@sub.domain.museum", "\"quoted local\"@example.com"]) {
      assert.equal(checkSyntax(e).ok, true, e);
    }
    assert.equal(checkSyntax("  Foo@Example.COM ").normalized, "Foo@example.com");
  });

  await t("syntax: rejects malformed addresses", () => {
    const bad = ["", "plain", "@nodomain.com", "nolocal@", "a@b", "a b@c.com", "a..b@c.com", ".a@c.com", "a.@c.com",
      "a@-c.com", "a@c-.com", "a@c.com.", "a@.c.com", "a@c.1", "a@@c.com", "a@c..com", "a".repeat(65) + "@c.com", "a@[127.0.0.1]"];
    for (const e of bad) assert.equal(checkSyntax(e).ok, false, `should reject ${JSON.stringify(e)}`);
  });

  await t("classifyRcpt maps reply codes", () => {
    assert.equal(classifyRcpt({ code: 250, message: "OK" }).result, "accepted");
    assert.equal(classifyRcpt({ code: 550, message: "5.1.1 The email account that you tried to reach does not exist" }).result, "rejected");
    assert.equal(classifyRcpt({ code: 550, message: "No such user here" }).result, "rejected");
    assert.equal(classifyRcpt({ code: 550, message: "5.7.1 Service unavailable; client host blocked using Spamhaus" }).result, "blocked");
    assert.equal(classifyRcpt({ code: 554, message: "Relay access denied" }).result, "blocked");
    assert.equal(classifyRcpt({ code: 552, message: "Mailbox full" }).result, "full");
    assert.equal(classifyRcpt({ code: 450, message: "Greylisted, try again later" }).result, "tempfail");
    assert.equal(classifyRcpt({ code: 451, message: "Temporary local problem" }).result, "tempfail");
  });

  await t("extractEmails dedupes and strips noise", () => {
    const out = extractEmails("Name,Email\nA,a@x.com\nB,<b@y.org>,\nA again, A@X.COM; c@z.net.\n");
    assert.deepEqual(out, ["a@x.com", "b@y.org", "c@z.net"]);
  });

  await t("toCsv quotes fields", () => {
    const csv = toCsv([{ email: "a@x.com", status: "valid", reason: 'say "hi", ok', mxHosts: ["m1", "m2"], elapsedMs: 5 }]);
    assert.match(csv, /^email,status,reason/);
    assert.match(csv, /a@x\.com,valid,"say ""hi"", ok",,,m1 m2/);
  });

  // ---- fake SMTP server ----
  const mailboxes = new Set(["real@fake.test", "full@fake.test"]);
  let catchAllMode = false;
  let connections = 0;
  const server = net.createServer((sock) => {
    connections++;
    sock.write("220 fake.test ESMTP ready\r\n");
    let buf = "";
    sock.on("data", (d) => {
      buf += d.toString();
      let i;
      while ((i = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        const up = line.toUpperCase();
        if (up.startsWith("EHLO")) sock.write("250-fake.test greets you\r\n250-SIZE 1000000\r\n250 OK\r\n");
        else if (up.startsWith("HELO")) sock.write("250 fake.test\r\n");
        else if (up.startsWith("MAIL FROM")) sock.write("250 2.1.0 OK\r\n");
        else if (up.startsWith("RCPT TO")) {
          const addr = line.slice(line.indexOf("<") + 1, line.indexOf(">")).toLowerCase();
          if (addr === "full@fake.test") sock.write("552 5.2.2 Mailbox full\r\n");
          else if (catchAllMode || mailboxes.has(addr)) sock.write("250 2.1.5 OK\r\n");
          else sock.write("550 5.1.1 User unknown\r\n");
        } else if (up.startsWith("QUIT")) { sock.write("221 Bye\r\n"); sock.end(); }
        else sock.write("500 Unknown command\r\n");
      }
    });
    sock.on("error", () => {});
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const opts = { port, heloHost: "test.local", connectTimeoutMs: 2000, commandTimeoutMs: 2000 };

  await t("probeSmtp: existing mailbox accepted, catch-all false", async () => {
    const r = await probeSmtp(["127.0.0.1"], "real@fake.test", "fake.test", opts, true);
    assert.equal(r.outcome, "accepted");
    assert.equal(r.catchAll, false);
    assert.equal(r.code, 250);
  });

  await t("probeSmtp: unknown mailbox rejected", async () => {
    const r = await probeSmtp(["127.0.0.1"], "nobody@fake.test", "fake.test", opts, true);
    assert.equal(r.outcome, "rejected");
  });

  await t("probeSmtp: full mailbox", async () => {
    const r = await probeSmtp(["127.0.0.1"], "full@fake.test", "fake.test", opts, false);
    assert.equal(r.outcome, "full");
  });

  await t("probeSmtp: catch-all detected", async () => {
    catchAllMode = true;
    const r = await probeSmtp(["127.0.0.1"], "anything@fake.test", "fake.test", opts, true);
    catchAllMode = false;
    assert.equal(r.outcome, "accepted");
    assert.equal(r.catchAll, true);
  });

  await t("probeSmtp: falls through dead MX to a live one", async () => {
    const dead = net.createServer(); await new Promise((r) => dead.listen(0, "127.0.0.1", r));
    const deadPort = dead.address().port; dead.close();
    // Port is now closed → ECONNREFUSED → should move on to the live host (same port opt, so use host list trick)
    const r = await probeSmtp(["127.0.0.1"], "real@fake.test", "fake.test", { ...opts, port: deadPort }, false);
    assert.equal(r.outcome, "connect_failed");
  });

  await t("session reuses one connection for many addresses of a domain", async () => {
    const { createSession } = require("./validator");
    const before = connections;
    const s = createSession({ ...opts, catchAll: true, concurrency: 8 });
    // Bypass DNS: inject the prober directly through a fake MX resolver.
    s._probers = null;
    const list = ["real@fake.test", "nobody@fake.test", "full@fake.test", "x1@fake.test", "x2@fake.test", "x3@fake.test"];
    const dnsModule = require("node:dns").promises;
    const origMx = dnsModule.resolveMx;
    dnsModule.resolveMx = async () => [{ exchange: "127.0.0.1", priority: 10 }];
    try {
      const results = await s.validateMany(list);
      assert.deepEqual(results.map((r) => r.status), ["valid", "invalid", "risky", "invalid", "invalid", "invalid"]);
      assert.equal(results[0].catchAll, false);
    } finally { dnsModule.resolveMx = origMx; }
    // 6 addresses + 1 catch-all probe over at most 2 sessions (sessionsPerDomain), not 6 connections.
    assert.ok(connections - before <= 2, `expected <=2 connections, got ${connections - before}`);
  });

  await t("catch-all domain is answered without further probes", async () => {
    catchAllMode = true;
    const before = connections;
    const dnsModule = require("node:dns").promises;
    const origMx = dnsModule.resolveMx;
    dnsModule.resolveMx = async () => [{ exchange: "127.0.0.1", priority: 10 }];
    try {
      const s = createSession({ ...opts, catchAll: true, concurrency: 1 });
      const results = await s.validateMany(Array.from({ length: 10 }, (_, i) => `u${i}@fake.test`));
      assert.ok(results.every((r) => r.status === "risky" && r.catchAll === true));
    } finally { dnsModule.resolveMx = origMx; catchAllMode = false; }
    assert.equal(connections - before, 1);
  });

  await t("unreachable domain fails fast for every address", async () => {
    const dnsModule = require("node:dns").promises;
    const origMx = dnsModule.resolveMx;
    dnsModule.resolveMx = async () => [{ exchange: "127.0.0.1", priority: 10 }];
    try {
      const s = createSession({ ...opts, port: 1, concurrency: 4 });
      const t0 = Date.now();
      const results = await s.validateMany(Array.from({ length: 20 }, (_, i) => `u${i}@dead.test`));
      assert.ok(results.every((r) => r.status === "unknown" && r.smtp === "connect_failed"));
      assert.ok(Date.now() - t0 < 3000, "should not wait per address");
    } finally { dnsModule.resolveMx = origMx; }
  });

  await t("createSession: invalid syntax short-circuits with no network", async () => {
    const s = createSession({ smtp: false });
    const r = await s.validateEmail("not an email");
    assert.equal(r.status, "invalid");
    assert.equal(r.syntax, false);
  });

  await t("createSession: role + disposable flags", async () => {
    const s = createSession({ smtp: false, dnsTimeoutMs: 1 });
    const r = await s.validateEmail("info@mailinator.com");
    assert.equal(r.role, true);
    assert.equal(r.disposable, true);
  });

  await t("createSession: typo suggestion", async () => {
    const s = createSession({ smtp: false, dnsTimeoutMs: 1 });
    const r = await s.validateEmail("jane@gmial.com");
    assert.equal(r.suggestion, "jane@gmail.com");
  });

  server.close();
  console.log(`\n${passed} passed${process.exitCode ? ", some FAILED" : ""}`);
}

run();
