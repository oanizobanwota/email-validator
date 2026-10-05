#!/usr/bin/env node
"use strict";

// Command-line companion: `npm run check -- a@b.com c@d.org` or `--file list.txt`.
// Same engine as the desktop app; handy for scripts and quick checks.

const fs = require("node:fs");
const { createSession, extractEmails, toCsv, checkOutboundSmtp } = require("./validator");

async function main() {
  const args = process.argv.slice(2);
  const opts = {};
  const emails = [];
  let csv = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--file" || a === "-f") emails.push(...extractEmails(fs.readFileSync(args[++i], "utf8")));
    else if (a === "--no-smtp") opts.smtp = false;
    else if (a === "--no-catchall") opts.catchAll = false;
    else if (a === "--csv") csv = true;
    else if (a === "--concurrency" || a === "-c") opts.concurrency = parseInt(args[++i], 10);
    else if (a === "--helo") opts.heloHost = args[++i];
    else if (a === "--from") opts.fromAddress = args[++i];
    else if (a === "--network") {
      const r = await checkOutboundSmtp();
      console.log(r.ok ? `Outbound SMTP (port 25) works via ${r.host}` : "Outbound SMTP (port 25) is blocked on this network");
      return;
    } else if (a === "--help" || a === "-h") {
      console.log("usage: check [--file list.txt] [--no-smtp] [--no-catchall] [--csv] [-c N] [--helo host] [--from addr] [--network] email...");
      return;
    } else emails.push(a);
  }
  if (!emails.length) { console.error("No emails given. --help for usage."); process.exit(2); }

  const session = createSession(opts);
  const results = await session.validateMany(emails, csv ? null : (r) => {
    const flags = [r.disposable && "disposable", r.role && "role", r.catchAll && "catch-all"].filter(Boolean).join(",");
    console.log(`${r.status.padEnd(8)} ${r.email.padEnd(40)} ${r.reason}${flags ? `  [${flags}]` : ""}  (${r.elapsedMs} ms)`);
  });
  if (csv) process.stdout.write(toCsv(results));
}

main().catch((e) => { console.error(e); process.exit(1); });
