# Email Validator (desktop)

A small Electron app that tells you whether an email address is **well-formed** and whether the **mailbox actually exists**. Works on one address at a time or on a pasted / imported list, and exports results to CSV.

No third-party validation API is used. Everything runs from your machine with Node built-ins:

| Check | How |
|---|---|
| Syntax | RFC 5321/5322-style rules: lengths, allowed characters, dot placement, domain labels, TLD |
| Typo hint | `gmial.com` → `gmail.com` and ~40 other common misspellings |
| Disposable | built-in list of throw-away providers (`src/main/disposableDomains.js`) |
| Role account | `info@`, `support@`, `noreply@` … flagged, not failed |
| Mail servers | DNS MX lookup, A/AAAA fallback, null-MX detection |
| Mailbox exists | SMTP handshake with the domain's MX: `EHLO` → `MAIL FROM` → `RCPT TO`, then `QUIT`. **No email is ever sent.** |
| Catch-all | a second `RCPT TO` with a random mailbox; if that is accepted too, the domain accepts anything (cached per domain) |

### Result statuses

- **valid** – syntax and DNS fine, server confirmed the exact mailbox, not a catch-all
- **invalid** – bad syntax, domain cannot receive mail, or the server said the mailbox does not exist
- **risky** – probably deliverable but unreliable: disposable provider, catch-all domain, mailbox full
- **unknown** – could not be proven either way: port 25 blocked on your network, greylisting, provider refused the probe

The header shows whether outbound port 25 is open from your network. Home ISPs and many offices block it; then only syntax + DNS results are conclusive and SMTP results come back `unknown`. Run it from a network/VPS that allows port 25 for full results.

## Run

```bash
npm install
npm start
```

## Build installers

```bash
npm run dist          # macOS .dmg + .zip → dist/
npm run dist:win      # Windows installer + portable (run on Windows or with wine)
npm run dist:linux    # AppImage + deb
```

The macOS build is unsigned: on first launch right-click → Open, or run `xattr -dr com.apple.quarantine "/Applications/Email Validator.app"`.

## Releasing

Installers are published as GitHub Release assets and the download page (`docs/`) is GitHub Pages on scuntore.com, linking to `releases/latest/download/<file>` so the links never change between versions.

```bash
npm version patch            # bumps package.json + creates tag vX.Y.Z
git push && git push --tags  # the release workflow builds Win/Mac/Linux and attaches them to the release
```

After the workflow finishes, edit the draft release on GitHub and publish it. Update the version shown in `docs/index.html` when it changes.

## Command line

The same engine without the window:

```bash
npm run check -- a@b.com c@d.org
npm run check -- --file contacts.csv --csv > results.csv
npm run check -- --network          # is port 25 open from here?
npm run check -- --no-smtp a@b.com  # syntax + DNS only
```

## Tests

```bash
npm test
```

Offline: syntax rules, reply classification, CSV, plus a full probe against a fake SMTP server on localhost.

## Speed on big lists

Addresses are grouped by domain and checked through one open SMTP connection per domain (up to 25 per connection, 2 connections per domain), and the app remembers what it learns about a domain — unreachable, blocked, or catch-all — so the rest of that domain's addresses are answered instantly. A 300-address mixed list takes ~12 s; 10,000 addresses take minutes rather than hours. The results table draws 400 rows at a time; use the filter or export to CSV for the rest.

## Networks that block DNS or port 25

Mail-server lookups try the system resolver first, then 1.1.1.1 / 8.8.8.8, then DNS-over-HTTPS (dns.google), and stick with the first one that answers — so a VPN or firewall that breaks the system resolver costs one timeout, not one per address. If outbound port 25 is blocked the app says so in its header, switches "Probe mailbox" off and still gives syntax, typo, disposable and MX results in seconds; tick it back on to force probing.

## Caveats

- Some big providers answer `250` for every address (Yahoo, many Office 365 tenants) — those show as **risky / catch-all**, not valid.
- Probing many addresses at one provider quickly can get your IP temporarily blocked; keep *Parallel* low (5 is the default) for large lists.
- Existence checks are a snapshot: a mailbox can be deleted after you check it.
