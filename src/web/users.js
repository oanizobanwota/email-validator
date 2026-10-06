#!/usr/bin/env node
"use strict";

/**
 * User accounts for the web version. Stored in users.json (path from USERS_FILE, default
 * <app folder>/users.json) as scrypt hashes — never plain passwords.
 *
 *   node src/web/users.js add <username> <password>
 *   node src/web/users.js remove <username>
 *   node src/web/users.js list
 */

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

// Anchored to the app folder (not the working directory) so services behave the same wherever they start.
const APP_ROOT = path.join(__dirname, "..", "..");
const USERS_FILE = process.env.USERS_FILE || path.join(APP_ROOT, "users.json");

function load() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, "utf8")); } catch { return { users: {} }; }
}
function save(db) { fs.writeFileSync(USERS_FILE, JSON.stringify(db, null, 2) + "\n", { mode: 0o600 }); }

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(String(password), salt, 64).toString("hex");
  return `scrypt$${salt}$${hash}`;
}
function checkPassword(stored, password) {
  const [algo, salt, hash] = String(stored || "").split("$");
  if (algo !== "scrypt" || !salt || !hash) return false;
  const calc = crypto.scryptSync(String(password), salt, 64);
  const want = Buffer.from(hash, "hex");
  return calc.length === want.length && crypto.timingSafeEqual(calc, want);
}

/** Resolve a login against users.json, then WEB_USERS ("a:pw;b:pw"), then legacy WEB_PASSWORD (user "admin"). */
function authenticate(username, password) {
  const u = String(username || "").trim().toLowerCase();
  if (!u || !password) return false;
  const db = load();
  const rec = db.users && db.users[u];
  if (rec && checkPassword(rec.hash, password)) return true;
  for (const pair of String(process.env.WEB_USERS || "").split(";")) {
    const i = pair.indexOf(":");
    if (i > 0 && pair.slice(0, i).trim().toLowerCase() === u && pair.slice(i + 1) === password) return true;
  }
  if (process.env.WEB_PASSWORD && u === "admin" && password === process.env.WEB_PASSWORD) return true;
  return false;
}
function hasAnyUser() {
  const db = load();
  return (db.users && Object.keys(db.users).length > 0) || !!process.env.WEB_USERS || !!process.env.WEB_PASSWORD;
}

module.exports = { authenticate, hasAnyUser, USERS_FILE };

if (require.main === module) {
  const [cmd, name, password] = process.argv.slice(2);
  const db = load(); db.users = db.users || {};
  if (cmd === "add" && name && password) {
    if (password.length < 8) { console.error("Use a password of at least 8 characters."); process.exit(2); }
    db.users[name.toLowerCase()] = { hash: hashPassword(password), createdAt: new Date().toISOString() };
    save(db); console.log(`Saved user "${name.toLowerCase()}" in ${USERS_FILE}. Restart the service to apply.`);
  } else if (cmd === "remove" && name) {
    delete db.users[name.toLowerCase()]; save(db); console.log(`Removed "${name.toLowerCase()}".`);
  } else if (cmd === "list") {
    console.log(Object.keys(db.users).join("\n") || "(no users in users.json)");
  } else {
    console.log("usage: users.js add <username> <password> | remove <username> | list"); process.exit(2);
  }
}
