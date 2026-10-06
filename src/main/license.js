"use strict";

// Offline license verification for the desktop app (Ed25519, public key embedded).
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

let PUBLIC_KEY_PEM = null;
try { PUBLIC_KEY_PEM = require("./licensePublicKey"); } catch { PUBLIC_KEY_PEM = null; }

function verifyLicenseKey(key) {
  const k = String(key || "").trim();
  if (!PUBLIC_KEY_PEM) return { valid: false, reason: "This build has no license public key" };
  const m = k.match(/^EV1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/);
  if (!m) return { valid: false, reason: "That does not look like a license key" };
  let payload;
  try {
    const data = Buffer.from(m[1], "base64url");
    const sig = Buffer.from(m[2], "base64url");
    const ok = crypto.verify(null, data, crypto.createPublicKey(PUBLIC_KEY_PEM), sig);
    if (!ok) return { valid: false, reason: "Invalid license key" };
    payload = JSON.parse(data.toString("utf8"));
  } catch {
    return { valid: false, reason: "Invalid license key" };
  }
  if (payload.expires && new Date(payload.expires + "T23:59:59Z").getTime() < Date.now()) {
    return { valid: false, reason: `This license expired on ${payload.expires}`, license: payload };
  }
  return { valid: true, license: payload };
}

function licenseFile(userDataDir) { return path.join(userDataDir, "license.json"); }

function loadLicense(userDataDir) {
  try {
    const { key } = JSON.parse(fs.readFileSync(licenseFile(userDataDir), "utf8"));
    const r = verifyLicenseKey(key);
    return { ...r, key: r.valid ? key : undefined };
  } catch {
    return { valid: false, reason: "No license key entered yet" };
  }
}

function saveLicense(userDataDir, key) {
  const r = verifyLicenseKey(key);
  if (!r.valid) return r;
  fs.mkdirSync(userDataDir, { recursive: true });
  fs.writeFileSync(licenseFile(userDataDir), JSON.stringify({ key: String(key).trim(), activatedAt: new Date().toISOString() }));
  return r;
}

function removeLicense(userDataDir) {
  try { fs.unlinkSync(licenseFile(userDataDir)); } catch { /* ignore */ }
}

module.exports = { verifyLicenseKey, loadLicense, saveLicense, removeLicense };
