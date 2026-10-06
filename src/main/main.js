"use strict";

const { app, BrowserWindow, ipcMain, dialog, shell } = require("electron");
const path = require("node:path");
const fs = require("node:fs/promises");
const { createSession, checkOutboundSmtp, extractEmails, toCsv, DEFAULTS } = require("./validator");
const license = require("./license");

// No GPU acceleration: over Remote Desktop or in a VM there is no GPU, and Chromium's
// software fallback repaints burn the CPU and stall the whole RDP session.
app.disableHardwareAcceleration();
// Windows occlusion tracking misjudges Remote Desktop / VM windows and throttles or blanks
// them; it is a known Chromium-on-RDP problem.
app.commandLine.appendSwitch("disable-features", "CalculateNativeWinOcclusion");

let win = null;
let activeRun = null; // { id, stop: boolean }

// One running copy at a time: a second launch focuses the existing window instead
// of starting another process (a stray process blocks the Windows installer/uninstaller).
if (!app.requestSingleInstanceLock()) {
  app.exit(0);
} else {
  app.on("second-instance", () => {
    if (win) { if (win.isMinimized()) win.restore(); win.focus(); }
  });
}

function createWindow() {
  win = new BrowserWindow({
    width: 1100,
    height: 760,
    minWidth: 820,
    minHeight: 560,
    title: "Email Validator",
    backgroundColor: "#0f1115",
    show: false, // shown once the page has rendered, so startup never flashes a blank window
    titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "default",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.once("ready-to-show", () => win.show());
  win.loadFile(path.join(__dirname, "..", "renderer", "index.html"));
  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: "deny" }; });
  // If the page ever hangs, closing the window must still end the process.
  win.on("unresponsive", () => { if (closing) win.destroy(); });
  win.on("close", () => { closing = true; if (activeRun) activeRun.stop = true; });
  win.on("closed", () => { win = null; });
}
let closing = false;

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on("window-all-closed", () => {
  if (process.platform === "darwin") return;
  app.quit();
  // Belt and braces: if quit is held up by anything, hard-exit shortly after.
  setTimeout(() => app.exit(0), 2000).unref();
});
app.on("before-quit", () => { if (activeRun) activeRun.stop = true; });

// ---------- IPC ----------

// ----- license gate (desktop only) -----
const userData = () => app.getPath("userData");
function requireLicense() {
  const st = license.loadLicense(userData());
  if (!st.valid) throw new Error("LICENSE_REQUIRED");
}
ipcMain.handle("license-status", () => { const st = license.loadLicense(userData()); return { valid: st.valid, reason: st.reason, license: st.license }; });
ipcMain.handle("license-activate", (_evt, key) => { const r = license.saveLicense(userData(), key); return { valid: r.valid, reason: r.reason, license: r.license }; });
ipcMain.handle("license-remove", () => { license.removeLicense(userData()); return true; });

ipcMain.handle("defaults", () => ({ ...DEFAULTS }));

ipcMain.handle("check-network", async () => checkOutboundSmtp());

ipcMain.handle("validate-one", async (_evt, email, options) => {
  requireLicense();
  const session = createSession(options || {});
  return session.validateEmail(email);
});

ipcMain.handle("validate-many", async (evt, emails, options) => {
  requireLicense();
  if (activeRun) activeRun.stop = true;
  const run = { id: Date.now(), stop: false };
  activeRun = run;
  const session = createSession(options || {});
  const sender = evt.sender;

  // Batch progress (2–3 screen updates a second): cheap over Remote Desktop, still feels live.
  let pending = [];
  let timer = null;
  const flush = () => {
    timer = null;
    if (!pending.length || sender.isDestroyed()) { pending = []; return; }
    sender.send("progress", { runId: run.id, items: pending, total: emails.length });
    pending = [];
  };
  const results = await session.validateMany(
    emails,
    (result, index, total, finished) => {
      pending.push({ result, index, finished });
      if (!timer) timer = setTimeout(flush, 400);
    },
    () => run.stop,
  );
  if (timer) clearTimeout(timer);
  flush();
  if (activeRun === run) activeRun = null;
  return { runId: run.id, results, stopped: run.stop };
});

ipcMain.handle("stop", () => { if (activeRun) activeRun.stop = true; return true; });

ipcMain.handle("open-file", async () => {
  const { canceled, filePaths } = await dialog.showOpenDialog(win, {
    title: "Import email list",
    properties: ["openFile"],
    filters: [{ name: "Text / CSV", extensions: ["txt", "csv", "tsv", "lst", "md"] }, { name: "All files", extensions: ["*"] }],
  });
  if (canceled || !filePaths.length) return null;
  const text = await fs.readFile(filePaths[0], "utf8");
  return { path: filePaths[0], emails: extractEmails(text) };
});

ipcMain.handle("export-csv", async (_evt, results) => {
  const { canceled, filePath } = await dialog.showSaveDialog(win, {
    title: "Export results",
    defaultPath: `email-validation-${new Date().toISOString().slice(0, 10)}.csv`,
    filters: [{ name: "CSV", extensions: ["csv"] }],
  });
  if (canceled || !filePath) return null;
  await fs.writeFile(filePath, toCsv(results), "utf8");
  return filePath;
});

ipcMain.handle("extract-emails", (_evt, text) => extractEmails(text));
