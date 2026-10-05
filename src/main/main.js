"use strict";

const { app, BrowserWindow, ipcMain, dialog, shell } = require("electron");
const path = require("node:path");
const fs = require("node:fs/promises");
const { createSession, checkOutboundSmtp, extractEmails, toCsv, DEFAULTS } = require("./validator");

let win = null;
let activeRun = null; // { id, stop: boolean }

function createWindow() {
  win = new BrowserWindow({
    width: 1100,
    height: 760,
    minWidth: 820,
    minHeight: 560,
    title: "Email Validator",
    backgroundColor: "#0f1115",
    titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "default",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadFile(path.join(__dirname, "..", "renderer", "index.html"));
  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: "deny" }; });
  win.on("closed", () => { win = null; });
}

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });

// ---------- IPC ----------

ipcMain.handle("defaults", () => ({ ...DEFAULTS }));

ipcMain.handle("check-network", async () => checkOutboundSmtp());

ipcMain.handle("validate-one", async (_evt, email, options) => {
  const session = createSession(options || {});
  return session.validateEmail(email);
});

ipcMain.handle("validate-many", async (evt, emails, options) => {
  if (activeRun) activeRun.stop = true;
  const run = { id: Date.now(), stop: false };
  activeRun = run;
  const session = createSession(options || {});
  const sender = evt.sender;
  const results = await session.validateMany(
    emails,
    (result, index, total, finished) => {
      if (!sender.isDestroyed()) sender.send("progress", { runId: run.id, result, index, total, finished });
    },
    () => run.stop,
  );
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
