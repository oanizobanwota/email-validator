"use strict";

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("validator", {
  defaults: () => ipcRenderer.invoke("defaults"),
  checkNetwork: () => ipcRenderer.invoke("check-network"),
  validateOne: (email, options) => ipcRenderer.invoke("validate-one", email, options),
  validateMany: (emails, options) => ipcRenderer.invoke("validate-many", emails, options),
  stop: () => ipcRenderer.invoke("stop"),
  openFile: () => ipcRenderer.invoke("open-file"),
  exportCsv: (results) => ipcRenderer.invoke("export-csv", results),
  extractEmails: (text) => ipcRenderer.invoke("extract-emails", text),
  license: {
    status: () => ipcRenderer.invoke("license-status"),
    activate: (key) => ipcRenderer.invoke("license-activate", key),
    remove: () => ipcRenderer.invoke("license-remove"),
  },
  onProgress: (cb) => {
    const handler = (_evt, payload) => cb(payload);
    ipcRenderer.on("progress", handler);
    return () => ipcRenderer.removeListener("progress", handler);
  },
});
