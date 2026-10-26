// Preload runs with contextIsolation on. The UI is served by binny --serve and
// talks to the backend over HTTP/SSE, so it needs nothing from Node today. This
// file is the seam for future native bridges (e.g. a real OS file-open dialog
// surfaced to the page) without turning on nodeIntegration.
const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('binnyDesktop', {
  version: process.env.npm_package_version || 'dev',
});
