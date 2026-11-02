// BINNY Desktop — Electron shell.
//
// The entire backend is the `binny --serve` binary (the same one the CLI uses).
// This process is only a shell: it starts binny as a loopback sidecar, waits for
// it to answer, and opens a window on it. Nothing here re-implements analysis.
//
// Finding the binary:
//   - BINNY_BIN env var, if set (dev: point it at your `go build` output); else
//   - a bundled binary at <resources>/bin/binny[.exe] (packaged app); else
//   - `binny` on PATH.
//
// Run in dev:  BINNY_BIN=/path/to/binny npm start

const { app, BrowserWindow, Menu, dialog, shell } = require('electron');
const { spawn } = require('child_process');
const http = require('http');
const net = require('net');
const path = require('path');
const fs = require('fs');

let sidecar = null;
let win = null;
let port = 0;
let serveDir = process.env.BINNY_DIR || '';

function binnyPath() {
  if (process.env.BINNY_BIN) return process.env.BINNY_BIN;
  const exe = process.platform === 'win32' ? 'binny.exe' : 'binny';
  const bundled = path.join(process.resourcesPath || '', 'bin', exe);
  if (fs.existsSync(bundled)) return bundled;
  return 'binny'; // from PATH
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

function waitHealth(p, tries = 60) {
  return new Promise((resolve, reject) => {
    const tick = (n) => {
      const req = http.get({ host: '127.0.0.1', port: p, path: '/api/health', timeout: 500 }, (res) => {
        res.resume();
        if (res.statusCode === 200) return resolve();
        retry(n);
      });
      req.on('error', () => retry(n));
      req.on('timeout', () => { req.destroy(); retry(n); });
    };
    const retry = (n) => {
      if (n <= 0) return reject(new Error('binny --serve did not become healthy'));
      setTimeout(() => tick(n - 1), 150);
    };
    tick(tries);
  });
}

async function startSidecar() {
  if (sidecar) { try { sidecar.kill(); } catch (_) {} sidecar = null; }
  port = await freePort();
  const args = ['--serve', '--serve-addr', `127.0.0.1:${port}`];
  if (serveDir) args.push('--serve-dir', serveDir);
  sidecar = spawn(binnyPath(), args, { stdio: 'inherit' });
  sidecar.on('exit', (code) => {
    if (code && !app.isQuitting) {
      dialog.showErrorBox('BINNY', `binny --serve exited (code ${code}).`);
    }
  });
  await new Promise((resolve, reject) => {
    sidecar.once('error', reject);
    waitHealth(port).then(resolve, reject);
  });
}

async function createWindow() {
  win = new BrowserWindow({
    width: 1320, height: 860, minWidth: 900, minHeight: 600,
    backgroundColor: '#0d0f14', title: 'BINNY Desktop',
    webPreferences: { contextIsolation: true, nodeIntegration: false, preload: path.join(__dirname, 'preload.js') },
  });
  await win.loadURL(`http://127.0.0.1:${port}/`);
  win.on('closed', () => { win = null; });
}

async function openFolder() {
  const r = await dialog.showOpenDialog(win, {
    title: 'Open a decompiled tree',
    properties: ['openDirectory'],
  });
  if (r.canceled || !r.filePaths[0]) return;
  serveDir = r.filePaths[0];
  try {
    await startSidecar();
    if (win) await win.loadURL(`http://127.0.0.1:${port}/`);
  } catch (e) {
    dialog.showErrorBox('BINNY', 'Could not restart with that folder: ' + e.message);
  }
}

function buildMenu() {
  const isMac = process.platform === 'darwin';
  const template = [
    ...(isMac ? [{ role: 'appMenu' }] : []),
    {
      label: 'File',
      submenu: [
        { label: 'Open Decompiled Folder…', accelerator: 'CmdOrCtrl+O', click: openFolder },
        { type: 'separator' },
        { label: 'Reload', accelerator: 'CmdOrCtrl+R', click: () => win && win.reload() },
        isMac ? { role: 'close' } : { role: 'quit' },
      ],
    },
    { role: 'editMenu' },
    { role: 'viewMenu' },
    {
      role: 'help',
      submenu: [{ label: 'BINNY on GitHub', click: () => shell.openExternal('https://github.com/openbin-ai/binny') }],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

app.whenReady().then(async () => {
  try {
    await startSidecar();
  } catch (e) {
    dialog.showErrorBox('BINNY', 'Could not start the binny backend: ' + e.message +
      '\n\nSet BINNY_BIN to your binny binary, or put it on PATH.');
    app.quit();
    return;
  }
  buildMenu();
  await createWindow();
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('before-quit', () => { app.isQuitting = true; if (sidecar) { try { sidecar.kill(); } catch (_) {} } });
app.on('window-all-closed', () => { app.quit(); });
