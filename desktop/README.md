# BINNY Desktop (Electron shell)

The GUI shell for BINNY. It does **not** contain any analysis logic — it starts
the `binny --serve` binary as a loopback sidecar, waits for it to answer, and
opens a window on it. See [`../docs/DESKTOP.md`](../docs/DESKTOP.md) for the
architecture.

## Run in development

1. Build the backend binary from the repo root:

   ```sh
   go build -o desktop/bin/binny .
   ```

2. Install and start the shell:

   ```sh
   cd desktop
   npm install
   BINNY_BIN=./bin/binny npm start
   ```

   `BINNY_BIN` points the shell at your binary. Without it, the shell looks for a
   bundled `bin/binny[.exe]` (packaged app), then `binny` on `PATH`.

   To open on a tree immediately: `BINNY_DIR=/path/to/decompiled npm start`, or
   use **File → Open Decompiled Folder…** in the app.

## Package (installers)

`electron-builder` bundles the binary from `desktop/bin/` as an app resource:

```sh
cd desktop
npm install
npm run dist        # builds the Go sidecar into bin/ (build-sidecar.js), then electron-builder
```

`npm run dist` runs `build-sidecar.js` first (native `go build` for the host, with
the version baked in from `BINNY_VERSION`), so you don't build the binary by hand.
Use `npm run pack` for an unpacked dir (faster, no installer). Output lands in
`desktop/dist/`. Targets: dmg/zip (macOS), nsis/zip (Windows), AppImage/tar.gz
(Linux).

Release: push a `desktop-v*` tag and `.github/workflows/release-desktop.yml`
packages on a per-OS runner matrix and attaches the installers to the release.

Builds are **unsigned** for now: macOS users right-click → Open the first time;
Windows shows a SmartScreen prompt. Code-signing + notarization just need certs —
electron-builder reads `CSC_LINK`/`CSC_KEY_PASSWORD` (macOS) and the Windows
signing secrets from the environment.

## What runs where

- **Shell (this folder):** spawns the sidecar, window + menu, folder picker.
- **Backend (`binny --serve`):** file serving, local-model detection, the agent
  tool loop, findings — all local, no cloud.
- **UI:** served by the backend from `internal/serve/web/`, loaded over
  `http://127.0.0.1:<port>`.
