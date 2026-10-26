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
go build -o desktop/bin/binny .     # the right GOOS/GOARCH for the target
cd desktop && npm run dist
```

macOS builds need notarization for distribution (not configured here yet — phase
8 in the design doc). The CI mirror pattern used for the CLI release
(`.github/workflows/release.yml`) is the template for a `release-desktop.yml`.

## What runs where

- **Shell (this folder):** spawns the sidecar, window + menu, folder picker.
- **Backend (`binny --serve`):** file serving, local-model detection, the agent
  tool loop, findings — all local, no cloud.
- **UI:** served by the backend from `internal/serve/web/`, loaded over
  `http://127.0.0.1:<port>`.
