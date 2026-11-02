#!/usr/bin/env bash
# BINNY Desktop — the quickest way to try it.
#
#   ./run.sh                      build + serve the GUI, open it in your browser
#   ./run.sh --serve-dir <path>   also open on a decompiled tree
#   BINNY_ADDR=127.0.0.1:9000 ./run.sh   pick a different port
#
# Ctrl-C stops the server. (For the real native window instead of a browser tab,
# see desktop/README.md — that path uses Electron.)
set -euo pipefail
cd "$(dirname "$0")"

ADDR="${BINNY_ADDR:-127.0.0.1:8899}"
URL="http://$ADDR"

echo "Building binny…"
go build -o desktop/bin/binny .

echo "Starting BINNY Desktop at $URL  (Ctrl-C to stop)"
./desktop/bin/binny --serve --serve-addr "$ADDR" "$@" &
PID=$!
trap 'kill "$PID" 2>/dev/null || true; echo; echo "stopped."; exit 0' INT TERM

# Give the server a beat, then open the browser.
sleep 1
if command -v open >/dev/null 2>&1; then open "$URL"
elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"
else echo "Open $URL in your browser."; fi

wait "$PID"
