// Build the binny Go binary into desktop/bin/ so electron-builder can bundle it
// as a resource (extraResources bin→bin; main.js loads <resources>/bin/binny).
// Runs for the host platform/arch — the release workflow runs this on each OS
// runner so every installer ships a native sidecar. Version comes from
// BINNY_VERSION (the release tag) when set, else "dev".
const { execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const isWin = process.platform === 'win32';
const outDir = path.join(__dirname, 'bin');
const out = path.join(outDir, isWin ? 'binny.exe' : 'binny');
const repoRoot = path.join(__dirname, '..');
const version = process.env.BINNY_VERSION || 'dev';

fs.mkdirSync(outDir, { recursive: true });
console.log(`building binny sidecar (version=${version}) → ${out}`);
execFileSync(
  'go',
  ['build', '-trimpath', `-ldflags=-s -w -X main.version=${version}`, '-o', out, '.'],
  { cwd: repoRoot, stdio: 'inherit', env: { ...process.env, CGO_ENABLED: '0' } }
);
console.log('sidecar built.');
