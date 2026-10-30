# BINNY Desktop — design

> Status: draft / in progress. The GUI for BINNY: a local-first, agent-centric
> reverse-engineering workstation. Lives in this repo (`desktop/`) because its
> backend *is* `binny --serve` — a new mode of this binary, reusing the engine.

## 1. Vision

BINNY Desktop is **GitHub Desktop for reverse engineering**: a graphical shell
around the same agent the CLI already runs. The agent is the product; the code
viewer and file tree are secondary, opt-in surfaces.

The defining property is **fully offline / air-gapped**:

- **Decompile is local** — JADX/Ghidra Docker workers, already downloaded and run
  by this binary.
- **Code serving is local** — the source cache (`internal/tools/cache.go`,
  `localsrc.go`), read from disk, not S3.
- **The model can be local** — `internal/llm` already speaks to Ollama / LM Studio
  (`openai.go:132` handles keyless local servers; `catalog.go` lists `/v1/models`).

> **The pitch: "Your malware never leaves your machine."** Analysts and vuln
> researchers often legally/contractually cannot upload samples or decompiled
> code to a cloud API. A 100%-offline agent is the differentiator.

**Connected mode (opt-in).** Local-first is the default, but the desktop is not
local-*only*: you can sign in to the openbin backend **from the GUI** (browser
device flow — no terminal) and open any of your existing cloud projects. BINNY
downloads that project's decompiled source into the local cache and serves it
exactly like a dropped APK, so chat/findings/reports all work against it. Login
shares the openbin CLI's credentials file, so signing in either place satisfies
both. See §8.

## 2. Architecture

```
Electron shell
  React frontend (chat-first; tree/code/findings/report are toggleable drawers)
        │ localhost HTTP + SSE/WS
  binny --serve   (ONE Go binary — the entire local backend)
    ├─ engine · tools · vuln framework · reports        (internal/agent, …)
    ├─ local file serving: /files /file /search /manifest (from the cache)
    ├─ agent stream: /binny/stream (SSE, same event shape the frontend knows)
    ├─ local-model detection: /local-models
    ├─ JADX/Ghidra workers (Docker)                     (internal/worker, jadx)
    └─ Ollama / LM Studio (auto-detected)               (internal/llm)
```

No Spring Boot, no Postgres, no Keycloak in the desktop app. One Go binary, one
React bundle, Docker for decompilation, optional Ollama for the model.

### Monorepo layout

```
binny/
  main.go               --serve flag branches here (TUI stays the default)
  internal/             engine/tools/llm — shared by CLI + desktop, unchanged
  internal/serve/       NEW: HTTP+WS adapter + session manager
  desktop/              NEW: React frontend + Electron shell
  .github/workflows/    release.yml (CLI, unchanged) + release-desktop.yml (new)
```

## 3. Agent-first UI

Invert the platform's `tree │ code │ chat` grid. **Chat is the root, full-bleed.**
Everything else is a drawer, **off by default**.

- **Default:** a centered conversation (Claude/ChatGPT-desktop feel). The input is
  the hero; an **Investigate** button next to it turns the engine loose (full
  autopilot, streaming stages into the conversation).
- **Code lives inline:** when the agent reads a file / finds a sink, the tool-card
  expands *in the conversation* to show the relevant lines. You rarely need the
  full pane.
- **Drawers (toggles, default off):** `Explorer` (tree), `Code` (full-file Shiki
  viewer), `Findings` (CWE/severity/reachability list), `Report` (CVE draft).
  Overlay for quick peeks; push only for Code (side-by-side reading).
- **Mode + focus** (Malware/Vuln + class chips) sit in the top bar, always visible,
  set *before* starting — kills the "stuck in malware mode" problem.

Decisions (current): file-open is **inline-only** by default (drawer never
auto-pops); Investigate is a **button**, chat is for steering.

## 4. Local-model detection

On launch, probe well-known local endpoints and auto-populate the model picker —
the Open WebUI / AUTOMATIC1111 UX. The engine already talks to these; detection
is a thin probe on top.

| Runtime  | Probe                              |
|----------|------------------------------------|
| Ollama   | `GET localhost:11434/api/tags`     |
| LM Studio| `GET localhost:1234/v1/models`     |
| Jan      | `GET localhost:1337/v1/models`     |
| llama.cpp / LocalAI / vLLM | `/v1/models` (configurable) |

Hit → register a keyless OpenAI-compatible provider at that base URL → show its
models as "Detected: <runtime>".

## 5. Reuse map (from the codebase survey)

Reuse from `platform/openapk-frontend` + `shared/` (strip auth/social):
- the three-pane `ProjectView` shell (invert to chat-first), drag-resize
- `HighlightedCode` (Shiki viewer; add a line-number gutter)
- `FileTreeNode` + `lib/localTree.ts` (repoint from presigned URL → local FS)
- the whole chat stack: `AskPanel`, `shared/api/streaming.ts` (SSE:
  `onChunk/onToolCall/onToolResult/onDone`), `askSessions.ts`, `BinnyToolCards.tsx`
- findings panels: `HighlightsPanel`, `AnalysisTab`/`SeverityPill`,
  `Symbols`/`Native`/`Crypto`/`Network`/`EntryPoints`/`CallChain`
- `shared/config/runtime.ts` (runtime endpoint config — already supports localhost)

Leave behind: Keycloak/OIDC, team chat, DMs, CTF, leaderboards, blog, profiles,
fork/share/publish, BYO-credential gating, the landing site.

Do **not** reuse the Java "BINNY light" agent — it's a 2/5 single-file chat loop
with none of the four pillars (pipeline / vuln framework / structured findings /
CVE reports). The Go engine is "terminal BINNY," the real one.

## 6. Build phases

1. ✅ **Vertical slice (prove the spine):** `binny --serve` with `/api/files` +
   `/api/file` from a decompiled tree on disk (`--serve-dir`); an **embedded**
   chat-first web UI (`internal/serve/web/`) served at `/`; tree loads +
   click-to-view code with a line-number gutter + light syntax highlight.
   Path-traversal guarded. *(DONE)*
2. ✅ **Local-model detection:** `/api/local-models` probe + picker wiring (and
   `/api/config` for configured cloud providers). *(DONE)*
3. ✅ **Chat (MVP):** `POST /api/chat` streams (SSE) a real conversation through
   the `internal/llm` provider layer — **fully offline against a detected local
   model**, or a configured cloud provider. Mode (Malware/Vuln) + focus chips
   shape the system prompt; the open file is sent as context. *(DONE)*
3b. ✅ **Agentic tool loop** (`internal/serve/agent.go`): with a served tree the
   model gets read-only tools — `list_files`, `read_file`, `search_code` — and
   *investigates on its own* (lists/searches/reads, then reports), streaming
   `tool_call`/`tool_result` SSE events the UI renders as cards. The GUI
   equivalent of the CLI's direct mode; fully offline against a tool-capable
   local model. Tools only ever touch the served tree (traversal-guarded).
   *(DONE)*
4. ⏭ **Full staged engine stream:** replace this lightweight loop with the real
   staged engine (triage→…→review, the full tool registry, structured findings,
   CVE reports) over SSE/WS + a typed event DTO mapping `StepResult`/stream-sink
   to the same `tool_call`/`tool_result` shape. Session-manager goroutine driver
   (port the loop from `internal/tui/agent.go`).
5. ⏭ **Answer/checkpoint protocol over WS** (`ask_user`, checkpoints, cap
   extension — engine support exists: `Provide`/`Ask`/`ContinuePastCap`/`Stop`).
6. 🟡 **Decompile from the GUI:** ✅ for APK — drop an `.apk` on the window (or
   ＋ APK) → `POST /api/decompile` runs the local JADX worker, streams progress
   (SSE), swaps the served tree to the result and opens Explorer. Cached by
   sha256 in the local store, so re-dropping is instant; the served dir is now
   runtime-swappable (`internal/serve/decompile.go`). ✅ binary/Ghidra path too —
   ＋ Open takes any file; binaries go to `POST /api/analyze` (Ghidra) and open in
   chat mode (`internal/serve/binary.go`); see §8.5.
7. 🟡 **Findings + report drawers**, inline code cards. Findings: ✅ — a
   `record_finding` tool pins structured findings (title/severity/CWE/file:line/
   reachability/note) that stream as `finding` SSE events into a severity-sorted
   Findings drawer; click a finding to open its file. Report drawer + inline code
   cards: ⏭.
8. 🟡 **Electron shell** (`desktop/`): ✅ — `main.js` starts `binny --serve` as a
   loopback sidecar (free port, health-wait, kill on quit), opens a window on it,
   and has a File → Open Decompiled Folder menu that restarts the sidecar on the
   chosen tree. `preload.js` (contextIsolation) is the seam for native bridges.
   Run: `go build -o desktop/bin/binny . && cd desktop && npm i && BINNY_BIN=./bin/binny npm start`.
   ⏭ remaining: `electron-builder` installers, macOS notarization,
   `release-desktop.yml`.

Try the MVP:

```
binny --serve --serve-dir <a decompiled tree>
# open the printed http://127.0.0.1:8899 in a browser
# (run Ollama/LM Studio for a zero-config local model)
```

Honest cost of what's left: the engine needs ~no changes; phase 4 (the typed
event layer + session-manager driver) is the real ~1–2 week piece. The current
chat is a direct provider call, not the staged engine — deliberately, so the
offline loop works today.

## 7. Dynamic analysis — DRAFT pipeline (future)

Everything today is **static** (reads decompiled output). Dynamic analysis is
greenfield, but the tool registry makes agent integration trivial; the real work
is the **sandbox + a stateful session abstraction**.

### 7.1 Two new primitives

- **`DynamicTarget`** — a live, stateful handle to a running debuggee/emulator,
  owned by a session manager. One interface, swappable backends (same pattern as
  `sourceTree` in `source.go`: `remote`/`local`/`cached`). Backends: `gdb`,
  `qemu`, `android-emulator`, `renode`.
- **Detonation sandbox** — isolation + snapshots + controllable network. The
  hard, safety-critical part (see risks).

### 7.2 Backends

| Backend | Role | Control surface | Priority |
|---------|------|-----------------|----------|
| GDB | live-debug native binaries (breakpoints, regs, mem, step) | GDB/MI | 1 (first win; pairs with Ghidra) |
| tshark/dumpcap | passive network capture during a run (C2/exfil IOCs) | CLI + TLS mitm | 2 (cheap, high value) |
| QEMU | cross-arch emulation + full-system sandbox VM | `-s -S` gdbstub (+ GDB) | 3 (sandbox backbone) |
| Android emulator | dynamic APK (install/drive/hook/logcat/net) | AVD + Frida | 4 (completes APK story) |
| Renode | embedded/IoT firmware emulation | monitor/robot + GDB | 5 (niche) |

Composition: **execution backend** (QEMU/emulator/Renode) + **instrumentation**
(GDB-MI / Frida) + **passive observation** (tshark / strace / logcat).

### 7.3 Pipeline shape

Dynamic slots into the existing engine as a **verification stage**:

```
triage → investigate (static) → [dynamic verification] → synthesize → review
```

- Static produces a **hypothesis** ("input-controlled loop into fixed buffer —
  overflow suspected, reachability unproven").
- Dynamic **proves it**: feed the input under QEMU+GDB, observe the crash, capture
  register/stack state; or detonate the sample and capture real C2 packets.
- Synthesize with **both** static and runtime evidence.

This upgrades the vuln framework's weakest column: `reachability=proven` stops
meaning "I traced the calls" and starts meaning "**I ran it and it crashed, here's
the state.**" CVE-grade evidence.

Safety gate: dynamic actions are destructive, so the agent *proposes* them and the
user confirms at a **`Checkpoint`** (mechanism already in the engine).

### 7.4 Risks (where the real cost is)

1. **Executing hostile code** — isolation is non-negotiable (VM snapshots, no host
   network, contained bridge, kill-switch). #1 responsibility.
2. **Network tension with "offline"** — malware wants to phone home; need
   *controllable* network (INetSim/FakeNet or mitm) to observe without real egress.
3. **Anti-analysis** — malware detects emulators/debuggers; cat-and-mouse, not
   magic.

### 7.5 Sequence

GDB (native) → tshark capture → QEMU+gdbstub → Android emulator+Frida → Renode.

## 8. Connected mode — login + cloud project picker ✅

Local-only was the testing gap ("I can't even log in and pick my projects").
Connected mode closes it while keeping local-first the default.

### 8.1 Login (browser device flow, no terminal)

BINNY shares the openbin CLI's credentials (`~/.config/openbin/credentials.json`),
but the desktop can't tell a user to go run `openbin login`. So the OAuth 2.0
device authorization grant (RFC 8628) — the same flow the CLI uses — is ported
into `internal/auth/login.go`:

- `auth.StartDeviceLogin(ep)` → `{user_code, verification_uri_complete}`.
- `auth.(*DeviceLogin).Poll(ctx, ep)` → polls the token endpoint, saves the
  tokens to the shared file, returns the `Account` (email/username from the JWT).
- `auth.Status(ep)` / `auth.Logout()` for the UI. `config.DeviceAuthEndpoint()`
  is the new Keycloak URL.

A login done in the desktop also works for the CLI/TUI, and vice-versa.

### 8.2 Routes (`internal/serve/connected.go`)

```
GET  /api/auth/status   who's logged in (refreshes a stale-but-valid session)
POST /api/auth/login    SSE device flow: {code …} then {done, account} | {error}
POST /api/auth/logout   forget stored credentials
GET  /api/projects      the user's backend projects (openable = APK or BIN, ready)
POST /api/project/open  SSE: fetch → (APK) swap tree {ready,root} | (BIN) load
                        analysis {ready,summary} | {error}
```

Opening an **APK** reuses the cached-remote-source path
(`tools.PrefetchSourceTree` → `store.RemoteTreeDir(id)/src`) and the same
`setDir` swap GUI decompile uses — so `/api/files`, `/api/file`, `/api/chat` and
findings work against it unchanged. A re-open of a cached project is instant.

Opening a **binary** (BIN) has no source tree — see §8.4.

The served `server` tracks the backing project id (`curPID`) and, for binaries,
the analysis tool registry (`curReg`); both are surfaced at `/api/health`
(`projectId`, `binary`).

### 8.3 Frontend

A **☁ Cloud** button in the top bar opens a modal: signed out → "Sign in with
your browser" (opens the verification URL, shows the short code, waits); signed
in → the account line + a list of your projects. APK and binary projects are
openable; scripts/zips are shown disabled. Picking an APK streams open-progress
and swaps Explorer to the cloud tree; picking a binary loads its analysis and
drops you straight into chat (Explorer notes there's no tree). Local analysis
(drop an APK) still needs no login.

### 8.4 Binary projects — chat over the Ghidra analysis ✅

Binaries have no browsable tree (they're one analysis blob: functions with
decompiled C, strings, imports/exports, symbols, xrefs — see the Ghidra recon in
§7). That fits the chat-first design perfectly: there's nothing to browse, so the
**agent is the whole surface**. Opening a BIN builds a `tools.NewToolbox(client,
project)` + `Registry` and calls `tb.RegisterRead(reg)`, which registers the real
binary tool set (`list_functions`, `get_function`, `get_strings`, `get_imports`,
`get_exports`, `xrefs`, `reachability`, `search`, …) — the **same tools the TUI
uses**, not reimplementations. `handleOpenProject` runs `get_metadata` once to
load+cache the blob and returns it as the open summary.

The serve chat agent (`agent.go`) is now registry-aware: `record_finding` is
always offered; when `s.reg()` is set it exposes `reg.Defs()` and dispatches
calls through `reg.Run()`; otherwise it falls back to the read-only tree tools.
So "open a cloud binary and interrogate it" works today — fully through the
existing toolbox, no new per-binary UI. The blob is cached (`store.SaveRemote`),
so re-opens are instant and work offline after the first fetch.

### 8.5 Local binary import ✅

The ＋ button is now **＋ Open** and takes any file: drag in or pick an `.apk`
(→ JADX, §8.2) or any binary (`.exe`/`.elf`/Mach-O → Ghidra). `POST /api/analyze`
(`internal/serve/binary.go`) mirrors the APK decompile but for binaries —
`archdetect.Detect` → `ghidra.Analyze` → `api.ParseAnalysis` → `store.Save`,
then builds a local `api.Project` (`local:<sha12>`, kind BIN) and enters the same
binary chat mode as a cloud BIN. Cached by sha256, so re-dropping is instant. The
whole thing is **offline**: a local binary's analysis blob is read straight from
the store, so the toolbox needs no backend client (`NewToolbox(nil, project)`).
Raw images (firmware, no ELF/PE/Mach-O header) need a forced processor id the GUI
can't prompt for yet — those still go to the CLI (`/decompile <file> <proc>`).

Honest scope: SCRIPT/zip projects still don't open. A richer binary UI (function
list / decompiled-C viewer pane) beyond chat is future work; the chat tools
already expose all of it.
