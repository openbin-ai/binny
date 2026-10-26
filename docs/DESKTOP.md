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

1. **Vertical slice (prove the spine):** `binny --serve` with `/files` + `/file`
   from the local cache; run the stripped frontend against localhost, auth
   stubbed; confirm tree loads + click-to-view code. No chat yet.
2. **Local-model detection:** `/local-models` probe + picker wiring. *(Self-
   contained; good standalone first win — shipped alongside phase 1.)*
3. **Agent stream:** `/binny/stream` SSE + a typed event DTO layer mapping the
   engine's `StepResult`/stream-sink to the `tool_call`/`tool_result` shape the
   frontend already renders. The session-manager goroutine driver (port the loop
   from `internal/tui/agent.go`).
4. **Answer/checkpoint protocol over WS** (`ask_user`, checkpoints, cap
   extension — engine support exists: `Provide`/`Ask`/`ContinuePastCap`/`Stop`).
5. **Decompile from the GUI:** drag-drop APK/binary → worker → progress → tree.
6. **Findings + report drawers**, mode/focus toolbar, inline code cards.
7. **Electron packaging** + macOS notarization; `release-desktop.yml`.

Honest cost: the engine needs ~no changes; the work is the serve adapter + the
typed event layer + the frontend decoupling from OIDC. ~1–2 weeks to a working
agent-in-a-window, more for polish/packaging.

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
