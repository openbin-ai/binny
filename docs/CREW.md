# BINNY Crew — implementation plan

Turn BINNY from a single agent into a **captain + crew**: BINNY orchestrates a
named crew of specialist agents, each with its own role, toolset and avatar.
Analysts arrange the crew into saved **missions**, direct them with **tasking**,
gate them with **checkpoints**, and the crew builds **experience** across runs.

This is an internal design/build plan, not user docs.

---

## 1. Concept & vocabulary

| Term | Meaning |
| --- | --- |
| **Captain (BINNY)** | Orchestrates: triage, dispatch, writes the report. Always first and last. |
| **Crew member** | A specialist worker agent with a fixed skill, toolset and avatar. |
| **Mission** | A saved pipeline: crew order + checkpoints + tasking. Mirrors how playbooks are data. |
| **Tasking** | Custom prompt directing an agent. Mission-level, crew-level, or a standalone Captain task card. |
| **Checkpoint** | A gate between two steps that pauses for the analyst. |
| **Debrief** | The short report a crew member hands back when its step finishes. |
| **Mission log** | The full transcript of a run. |
| **Experience** | Opt-in *method* notes, keyed by target type, that grow across runs. |

`/investigate` becomes "run the default mission". Missions live in
`~/.config/binny/missions/`, experience in `~/.config/binny/experience/`.

### The crew

| Name | Role | Tools (subset of the registry) | Avatar | Accent |
| --- | --- | --- | --- | --- |
| **BINNY** | Captain — triage, dispatch, report | full conversation, `ask_user`, report tools | file | black/white |
| **Siggy** | Lookout — first sweep, classification hints | metadata, imports, strings | magnifying glass | purple |
| **Twine** | String/IOC hunter | strings, data reads, `add_ioc` | spool | orange |
| **Trace** | Navigator — call paths, source→sink | function list, decompilation, `reachability` | compass | blue |
| **Hex** | Engineer — crypto, config decryption, unpacking | raw data reads, sandbox `run`, artifacts | hex nut | green |
| **Dex** | Android specialist (lead worker on APK projects) | manifest, code search, find usages | red Android devil | red |
| **Parity** | Skeptic — verifies findings before the report | read tools only; can confirm/downgrade/reject | light bulb (lit/dark) | yellow |

Art lives in `internal/serve/web/crew/` (embedded + served). Avatars read down
to 24px; Parity has `parity.png` (lit) and `parity-dark.png` (rejected).

---

## 2. Decisions locked for v1

- **Sequential, not parallel.** Crew run one at a time first. Parallelism is a
  later milestone (it complicates the budget, the transcript, and resume).
- **Parity is removable.** If a mission drops Parity, the draft is labelled
  **"unverified"**. BINNY and triage/report are not removable.
- **Experience ships after missions.** It is the riskiest piece and nothing
  else depends on it.
- **Go code drives dispatch, not a lead model.** BINNY must work with weak local
  models; the playbooks already decompose the work. One opt-in switch
  ("Captain may add steps") lets strong models adapt.
- **Evidence-grounding is untouchable.** Tasking and experience are *hints*.
  Findings are still refused without an evidence ref
  (`Investigation.AddFinding`, `internal/agent/investigation.go`).

---

## 3. Architecture

### 3.1 Where the code is today
- `internal/agent/engine.go` — `Engine` drives a stage machine
  (triage→investigate→synthesize→review→done) over **one** `messages` slice via
  `Step()`. Mixes the model/tool loop with phase flow.
- `internal/agent/investigation.go` — mutex-guarded shared state; evidence
  enforced at write time. **This is already crew-safe shared memory.**
- `internal/playbook/playbook.go` — playbooks are data: `Objectives` + tool bias
  + report `Sections`, selected by STIX type.
- `internal/tools/tools.go` — `Registry` (name-addressed tools, `Defs()`/`Run()`).
- `internal/agent/build.go` — `Build()` wires provider + registry + investigation.
- `internal/agent/persist.go` — `EngineState` snapshot for resume.
- `internal/serve/serve.go:50` — `//go:embed web` serves everything under `web/`,
  including `crew/`.
- `internal/serve/web/index.html` — Desktop UI; SSE event types today:
  `chunk, tool_call, tool_result, status, finding, artifact, highlight, saved, usage`.
- `internal/tui/` — terminal UI (`binnyart.go` holds text art).

### 3.2 The core refactor (no behaviour change)
Extract the model/tool loop out of `Engine` into a reusable **runner** so one
crew member is "a loop with a role + tool subset + budget + its own messages,
writing to the shared `Investigation`".

- New `internal/agent/runner.go`: `Runner` owns `messages`, a `*tools.Registry`
  view (filtered to the role's tools), a per-step budget, and `Step()` — the
  provider round-trip + tool execution currently inside `Engine.Step`.
- `Engine` keeps the stage machine and becomes the **captain + dispatcher**: it
  owns the shared `Investigation`, runs triage itself, then drives each crew
  member's `Runner` to completion, injecting tasking as the opening message.
- A crew member finishes its step when it ends a turn with no tool calls (same
  signal `Engine` uses today) and emits a **debrief** (a short structured
  summary written to the mission log + shared notebook).

### 3.3 Crew as data
New `internal/agent/crew.go`:
```go
type Role struct {
    ID        string   // "hex"
    Name      string   // "Hex"
    Avatar    string   // "crew/hex.png"
    Accent    string   // "#1DB954"
    Tools     []string // tool names this role may call
    SystemAdd string   // role personality + rules appended to the base system prompt
    Owns      []string // objective IDs this role owns by default
}
```
Roles are a static registry (like `playbook.registry`). `Owns` maps playbook
objectives to default owners, so a mission with empty tasking still works:
triage picks objectives → each objective's owner runs it.

### 3.4 Missions as data
New `internal/mission/mission.go`:
```go
type Mission struct {
    Name       string
    Steps      []Step   // ordered; BINNY triage implicit first, report implicit last
    AllowAdd   bool     // "Captain may add steps"
    Tasking    string   // mission-level, seen by all
}
type Step struct {
    RoleID      string   // "hex", or "binny" for a standalone Captain task card
    Tasking     string   // crew-level / the task card's prompt ("" = default from Owns)
    Model       string   // "" = session model
    TokenBudget int      // 0 = share of mission budget
    Focus       []string // objective IDs to override Owns
    Checkpoint  bool     // pause AFTER this step
}
```
- Persist as JSON in `~/.config/binny/missions/<name>.json`.
- Autonomy presets map to checkpoint placement: **autonomous** = none,
  **supervised** = after every step, **custom** = as placed.
- Starters shipped read-only, cloned to edit: *Quick Triage* (Siggy, Twine),
  *Full Malware*, *Android* (Dex-led), *Vuln Hunt* (Trace-led), *Config
  Extractor* (Hex, Parity), *IOC Sweep* (Twine, Parity).
- **Coverage check** at save + run: warn when selected objectives have no owner
  in the crew; unowned objectives fall back to BINNY or report as uncovered.
- **Can't-run steps** (Dex on a native binary; Hex with no sample/Docker) skip
  with a visible reason; they never fail the run.

### 3.5 Tasking
- Three levels: mission tasking (all), crew tasking (one card), standalone
  Captain task card (free-form, run by BINNY with everything found so far).
- Empty crew tasking → default from the role's `Owns` + playbook objectives.
- Placeholders expand at run time: `{sample}`, `{classification}`, `{findings}`.
- Tasking **adds to** a role's rules; it cannot disable evidence-grounding.
- Tasking is shown on each mission card in the log for provenance.

### 3.6 Parity (verification)
- Runs once before synthesis by default (cheapest); option to run after each step.
- Reads a finding's evidence refs in a **fresh context** (ideally a different
  model from the finder) and sets a verdict: confirmed / downgraded / rejected.
- Only confirmed findings feed the draft; rejected kept as negative results
  (same spirit as vuln `ruled_out`).
- Add a `Verdict` + `VerifiedBy` field to `Finding`
  (`internal/agent/investigation.go`); default unset = "unverified".
- If Parity is absent, draft is labelled "unverified".

### 3.7 Shared notebook
- Add a `Notes []Note` board to `Investigation` (function→meaning, keyed by
  symbol/address) so crew don't re-read the same function. Guarded by the
  existing mutex.
- Notes can graduate into the rename suggestions BINNY already supports
  (`RenameSuggestion`).

### 3.8 Persistence & budget
- `EngineState` (`persist.go`) grows: active mission, current step index, each
  runner's messages, per-step spend. Resume lands back mid-mission.
- Token budget becomes a mission total split across steps; cap pauses are named
  ("Hex has used its share and wants 20k more").

---

## 4. Experience (later milestone)

Opt-in memory of **method, never conclusions**.

- **Save method:** "In WiFi drivers, the ioctl handler is the attacker-reachable
  entry — trace from there." NOT "this driver is malicious" or "C2 is x.x.x.x".
  Remembered conclusions would let the crew find what it expects and break
  evidence-grounding (and the skeptical `/ask` stance).
- **Model:** `Note{TargetType, Lesson, FromRun, Role}` keyed by target type
  (WiFi driver, ELF dropper, banking APK). Injected into the matching role's
  tasking as hints only — never pre-fills a finding.
- **Opt-in per note:** after a run, analyst picks which lessons to keep; nothing
  auto-saves.
- **Reviewable:** `/experience` view + Desktop panel to see, edit, prune. A
  confidently wrong lesson is worse than none.
- **Scoped:** a WiFi-driver lesson never fires on an APK.
- **"Save as mission"** is the separate, safe sibling: serialize the run you just
  did (crew order + tasking, generalized) into a reusable mission. Low effort.

---

## 5. Desktop UI

- **Mission editor.** Horizontal track; BINNY locked at start (triage) and end
  (report). Drag crew from a tray into the middle, reorder. Checkpoint toggle
  between cards. Click a card → tasking, model, budget, focus. Coverage warning
  + max-spend preview. Save/clone/load missions.
- **The track is the progress view.** During a run the same row lights up:
  current card pulses with a one-line status, finished cards show finding counts
  + spend.
- **Mission cards in the thread.** Chat stays BINNY's voice. Each dispatch is one
  collapsible card: agent avatar, the tasking it was given, its tool calls
  nested, and the debrief. Avoids interleaving parallel agents line-by-line.
- **Avatars on tool cards.** The status dot (`index.html` `.tool-card .dot`)
  becomes the agent avatar + status ring.
- **Findings drawer provenance.** Each finding shows who found it + Parity's
  bulb: outline = pending, lit = confirmed, dark = rejected. Filter by crew.
- **Welcome lineup.** Empty state introduces the crew, one line each.
- **New SSE events:** `step_start`, `step_debrief`, `verdict`, plus `agent` on
  existing `tool_call`/`tool_result`/`status` so the UI knows who is acting.

### Terminal
- Coloured name tags per line (`[hex]` green).
- `/crew` — status, current task, spend per agent.
- `/mission <name>` — run a saved mission; `/missions` — list.
- Crew art in the TUI is text/coloured tags (PNGs can't render there);
  `internal/tui/binnyart.go` gains per-role tags.

---

## 6. Build order (milestones)

1. **Runner refactor.** Extract the loop into `Runner`; `Engine` drives one
   runner. No behaviour change — existing tests stay green. *(foundation)*
2. **Crew as data + role toolsets.** `crew.go`, filtered registry views, role
   system prompts. Single-crew dispatch still sequential through today's stages.
3. **Parity pass.** Sequential verification before synthesis; `Verdict` on
   findings; "unverified" label. *(biggest quality win, no concurrency)*
4. **Missions (data + run).** `mission` package, JSON persistence, checkpoints,
   tasking, coverage + can't-run handling, starter missions. Terminal
   `/mission`.
5. **Desktop mission editor + run view.** Track UI, mission cards, provenance,
   new SSE events, avatars on cards.
6. **Shared notebook.** Notes board on `Investigation`; feed renames.
7. **Parallel crew.** Fan out independent steps (vuln reachability first);
   per-provider concurrency cap (Ollama defaults to 1).
8. **Experience.** Method notes, opt-in save, `/experience`, scoping; plus
   "save as mission".

Art cleanup (tracked separately, blocks shipping avatars): `hex.png`,
`parity.png`, `parity-dark.png` have a baked-in checkerboard (not real
transparency); all six source PNGs are ~1254px / ~0.5–1.2MB and need 128px
copies in `crew/` with originals moved to `docs/crew/`. Twine art still to come.

---

## 7. Open questions

- Parity after *every* step vs once before report — default once; expose toggle.
- Max concurrency per provider for milestone 7.
- Experience note format: free text vs light structure (source/entry/technique).

---

## 8. Status — what is built

All eight milestones are implemented. Where the build differs from the plan
above, it is noted here.

| # | Milestone | Where |
| --- | --- | --- |
| 1 | Runner refactor | `internal/agent/runner.go`; `Engine` embeds the captain's `Runner` |
| 2 | Crew as data + role toolsets | `internal/agent/crew.go`, `tools.Registry.View/Without/Merge` |
| 3 | Parity pass | `set_verdict` (crew.go), `Finding.Verdict/VerifiedBy`, `Investigation.Verification` |
| 4 | Missions (data + run) | `internal/mission`, `internal/agent/dispatch.go`, TUI `/mission`, `/missions`, `/crew`, `/skip` |
| 5 | Desktop editor + run view | `internal/serve/mission.go`, `web/index.html` (Mission button) |
| 6 | Shared notebook | `Investigation.Notes`, `add_note` / `read_notes` |
| 7 | Parallel crew | `Step.Parallel`, `Engine.stepGroup`, `Provider.Concurrency()` |
| 8 | Experience | `internal/experience`, TUI `/experience`, Desktop Mission → Experience |

Differences and things worth knowing:

- **`/investigate` runs the Default mission** — the crew is assembled after
  triage from whoever owns the loaded objectives, then Parity. `/mission solo`
  keeps the old single-agent run. An engine with no mission set behaves exactly
  as before (the pre-crew tests are unchanged, bar one struct literal).
- **Desktop does not use `Engine`.** Its chat loop is its own (`serve/agent.go`),
  so the Desktop mission runner drives that loop per step and shares the role
  data, crew tools, Parity brief and verification rule with the engine through
  the exports at the bottom of `crew.go`. There is no playbook triage in
  Desktop: objectives come from the generic malware playbook (or the vuln
  playbook for the target kind).
- **Checkpoints.** A saved mission's checkpoints are the ones placed on it; the
  session's autonomy only places them on the Default (auto) mission. In Desktop
  a checkpoint ends the stream and the run is resumed by id (state is kept in
  memory, so it does not survive a `binny --serve` restart).
- **Budget.** The session budget is the mission total, split evenly across the
  steps still to run (floor 15k; a step's own `TokenBudget` wins). In the
  terminal a step that uses its share pauses by name and can be extended or
  skipped; in Desktop, and for members of a parallel group, it wraps up and
  hands back what it has instead of pausing.
- **Parallel steps** can't ask the analyst questions or switch samples, and
  their text isn't streamed live — each member's lines arrive as a block.
  Open question 2 is answered by `maxConcurrency` on a provider (default 1 for
  local servers, 3 otherwise).
- **Parity** defaults to once, where it is placed; `verifyEachStep` is the
  toggle (open question 1). A step `model` of `provider/model` runs it on a
  different provider from the finders.
- **Experience** notes are free text (open question 3), scoped by project
  kind, mode, STIX types and role. A lesson that names an indicator, a hash, a
  sample-specific address, or says what "this sample" is, is refused at
  proposal, save and edit time. The crew proposes lessons on `LESSON:` lines in
  a debrief; nothing is saved until the analyst keeps it.
- **Art.** The avatars in `web/crew/` are 128px with real transparency
  (~14KB each); the 1254px originals and the script that regenerates the
  avatars are in `docs/crew/`. A member whose file is missing from `web/crew/`
  falls back to its initial in its accent ring (add the source PNG to
  `docs/crew/`, its name to `make-avatars.py`, and re-run the script).
- **Crew awareness and voice.** Every captain prompt (mission, solo, Q&A,
  Desktop chat) carries `CaptainCrewBrief()`: the roster, the rule that a crew
  name means the crew member (Dex is not the file format), and that BINNY only
  speaks for a crewmate from what they actually handed back. Every crew prompt
  carries the roster of its crewmates and who else is on the mission
  (`MissionCrewLine`). Each `Role` has a `Voice`; `voiceRule` keeps it to chat
  replies and debriefs — findings, IOCs, notes, verdict reasons and report
  sections stay plain.
- **Handoffs.** A debrief may end with `HANDOFF: <crewmate> — <what and
  where>` lines. They are lifted into `StepRecord.Handoffs` and put in front
  of that crewmate in its kickoff as leads (never evidence); the captain sees
  them under the debriefs.
- **Not persisted yet:** Desktop mission cards are not replayed from History
  (the report, the findings and their verdicts are).
