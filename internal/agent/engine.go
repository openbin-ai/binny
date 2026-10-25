package agent

import (
	"context"
	"fmt"
	"strings"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/llm"
	"openbin.ai/binny/internal/playbook"
	"openbin.ai/binny/internal/tools"
)

// Engine drives BINNY's phase state machine over a single conversation. It is
// stepped one provider round-trip at a time (Step), so the TUI can keep the
// loop off its own thread and surface progress incrementally, and ask_user
// suspends cleanly between steps.
type Engine struct {
	sess       *app.Session
	inv        *Investigation
	reg        *tools.Registry
	tb         *tools.Toolbox // read toolbox (nil in bare unit-test engines)
	provider   llm.Provider
	providerID string // id of the currently-built provider (rebuilt on /model switch)
	system     string

	messages []llm.Message
	stage    stage
	pbs      []playbook.Playbook
	briefed  map[stage]bool

	pending *pendingAsk

	streamSink func(string) // live text-delta sink (set by the UI)

	// budget
	maxTokens       int
	perTurnMax      int
	spentTokens     int
	cacheReadTokens int // cumulative cache-read (re-sent prefix served ~0.1x)
	rounds          int
	maxRounds       int
	triageNudges    int

	// collaborative-mode report shaping
	reportPrefs      string // analyst's audience/depth/tone answer (Collaborative)
	reportPrefsAsked bool   // interview already offered (ask once)

	synthDeadline int    // round number by which SYNTHESIZE must finish (0 = not set)
	capReason     string // set when paused on a spend cap ("rounds"|"tokens"|"synth"); cleared on ContinuePastCap

	// context compaction (in-place elision of stale tool results)
	compactThreshold int  // start compacting once message bytes exceed this
	compactedOnce    bool // whether the one-time "compaction on" notice has fired
}

const (
	// compactKeepRecent is how many trailing messages stay verbatim (~4 rounds);
	// the model may still be reasoning over these.
	compactKeepRecent = 8
	// compactMinElideBytes: only stub tool results bigger than this (small ones
	// are cheap and worth keeping intact).
	compactMinElideBytes = 500
	// defaultCompactThreshold ≈ 50k tokens of history (~4 bytes/token). Below it
	// we don't compact at all — full fidelity + better prompt caching.
	defaultCompactThreshold = 200_000
)

// Spend-cap extensions granted each time the analyst chooses to continue past a
// cap. Deliberately a chunk at a time (not unbounded) so runaway cost still
// requires a fresh, explicit "keep going" per chunk.
const (
	capRoundExtension = 12      // extra investigation rounds per continue
	capTokenExtension = 120_000 // extra token budget per continue (~one default budget)
	capSynthExtension = 8       // extra synthesis rounds per continue
)

// synthesisRounds is the round allowance SYNTHESIZE gets on top of wherever the
// investigation left off, so a run that exhausted its investigation budget can
// still WRITE the report instead of landing in REVIEW with an empty draft.
// Generous, because a deep report may re-read functions (to trace from main) and
// extract the config before writing several substantial sections.
const synthesisRounds = 16

type stage int

const (
	stageTriage stage = iota
	stageInvestigate
	stageSynthesize
	stageReview // conversational Q&A after the draft — full memory, no phase advance
	stageDone
)

// askKind distinguishes a model-issued ask_user (answer becomes a tool_result)
// from the engine's own Collaborative report interview (answer is stored, not
// sent as a tool result).
type askKind int

const (
	askTool        askKind = iota // resolves an ask_user tool call
	askReportPrefs                // Collaborative report-shaping interview
)

// pendingAsk holds the state needed to resume after a question: the question,
// the ask_user call's id, and any OTHER tool results from the same assistant
// turn that must be sent together with the analyst's answer (the API requires a
// result for every tool_use block in one user message).
type pendingAsk struct {
	kind         askKind
	question     string
	askToolID    string
	otherResults []llm.Block
}

// Line is one transcript entry the engine produces.
type Line struct {
	Kind string // binny | tool | sys | ok | err | phase
	Text string
}

// StepResult is the outcome of one Step.
type StepResult struct {
	Lines         []Line
	AwaitQuestion string // non-empty → the engine is suspended on ask_user
	TurnComplete  bool   // assistant finished a REVIEW turn; pause for analyst input
	Checkpoint    bool   // Supervised/Collaborative: paused at a phase boundary
	CapReached    string // hit a spend cap ("rounds"|"tokens"|"synth") — paused in place, offer continue/stop
	Refused       bool   // provider declined (safety); paused in place, switch model + retry
	Done          bool
	Err           error
}

// NewEngine builds an engine for a session + investigation + tool registry.
// Budgets are deliberately conservative for BYOK testing: ~120k tokens, 24
// rounds, 4k output/turn. Raise them once you trust a run.
func NewEngine(sess *app.Session, inv *Investigation, reg *tools.Registry, provider llm.Provider) *Engine {
	e := &Engine{
		sess: sess, inv: inv, reg: reg, provider: provider,
		system:           systemPrompt(sess.Mode, sess.Autonomy, sess.SamplePath != "", sess.Project.Kind),
		briefed:          map[stage]bool{},
		maxTokens:        sess.TokenBudget(), // per-project budget (Settings), default 120k
		perTurnMax:       4096,
		maxRounds:        24,
		compactThreshold: defaultCompactThreshold,
	}
	if sess.Provider != nil {
		e.providerID = sess.Provider.ID
		// A small window (local models) gets an earlier compaction point:
		// ~3 bytes per token leaves room for the system prompt, the tool
		// schemas and the reply, so the start of the history is elided by us
		// instead of being silently dropped by the server.
		if ct := sess.Provider.ContextTokens; ct > 0 && ct*3 < e.compactThreshold {
			e.compactThreshold = ct * 3
		}
	}
	return e
}

// ensureProvider rebuilds the LLM client when the session's provider changed
// (the analyst ran /model to switch), so a mid-session switch actually takes
// effect on the next turn.
func (e *Engine) ensureProvider() error {
	if e.sess.Provider == nil || e.sess.Provider.ID == e.providerID {
		return nil
	}
	p, err := llm.New(*e.sess.Provider)
	if err != nil {
		return err
	}
	e.provider = p
	e.providerID = e.sess.Provider.ID
	return nil
}

// SetStreamSink registers a callback that receives assistant text deltas as
// they stream in (the UI renders them live).
func (e *Engine) SetStreamSink(f func(string)) { e.streamSink = f }

// Toolbox exposes the read toolbox (for /switch, which re-points the read
// tools at another sample of a multi-sample project mid-session).
func (e *Engine) Toolbox() *tools.Toolbox { return e.tb }

// StreamLine pushes a progress line through the live stream sink — used by
// long-running tools (decompile_sample's Ghidra run) so the analyst sees
// progress mid-tool-call instead of a frozen spinner.
func (e *Engine) StreamLine(s string) {
	if e.streamSink != nil {
		e.streamSink("\n" + s)
	}
}

// Spent returns freshly-billed tokens so far (uncached input + cache writes +
// output across all turns). Cache reads are excluded — see CacheRead.
func (e *Engine) Spent() int { return e.spentTokens }

// CacheRead returns cumulative cache-read tokens — the conversation prefix
// re-served from cache at ~0.1x instead of re-billed. High values mean caching
// is doing its job.
func (e *Engine) CacheRead() int { return e.cacheReadTokens }

// Rounds returns (current round, cap).
func (e *Engine) Rounds() (int, int) { return e.rounds, e.maxRounds }

// Budget returns the token budget cap.
func (e *Engine) Budget() int { return e.maxTokens }

// SetBudget raises/lowers the token cap mid-session (Settings → token budget).
func (e *Engine) SetBudget(n int) {
	if n > 0 {
		e.maxTokens = n
	}
}

// Model returns the model id in use.
func (e *Engine) Model() string { return e.sess.Model }

// Phase returns the current app-level phase for display.
func (e *Engine) Phase() app.Phase {
	switch e.stage {
	case stageTriage:
		return app.PhaseTriage
	case stageInvestigate:
		return app.PhaseInvestigate
	case stageSynthesize:
		return app.PhaseSynthesize
	default:
		return app.PhaseReview
	}
}

// Start seeds the conversation and picks the opening stage. Malware mode starts
// in TRIAGE (classify → load playbook); vuln mode goes straight to the
// memory-safety playbook and INVESTIGATE.
func (e *Engine) Start() []Line {
	e.messages = []llm.Message{llm.UserText(triageKickoff(e.sess, nil))}
	if e.sess.Mode == app.ModeVuln {
		e.pbs = []playbook.Playbook{e.vulnPlaybook()}
		e.loadObjectives()
		e.stage = stageInvestigate
		return []Line{{Kind: "phase", Text: "TRIAGE skipped (vuln mode) — loaded playbook: " + e.pbs[0].Name}}
	}
	e.stage = stageTriage
	return []Line{{Kind: "phase", Text: "Phase: TRIAGE — classifying the sample"}}
}

// StartFromReport seeds a conversational REVIEW session on top of an EXISTING
// report instead of running the phase machine from scratch. The report's
// sections are loaded into the investigation as trusted prior analysis, the
// conversation is seeded with the report text + a continue brief, and the stage
// is set directly to REVIEW so the analyst can immediately direct BINNY (verify
// a section, recover a config, extend the work). No provider call is made here —
// nothing is spent until the analyst sends their first message.
func (e *Engine) StartFromReport(report *api.Report) []Line {
	sections := 0
	for _, s := range report.Sections {
		if strings.TrimSpace(s.Content) == "" {
			continue
		}
		e.inv.WriteSection(ReportSection{ID: s.ID, Title: s.Title, Content: s.Content})
		sections++
	}
	if report.MalwareType != "" {
		e.inv.SetClassification([]string{report.MalwareType}, "reported")
	}
	// Re-derive playbooks so write_report_section knows the section template if
	// BINNY extends the report; harmless if the classification doesn't map.
	if e.sess.Mode == app.ModeVuln {
		e.pbs = []playbook.Playbook{e.vulnPlaybook()}
	} else if len(e.inv.MalwareTypes) > 0 {
		e.pbs = playbook.SelectByTypes(e.inv.MalwareTypes)
	}
	e.messages = []llm.Message{llm.UserText(continueKickoff(e.sess, report))}
	e.stage = stageReview
	title := report.Title
	if strings.TrimSpace(title) == "" {
		title = e.sess.Project.Name
	}
	return []Line{{Kind: "ok", Text: fmt.Sprintf(
		"Loaded existing report %q (%d sections) as established. Phase: REVIEW — tell me what to verify, recover, or extend.",
		title, sections)}}
}

// StartQA seeds a conversational Q&A session on a project AT ITS CURRENT STATE,
// without running the triage→investigate→synthesize pipeline. The analyst asks
// questions, asks BINNY to verify a claim, build a proof-of-concept, or dig into
// a specific function; BINNY answers on demand with tools and grounds every
// claim. It never auto-drafts a report.
//
// A report may be supplied (report != nil) — it is loaded as the analyst's
// CLAIMS to check, NOT as trusted prior work (the skeptical posture is the
// whole point of "verify"; contrast StartFromReport, which trusts + extends).
// report may be nil (no report yet — pure exploration / a freshly-attached
// local binary). No provider call is made here; nothing is spent until the
// analyst asks something.
func (e *Engine) StartQA(report *api.Report) []Line {
	sections := 0
	if report != nil {
		for _, s := range report.Sections {
			if strings.TrimSpace(s.Content) == "" {
				continue
			}
			e.inv.WriteSection(ReportSection{ID: s.ID, Title: s.Title, Content: s.Content})
			sections++
		}
		if report.MalwareType != "" {
			e.inv.SetClassification([]string{report.MalwareType}, "reported")
		}
	}
	// Derive playbooks so write_report_section knows the section template if the
	// analyst later asks BINNY to record something; harmless otherwise.
	if e.sess.Mode == app.ModeVuln {
		e.pbs = []playbook.Playbook{e.vulnPlaybook()}
	} else if len(e.inv.MalwareTypes) > 0 {
		e.pbs = playbook.SelectByTypes(e.inv.MalwareTypes)
	}
	e.messages = []llm.Message{llm.UserText(qaKickoff(e.sess, report))}
	e.stage = stageReview
	if sections > 0 {
		return []Line{{Kind: "ok", Text: fmt.Sprintf(
			"Q&A mode — loaded the existing report (%d sections) as claims to check, not gospel. Ask me to verify something, build a PoC, or dig into a function.", sections)}}
	}
	return []Line{{Kind: "ok", Text: "Q&A mode — no report loaded; I'll answer from the sample as it stands. Ask about a function, ask me to verify a claim or build a PoC, or /sample <path> to point me at a local binary."}}
}

// Provide supplies the analyst's answer to a pending ask_user, resuming the
// loop on the next Step.
func (e *Engine) Provide(answer string) {
	if e.pending == nil {
		// No question outstanding — treat as a steering message.
		e.messages = append(e.messages, llm.UserText(answer))
		return
	}
	// Collaborative report interview: store the answer to shape the report; it
	// is not a tool result, so don't touch the message stream here.
	if e.pending.kind == askReportPrefs {
		e.reportPrefs = strings.TrimSpace(answer)
		e.pending = nil
		return
	}
	results := append([]llm.Block(nil), e.pending.otherResults...)
	results = append(results, llm.ToolResult(e.pending.askToolID, answer, false))
	e.messages = append(e.messages, llm.Message{Role: llm.RoleUser, Blocks: results})
	e.pending = nil
}

// Ask continues the SAME conversation with a follow-up from the analyst —
// preserving all memory. Used after the draft is ready (REVIEW) or to resume
// after an interrupt. It never restarts the phase machine.
//
// Alternation safety: if the last message is already a user turn (e.g. an
// interrupted turn left an unanswered brief/tool_result), the new text is
// merged into it as an extra text block rather than appended as a second
// consecutive user message (which the Messages API rejects).
func (e *Engine) Ask(text string) {
	if e.stage == stageDone {
		e.stage = stageReview
	}
	e.appendUser(text)
}

// appendUser adds a user-role text turn, merging into a trailing user message
// when there already is one (the Messages API rejects two consecutive user
// turns — this happens when checkpoint steering is followed by a stage brief).
func (e *Engine) appendUser(text string) {
	n := len(e.messages)
	if n > 0 && e.messages[n-1].Role == llm.RoleUser {
		e.messages[n-1].Blocks = append(e.messages[n-1].Blocks, llm.TextBlock(text))
		return
	}
	e.messages = append(e.messages, llm.UserText(text))
}

// Started reports whether Start has seeded the conversation.
func (e *Engine) Started() bool { return len(e.messages) > 0 }

// Stop wraps up the current phase (analyst-initiated /stop, or "stop" chosen at
// a spend-cap pause). From investigation it forces synthesis; from synthesis it
// finalizes to REVIEW with the current draft. It clears any cap pause.
func (e *Engine) Stop() []Line {
	e.capReason = ""
	switch e.stage {
	case stageTriage, stageInvestigate:
		e.stage = stageSynthesize
		e.synthDeadline = e.rounds + synthesisRounds
		return []Line{{Kind: "phase", Text: "Stopping investigation — moving to SYNTHESIZE"}}
	case stageSynthesize:
		e.stage = stageReview
		return []Line{{Kind: "phase", Text: "Finalizing — moving to REVIEW with the current draft."}}
	}
	return nil
}

// ContinuePastCap extends whichever spend cap paused the loop and clears the
// pause so the next Step keeps going. Each call grants one more chunk — the
// analyst re-authorizes the spend every time, so cost can't run away silently.
func (e *Engine) ContinuePastCap() []Line {
	switch e.capReason {
	case "rounds":
		e.maxRounds += capRoundExtension
		e.capReason = ""
		return []Line{{Kind: "ok", Text: fmt.Sprintf(
			"Continuing investigation: +%d rounds (cap now %d). This spends more of your BYOK tokens.", capRoundExtension, e.maxRounds)}}
	case "tokens":
		e.maxTokens += capTokenExtension
		e.capReason = ""
		return []Line{{Kind: "ok", Text: fmt.Sprintf(
			"Continuing: token budget +%dk (cap now ~%dk). This spends more of your BYOK tokens.", capTokenExtension/1000, e.maxTokens/1000)}}
	case "synth":
		e.synthDeadline += capSynthExtension
		e.capReason = ""
		return []Line{{Kind: "ok", Text: fmt.Sprintf(
			"Continuing synthesis: +%d rounds. This spends more of your BYOK tokens.", capSynthExtension)}}
	}
	return nil
}

// CapReason reports which spend cap paused the loop ("rounds"|"tokens"|"synth"),
// or "" if not paused — used to render the right disclaimer after a resume.
func (e *Engine) CapReason() string { return e.capReason }

// Step performs one provider round-trip, runs any tool calls, and advances the
// phase machine. The TUI calls Step repeatedly until Done or AwaitQuestion.
func (e *Engine) Step(ctx context.Context) StepResult {
	if e.stage == stageDone {
		return StepResult{Done: true}
	}
	if e.pending != nil {
		return StepResult{AwaitQuestion: e.pending.question}
	}
	// Give SYNTHESIZE its own round allowance the moment we enter it, so the
	// investigation cap/budget can't leave the report unwritten.
	if e.stage == stageSynthesize && e.synthDeadline == 0 {
		e.synthDeadline = e.rounds + synthesisRounds
	}
	// Collaborative: on entering synthesis, interview the analyst on report
	// shape (audience/depth/tone) once, before writing any sections.
	if e.stage == stageSynthesize && e.sess.Autonomy == app.Collaborative && !e.reportPrefsAsked {
		e.reportPrefsAsked = true
		q := reportInterview
		e.pending = &pendingAsk{kind: askReportPrefs, question: q}
		return StepResult{AwaitQuestion: q, Lines: []Line{{Kind: "binny", Text: q}}}
	}
	// Spend caps PAUSE the automated loop in place (stage unchanged) and hand the
	// analyst the choice — ContinuePastCap to extend and keep going, or Stop to
	// wrap up — rather than silently truncating the analysis. This applies in
	// every autonomy mode: a hard budget limit is about money, not phase flow.
	// (The analyst-paced REVIEW stage has no caps.)
	switch e.stage {
	case stageSynthesize:
		// Only cap synthesis on ITS own allowance — never the shared investigation
		// cap, which is usually already reached by now.
		if e.rounds >= e.synthDeadline {
			e.capReason = "synth"
			return StepResult{CapReached: "synth", Lines: []Line{{Kind: "phase", Text: "Synthesis round budget reached — the draft may be incomplete."}}}
		}
	case stageTriage, stageInvestigate:
		if e.rounds >= e.maxRounds {
			e.capReason = "rounds"
			return StepResult{CapReached: "rounds", Lines: []Line{{Kind: "phase", Text: fmt.Sprintf("Round cap reached (%d rounds) — analysis paused, not finished.", e.maxRounds)}}}
		}
		if e.stage == stageInvestigate && e.spentTokens >= e.maxTokens {
			e.capReason = "tokens"
			return StepResult{CapReached: "tokens", Lines: []Line{{Kind: "phase", Text: fmt.Sprintf("Token budget reached (~%dk) — analysis paused, not finished.", e.spentTokens/1000)}}}
		}
	}

	if err := e.ensureProvider(); err != nil {
		return StepResult{Err: err}
	}

	var lines []Line
	lines = append(lines, e.ensureBrief()...)
	lines = append(lines, e.compact()...) // trim stale tool output before re-sending

	e.rounds++
	req := llm.Request{
		System:    e.system,
		Messages:  e.messages,
		Tools:     e.reg.Defs(),
		Model:     e.sess.Model,
		MaxTokens: e.perTurnMax,
	}
	streamed := false
	sink := func(s string) {
		if e.streamSink != nil {
			streamed = true
			e.streamSink(s)
		}
	}
	resp, err := e.provider.Stream(ctx, req, sink)
	if err != nil {
		return StepResult{Err: err, Lines: lines}
	}
	// Budget on freshly-billed tokens only: uncached input + cache writes +
	// output. Cache READS (the re-sent conversation prefix) are ~0.1x and are
	// tracked separately — counting them here would defeat the point of caching
	// and burn the budget on context the model already paid to store.
	e.spentTokens += resp.Usage.InputTokens + resp.Usage.CacheCreationTokens + resp.Usage.OutputTokens
	e.cacheReadTokens += resp.Usage.CacheReadTokens

	if resp.StopReason == llm.StopRefusal {
		// Don't append the refusal or advance the phase — keep the analyst's
		// place. The same context re-sent to the same model will refuse again,
		// so guide them to switch provider (or rephrase) and continue.
		lines = append(lines, Line{Kind: "err", Text: fmt.Sprintf(
			"%s declined this (safety classifier — malware RE can trip Claude's cyber safeguards). Your place is kept. Options: /model to a non-Claude provider (e.g. openai, deepseek), then type to continue; or /stop to synthesize with what's gathered so far.",
			e.sess.Model)})
		return StepResult{Lines: lines, Refused: true}
	}

	// Only add the text as a transcript line when it wasn't streamed live (the
	// UI already rendered streamed text). Non-streaming providers still surface.
	if txt := strings.TrimSpace(resp.Text()); txt != "" && !streamed {
		lines = append(lines, Line{Kind: "binny", Text: txt})
	}
	e.messages = append(e.messages, resp.AsMessage())

	calls := resp.ToolCalls()
	if len(calls) == 0 {
		// Model ended its turn without tools → phase transition or pause.
		before := e.stage
		lines = append(lines, e.advanceStage()...)
		switch e.stage {
		case stageDone:
			return StepResult{Lines: lines, Done: true}
		case stageReview:
			return StepResult{Lines: lines, TurnComplete: true}
		default:
			// Supervised/Collaborative pause at a real phase boundary for review.
			return StepResult{Lines: lines, Checkpoint: e.crossedBoundary(before)}
		}
	}

	// Run tool calls, collecting results into one user message. If ask_user is
	// among them, suspend after running the others.
	var results []llm.Block
	var ask *llm.ToolCall
	for i := range calls {
		c := calls[i]
		if c.Name == AskUserToolName {
			ask = &calls[i]
			continue
		}
		lines = append(lines, Line{Kind: "tool", Text: toolCallLabel(c)})
		out, isErr := e.reg.Run(ctx, c.Name, c.Input)
		kind := "tool"
		if isErr {
			kind = "err"
		}
		lines = append(lines, Line{Kind: kind, Text: toolResultLabel(c.Name, out)})
		results = append(results, llm.ToolResult(c.ID, out, isErr))
	}

	if ask != nil {
		q := QuestionFromAskUser(ask.Input)
		e.pending = &pendingAsk{kind: askTool, question: q, askToolID: ask.ID, otherResults: results}
		// Only surface the question as its own line when the assistant didn't
		// already write it as preamble text (models usually do) — otherwise it
		// shows twice.
		if strings.TrimSpace(resp.Text()) == "" {
			lines = append(lines, Line{Kind: "binny", Text: q})
		}
		return StepResult{Lines: lines, AwaitQuestion: q}
	}

	e.messages = append(e.messages, llm.Message{Role: llm.RoleUser, Blocks: results})

	// If TRIAGE just produced a classification, load the playbook and advance.
	if e.stage == stageTriage && len(e.inv.MalwareTypes) > 0 {
		before := e.stage
		lines = append(lines, e.advanceStage()...)
		return StepResult{Lines: lines, Checkpoint: e.crossedBoundary(before)}
	}
	return StepResult{Lines: lines}
}

// checkpointing reports whether the mode pauses at phase boundaries.
func (e *Engine) checkpointing() bool { return e.sess.Autonomy != app.Autonomous }

// crossedBoundary reports whether a real phase transition just happened AND the
// mode wants to pause on it (Supervised/Collaborative). Transitions into REVIEW
// or DONE are handled by TurnComplete/Done, not this.
func (e *Engine) crossedBoundary(before stage) bool {
	return e.checkpointing() && e.stage != before &&
		e.stage != stageReview && e.stage != stageDone
}

// messagesBytes estimates the conversation size (chars ≈ 4× tokens).
func (e *Engine) messagesBytes() int {
	n := 0
	for _, m := range e.messages {
		for _, b := range m.Blocks {
			n += len(b.Text) + len(b.Content) + len(b.Input)
		}
	}
	return n
}

// compact bounds the re-sent context by stubbing the CONTENT of stale, large
// tool_result blocks (everything except the last compactKeepRecent messages and
// the opening kickoff). It edits content in place — tool_use/tool_result pairing
// and user/assistant alternation are untouched — so it's safe for the Messages
// API. Conclusions live in the Investigation, so the raw output is disposable;
// the model can re-run a tool if it truly needs the detail again. No-op until the
// history crosses compactThreshold (short runs stay pristine + cache well).
func (e *Engine) compact() []Line {
	if e.messagesBytes() < e.compactThreshold {
		return nil
	}
	cut := len(e.messages) - compactKeepRecent
	if cut <= 1 { // keep messages[0] (kickoff) + the recent tail
		return nil
	}
	elided, saved := 0, 0
	for i := 1; i < cut; i++ {
		for j := range e.messages[i].Blocks {
			b := &e.messages[i].Blocks[j]
			if b.Kind == llm.BlockToolResult && len(b.Content) > compactMinElideBytes {
				saved += len(b.Content)
				b.Content = fmt.Sprintf("[output elided to save context — %d chars; conclusions are recorded. Re-run the tool if you need the detail again.]", len(b.Content))
				elided++
			}
		}
	}
	if elided == 0 || e.compactedOnce {
		return nil
	}
	e.compactedOnce = true
	return []Line{{Kind: "sys", Text: fmt.Sprintf(
		"Context compaction: trimmed %d older tool result(s) (~%dk chars) to keep this run affordable — your scrollback is unchanged and all findings are preserved.",
		elided, saved/1000)}}
}

// ensureBrief injects the stage's instruction message the first time we enter
// that stage.
func (e *Engine) ensureBrief() []Line {
	if e.briefed[e.stage] {
		return nil
	}
	e.briefed[e.stage] = true
	switch e.stage {
	case stageInvestigate:
		if len(e.pbs) == 0 { // safety: no playbook yet
			return nil
		}
		e.appendUser(investigateBrief(e.pbs, e.inv.Snapshot().Objectives, e.sess.Project.Kind, e.sess.Mode, e.sess.VulnFocus))
	case stageSynthesize:
		brief := synthesizeBrief(e.sess.Mode, e.pbs, e.inv.Snapshot())
		if e.reportPrefs != "" {
			brief += "\n\n★ ANALYST REPORT DIRECTIVE — AUTHORITATIVE, overrides the default structure/tone/depth above. Match the title, audience, depth, and tone exactly as specified; if they asked for deep technical detail, err on the side of MORE detail and longer prose:\n" + e.reportPrefs
		}
		e.appendUser(brief)
	}
	return nil
}

// advanceStage moves triage→investigate→synthesize→done, injecting the next
// brief and returning transcript lines describing the transition.
func (e *Engine) advanceStage() []Line {
	switch e.stage {
	case stageTriage:
		if len(e.inv.MalwareTypes) == 0 {
			// Model ended triage without classifying — nudge once, then default.
			e.triageNudges++
			if e.triageNudges <= 1 {
				e.messages = append(e.messages, llm.UserText(
					"You haven't called set_classification yet. Classify the sample now with one or more STIX malware types (use \"unknown\" if you truly can't tell)."))
				return []Line{{Kind: "sys", Text: "Nudging for a classification…"}}
			}
			e.inv.SetClassification([]string{"unknown"}, "low")
		}
		e.pbs = playbook.SelectByTypes(e.inv.MalwareTypes)
		e.loadObjectives()
		e.stage = stageInvestigate
		names := make([]string, 0, len(e.pbs))
		for _, pb := range e.pbs {
			names = append(names, pb.Name)
		}
		return []Line{{Kind: "phase", Text: fmt.Sprintf("Classified as %s → playbook(s): %s. Phase: INVESTIGATE",
			strings.Join(e.inv.MalwareTypes, ", "), strings.Join(names, ", "))}}
	case stageInvestigate:
		c, t := e.inv.Coverage()
		e.stage = stageSynthesize
		return []Line{{Kind: "phase", Text: fmt.Sprintf("Investigation complete (%d/%d objectives). Phase: SYNTHESIZE", c, t)}}
	case stageSynthesize:
		e.stage = stageReview
		snap := e.inv.Snapshot()
		return []Line{{Kind: "ok", Text: fmt.Sprintf("Draft ready: %d sections, %d findings, %d IOCs. Phase: REVIEW — ask me anything, /draft to view, /save to push.",
			len(snap.Sections), len(snap.Findings), len(snap.IOCs))}}
	case stageReview:
		// Conversational turn finished — stay in review, pause for the analyst.
		return nil
	}
	return nil
}

// vulnPlaybook returns the session's vuln playbook — scoped to the focused
// classes when /focus (or /mode vuln <class>) set any, else the generic one.
func (e *Engine) vulnPlaybook() playbook.Playbook { return vulnPlaybookForSession(e.sess) }

// vulnPlaybookForSession is the free-function form (used from RestoreEngine).
func vulnPlaybookForSession(sess *app.Session) playbook.Playbook {
	kind := string(sess.Project.Kind)
	if len(sess.VulnFocus) > 0 {
		pb, _ := playbook.VulnPlaybookForFocus(kind, sess.VulnFocus)
		return pb
	}
	return playbook.VulnPlaybookFor(kind)
}

func (e *Engine) loadObjectives() {
	var objs []Objective
	seen := map[string]bool{}
	for _, pb := range e.pbs {
		for _, o := range pb.Objectives {
			if seen[o.ID] {
				continue
			}
			seen[o.ID] = true
			objs = append(objs, Objective{ID: o.ID, Desc: o.Desc})
		}
	}
	e.inv.SetObjectives(objs)
}

func toolCallLabel(c llm.ToolCall) string {
	in := strings.TrimSpace(string(c.Input))
	if in == "" || in == "{}" {
		return c.Name + "()"
	}
	return c.Name + " " + api.Abbrev(in, 120)
}

func toolResultLabel(name, out string) string {
	first := out
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		first = out[:i] + " …"
	}
	return "→ " + api.Abbrev(first, 160)
}
