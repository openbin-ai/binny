package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"openbin.ai/binny/internal/agent"
	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/playbook"
	"openbin.ai/binny/internal/store"
)

// agentStepMsg carries the result of one engine.Step (run off the UI thread).
type agentStepMsg struct{ res agent.StepResult }

// agentDeltaMsg carries a streamed assistant text delta, pushed from the loop
// goroutine via p.Send.
type agentDeltaMsg struct{ text string }

// requestStart validates preconditions and asks the analyst to confirm the
// token spend before the loop begins. The note becomes opening intel.
func (m *Model) requestStart(note string) {
	if m.sess.Project == nil {
		m.append(errLine("No project attached — /project to pick one."))
		return
	}
	m.applyDetectedIntent(note)
	if !m.sess.Project.Ready() {
		m.append(errLine(fmt.Sprintf("Project status is %s — needs READY. Decompile it first.", m.sess.Project.Status)))
		return
	}
	if !m.sess.ProviderReady() {
		m.append(errLine("No LLM key for the active provider — /key to set one (BYOK)."))
		return
	}
	m.pendingStartNote = note
	m.confirmStart = true
	prov := "(provider)"
	if m.sess.Provider != nil {
		prov = m.sess.Provider.ID
	}
	m.append(warnLine(fmt.Sprintf(
		"⚠ Starting BINNY spends YOUR %s/%s API tokens (budget ~120k tokens, up to 24 rounds; each round resends the conversation, so cost grows). Type y to start, anything else to cancel.",
		prov, m.sess.Model)))
}

// startAgentNow builds + starts the engine (first run only) and begins stepping.
func (m *Model) startAgentNow(note string) tea.Cmd {
	if m.engine == nil {
		eng, inv, err := agent.Build(m.sess, m.sess.API)
		if err != nil {
			m.append(errLine("Couldn't start BINNY: " + err.Error()))
			return nil
		}
		m.engine, m.inv = eng, inv
		// Stream text deltas from the loop goroutine into the UI.
		prog := m.program
		m.engine.SetStreamSink(func(s string) {
			if prog != nil {
				prog.Send(agentDeltaMsg{text: s})
			}
		})
	}
	m.append(m.toLines(m.engine.Start())...)
	m.engineStarted = true
	if strings.TrimSpace(note) != "" {
		m.engine.Ask(note) // fold the opening note into the conversation
	}
	return m.beginRun()
}

// resumePastCap extends the tripped spend cap and continues the loop, optionally
// folding in analyst steering. Called when the analyst chooses to keep going at a
// cap pause (Enter, /continue, or a typed message).
func (m *Model) resumePastCap(steer string) tea.Cmd {
	if m.engine == nil {
		return nil
	}
	m.append(m.toLines(m.engine.ContinuePastCap())...)
	m.capPaused = false
	if strings.TrimSpace(steer) != "" {
		m.engine.Ask(steer)
	}
	return m.beginRun()
}

// beginRun opens a fresh cancelable context for this activation and returns the
// first step command.
func (m *Model) beginRun() tea.Cmd {
	ctx, cancel := context.WithCancel(context.Background())
	m.runCancel = cancel
	m.agentRunning = true
	m.reviewIdle = false
	m.awaiting = false
	m.checkpoint = false
	m.capPaused = false
	m.follow = true // snap back to the live tail when a run (re)starts
	if m.engine != nil {
		m.sess.Phase = m.engine.Phase()
	}
	// Batch the first step with the spinner tick so "working…" animates during
	// the (multi-second) model round-trips.
	return tea.Batch(m.spinner.Tick, m.stepCmd(ctx))
}

// stepCmd runs one engine step off the UI thread against ctx.
func (m *Model) stepCmd(ctx context.Context) tea.Cmd {
	eng := m.engine
	return func() tea.Msg {
		return agentStepMsg{res: eng.Step(ctx)}
	}
}

// continueCmd re-issues a step on the same run context (mid-loop).
func (m *Model) continueCmd() tea.Cmd {
	ctx, cancel := context.WithCancel(context.Background())
	m.runCancel = cancel
	return m.stepCmd(ctx)
}

// handleAgentStep applies a step result and decides what happens next.
func (m *Model) handleAgentStep(res agent.StepResult) (tea.Model, tea.Cmd) {
	// Commit any streamed assistant text as a transcript line (ordered before
	// this step's tool/phase lines).
	if m.streaming != "" {
		m.append(binnyLine(m.streaming))
		m.streaming = ""
	}
	m.append(m.toLines(res.Lines)...)
	if m.engine != nil {
		m.sess.Phase = m.engine.Phase()
	}

	switch {
	case res.Err != nil:
		if m.interrupted || errors.Is(res.Err, context.Canceled) {
			m.interrupted = false
			m.agentRunning = false
			m.reviewIdle = true
			m.append(warnLine("Paused. Type to continue the conversation, /draft to view, or /stop to synthesize."))
			return m, nil
		}
		m.append(errLine("BINNY error: " + res.Err.Error()))
		if h := errorHint(res.Err.Error()); h != "" {
			m.append(sysLine(h))
		}
		m.agentRunning = false
		m.reviewIdle = m.engineStarted // keep place: /model to another provider + type to resume
		return m, nil
	case res.Refused:
		// Paused in place (phase unchanged). The analyst can /model to another
		// provider and type to continue, or /stop to synthesize.
		m.agentRunning = false
		m.reviewIdle = true
		return m, nil
	case res.AwaitQuestion != "":
		m.awaiting = true // BINNY is waiting on the analyst; input answers it
		m.agentRunning = false
		return m, nil
	case res.Checkpoint:
		// Supervised/Collaborative pause at a phase boundary. Typing steers;
		// empty Enter or /continue proceeds.
		m.agentRunning = false
		m.checkpoint = true
		m.reviewIdle = true
		m.append(warnLine("⏸ Checkpoint (" + app.AutonomyLabel(m.sess.Autonomy) + ") — review above. Type to steer, or press Enter / /continue to proceed."))
		return m, nil
	case res.CapReached != "":
		// Hit a spend cap — pause and let the analyst decide, rather than
		// truncating the analysis. Enter / /continue extends and keeps going;
		// typing steers + continues; /stop wraps up.
		m.agentRunning = false
		m.capPaused = true
		m.reviewIdle = true
		m.append(warnLine(capDisclaimer(res.CapReached)))
		return m, nil
	case res.TurnComplete:
		m.agentRunning = false
		m.reviewIdle = true // conversational: free text is a follow-up
		return m, nil
	case res.Done:
		m.agentRunning = false
		m.reviewIdle = true
		return m, nil
	default:
		return m, m.continueCmd() // keep stepping
	}
}

// capDisclaimer is the pause message shown when a spend cap is hit — it states
// plainly that the analysis is NOT finished and that continuing costs more.
func capDisclaimer(reason string) string {
	switch reason {
	case "tokens":
		return "⏸ Token budget reached — analysis PAUSED, not finished. Press Enter or /continue to extend the budget and keep investigating (this spends more of YOUR BYOK tokens), type guidance to steer + continue, or /stop to wrap up and synthesize the report now."
	case "synth":
		return "⏸ Synthesis budget reached — the draft may be INCOMPLETE. Press Enter or /continue to keep writing (this spends more of YOUR BYOK tokens), or /stop to finalize with the current draft."
	default: // rounds
		return "⏸ Round cap reached — analysis PAUSED, not finished. Press Enter or /continue to keep investigating (this spends more of YOUR BYOK tokens), type guidance to steer + continue, or /stop to wrap up and synthesize the report now."
	}
}

// errorHint turns a raw provider error into an actionable one-liner. Your
// place is kept, so any of these can be followed by /model to switch provider
// and typing to resume.
func errorHint(err string) string {
	e := strings.ToLower(err)
	switch {
	case strings.Contains(e, "insufficient_quota"), strings.Contains(e, "exceeded your current quota"), strings.Contains(e, "billing"):
		return "→ That provider's account has no credits/quota. Add billing on the provider's side, or /model to switch to one with credits (e.g. deepseek). Your place is kept."
	case strings.Contains(e, "status 429"), strings.Contains(e, "rate limit"):
		return "→ Rate-limited by the provider. Wait a moment and type to retry, or /model to switch. Your place is kept."
	case strings.Contains(e, "status 401"), strings.Contains(e, "invalid_api_key"), strings.Contains(e, "authentication"):
		return "→ The API key was rejected. Run /key to re-enter it (or /model to switch provider)."
	case strings.Contains(e, "no key"):
		return "→ /key to set a key for this provider, or /model to switch."
	case strings.Contains(e, "connection refused"), strings.Contains(e, "no such host"):
		return "→ Couldn't reach the provider's server. For a local model, start it first (ollama serve, or LM Studio's server tab) and check /endpoint. Your place is kept."
	case strings.Contains(e, "does not support tools"), strings.Contains(e, "tool use is not supported"), strings.Contains(e, "tools are not supported"):
		return "→ This model can't call tools, and BINNY works through tools. Pick a tool-capable model (/model): qwen3, gpt-oss, llama3.1+, mistral-nemo, devstral. Your place is kept."
	case strings.Contains(e, "model") && strings.Contains(e, "not found"):
		return "→ The server doesn't have that model. Pull it first (ollama pull <model>) or /model to pick one it lists."
	default:
		return ""
	}
}

// toLines maps engine lines to transcript lines.
func (m *Model) toLines(els []agent.Line) []line {
	out := make([]line, 0, len(els))
	for _, el := range els {
		switch el.Kind {
		case "binny":
			out = append(out, binnyLine(el.Text))
		case "tool":
			out = append(out, toolLine(el.Text))
		case "ok":
			out = append(out, okLine(el.Text))
		case "err":
			out = append(out, errLine(el.Text))
		case "phase":
			out = append(out, warnLine(el.Text))
		default:
			out = append(out, sysLine(el.Text))
		}
	}
	return out
}

// --- agent-related slash handlers -----------------------------------------

func (m *Model) cmdStop() tea.Cmd {
	if m.engine == nil {
		m.append(sysLine("Nothing running."))
		return nil
	}
	m.capPaused = false
	m.append(m.toLines(m.engine.Stop())...)
	// Stop from synthesis finalizes to REVIEW — don't kick off another step
	// (review is analyst-paced; a run would just spend a round doing nothing).
	if m.engine.Phase() == app.PhaseReview {
		m.reviewIdle = true
		m.checkpoint = false
		return nil
	}
	if m.awaiting {
		m.awaiting = false
		m.engine.Provide("(analyst asked to stop and synthesize)")
		return m.beginRun()
	}
	if !m.agentRunning {
		return m.beginRun()
	}
	return nil
}

func (m *Model) cmdDraft() {
	if m.inv == nil {
		m.append(sysLine("No investigation yet — type a message or /investigate to start."))
		return
	}
	snap := m.inv.Snapshot()
	if len(snap.Sections) == 0 {
		m.append(sysLine("No draft sections yet (they appear once BINNY reaches SYNTHESIZE)."))
		return
	}
	m.append(sysLine("── DRAFT REPORT ──"))
	for _, s := range snap.Sections {
		m.append(binnyLine("# " + s.Title))
		m.append(sysLine(s.Content))
	}
}

func (m *Model) cmdFindings() {
	if m.inv == nil {
		m.append(sysLine("No investigation yet."))
		return
	}
	snap := m.inv.Snapshot()
	m.append(sysLine(snap.EvidenceSummary()))
	m.append(sysLine("Coverage: " + snap.CoverageLine()))
}

// cmdSample attaches a local raw binary to the session so the extraction
// sandbox (write_file/run/read_artifact) can operate on it. It takes effect
// immediately, mid-run — the sandbox reads the path lazily on next use.
func (m *Model) cmdSample(path string) {
	path = expandHome(strings.Trim(path, `"'`))
	info, err := os.Stat(path)
	if err != nil {
		m.append(errLine("Can't attach sample: " + err.Error()))
		return
	}
	if info.IsDir() {
		m.append(errLine("That's a directory — point /sample at the raw binary file itself."))
		return
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	m.sess.SamplePath = abs
	m.append(okLine(fmt.Sprintf("Sample attached: %s (%d bytes). Active extraction is now enabled.", abs, info.Size())))
	if m.engineStarted && m.reviewIdle {
		m.append(sysLine("Ask BINNY to extract the config/blob now — e.g. \"extract the encrypted config\"."))
	}
}

// cmdAutonomy shows or sets the autonomy mode mid-session.
func (m *Model) cmdAutonomy(fields []string) {
	if len(fields) < 2 {
		m.append(sysLine(fmt.Sprintf("Autonomy: %s. Usage: /autonomy autonomous | supervised | collaborative",
			app.AutonomyLabel(m.sess.Autonomy))))
		return
	}
	switch strings.ToLower(fields[1]) {
	case "autonomous", "auto", "a", "1":
		m.sess.Autonomy = app.Autonomous
	case "supervised", "super", "s", "2":
		m.sess.Autonomy = app.Supervised
	case "collaborative", "collab", "c", "3":
		m.sess.Autonomy = app.Collaborative
	default:
		m.append(errLine("Unknown mode — use autonomous, supervised, or collaborative."))
		return
	}
	m.append(okLine("Autonomy → " + app.AutonomyLabel(m.sess.Autonomy) + ". Pausing behavior applies from the next round; report-shaping applies at synthesis."))
}

// hasUnrecoveredConfig reports whether the investigation flagged encrypted/
// encoded config or crypto but hasn't produced a decrypted artifact yet — used
// to nudge extraction when a sample is attached late.
func (m *Model) hasUnrecoveredConfig() bool {
	if m.inv == nil {
		return false
	}
	snap := m.inv.Snapshot()
	for _, a := range snap.Artifacts {
		if a.Kind == "decrypted" {
			return false // already recovered something
		}
	}
	for _, f := range snap.Findings {
		s := strings.ToLower(f.Category + " " + f.Note)
		for _, kw := range []string{"config", "encrypt", "xor", "crypto", "rc4", "obfusc", "encoded", "packed"} {
			if strings.Contains(s, kw) {
				return true
			}
		}
	}
	return false
}

// maybeAttachSample scans free-text input for a path to a real file and, if the
// session has no sample attached yet, attaches it automatically — so replying to
// "attach the raw sample" with the path just works (no /sample needed). Returns
// the absolute path when it attached, else "".
func (m *Model) maybeAttachSample(text string) string {
	if m.sess.SamplePath != "" {
		return "" // already have one
	}
	p := detectFilePath(text)
	if p == "" {
		return ""
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}
	m.sess.SamplePath = abs
	sz := int64(0)
	if info, err := os.Stat(abs); err == nil {
		sz = info.Size()
	}
	m.append(okLine(fmt.Sprintf("Detected a file path in your message — attached %s (%d bytes) as the sample. Active extraction is now enabled.", abs, sz)))
	return abs
}

// detectFilePath returns the first whitespace-delimited token in text that looks
// like a path and resolves to an existing regular file (~ expanded).
func detectFilePath(text string) string {
	for _, tok := range strings.Fields(text) {
		tok = strings.Trim(tok, `"'`+"`,")
		if !looksPathish(tok) {
			continue
		}
		p := expandHome(tok)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

// looksPathish is a cheap filter so we only os.Stat tokens that could be paths
// (contain a separator or a ~/. prefix) — not every word in a sentence.
func looksPathish(s string) bool {
	return strings.HasPrefix(s, "~") || strings.Contains(s, "/") || strings.ContainsRune(s, filepath.Separator)
}

// cmdBudget shows or sets the active project's per-run token budget.
func (m *Model) cmdBudget(fields []string) {
	if m.sess.Project == nil {
		m.append(errLine("No project attached — /project to pick one first."))
		return
	}
	if len(fields) < 2 {
		m.append(sysLine(fmt.Sprintf("Token budget for %s: %s (default %s). Set with /budget <n> (e.g. /budget 200k), or /settings.",
			m.sess.Project.Name, humanTokens(m.sess.TokenBudget()), humanTokens(config.DefaultTokenBudget))))
		return
	}
	n, ok := parseBudget(fields[1])
	if !ok {
		m.append(errLine("Invalid budget — use a number like 120000 or 150k."))
		return
	}
	m.applyBudget(n)
	m.append(okLine(fmt.Sprintf("Token budget for %s → %s (applies to the current run and future sessions).",
		m.sess.Project.Name, humanTokens(n))))
}

func (m *Model) cmdSampleStatus() {
	if m.sess.SamplePath == "" {
		m.append(sysLine("No sample attached. Extraction (decrypt configs, carve blobs) needs the raw binary:"))
		m.append(sysLine("  /sample <path>   attach the local file you ran `openbin` on"))
		return
	}
	m.append(sysLine("Sample: " + m.sess.SamplePath))
}

// expandHome resolves a leading ~ to the user's home directory.
func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

func (m *Model) cmdSave() {
	if m.inv == nil || m.sess.Project == nil {
		m.append(errLine("Nothing to save."))
		return
	}
	snap := m.inv.Snapshot()
	if len(snap.Sections) == 0 {
		m.append(errLine("No draft sections to save."))
		return
	}
	sections := make([]api.ReportSection, 0, len(snap.Sections))
	for _, s := range snap.Sections {
		sections = append(sections, api.ReportSection{ID: s.ID, Title: s.Title, Content: s.Content})
	}
	title := "BINNY draft — " + m.sess.Project.Name

	// Local project: there's no backend report — save markdown into the local
	// analysis store next to the analysis blob.
	if m.sess.Project.IsLocal() {
		path, err := store.ReportPath(m.sess.Project.Sha256)
		if err != nil {
			m.append(errLine("Save failed: " + err.Error()))
			return
		}
		var md strings.Builder
		md.WriteString("# " + title + "\n")
		for _, s := range sections {
			md.WriteString("\n## " + s.Title + "\n\n" + s.Content + "\n")
		}
		if err := os.WriteFile(path, []byte(md.String()), 0o644); err != nil {
			m.append(errLine("Save failed: " + err.Error()))
			return
		}
		m.append(okLine(fmt.Sprintf("Saved %d sections to %s (local project — no backend report).", len(sections), path)))
		return
	}

	if _, err := m.sess.API.UpdateReport(m.sess.Project.ID, api.UpdateReportRequest{
		Title: title, Sections: sections,
	}); err != nil {
		m.append(errLine("Save failed: " + err.Error()))
		return
	}
	m.append(okLine(fmt.Sprintf("Saved %d sections to the project report (DRAFT — review before publishing).", len(sections))))
}

// applyDetectedIntent reads the analyst's intel (+ any opening note) and, unless
// the mode was set explicitly with /mode, switches to VULN mode and seeds a
// class focus when the text clearly asks for vulnerability research. This is why
// "this is a vuln assessment, find buffer overflows" no longer runs malware
// triage. It also seeds focus in vuln mode even when the mode was explicit.
func (m *Model) applyDetectedIntent(opening string) {
	text := strings.TrimSpace(m.sess.Intel + "\n" + opening)
	if strings.TrimSpace(text) == "" {
		return
	}
	if !m.modeExplicit && m.sess.Mode != app.ModeVuln {
		if ok, cue := playbook.DetectVulnIntent(text); ok {
			m.sess.Mode = app.ModeVuln
			m.append(okLine(fmt.Sprintf("Detected vulnerability-research intent (%q) → switched to VULN mode. /mode malware to override.", cue)))
		}
	}
	if m.sess.Mode == app.ModeVuln && len(m.sess.VulnFocus) == 0 {
		if classes := playbook.DetectVulnClasses(text); len(classes) > 0 {
			m.sess.VulnFocus = classes
			m.append(okLine("Scoped the hunt from your brief → focus: " + focusLabel(classes) + ". /focus all to widen, /focus <class> to change."))
		}
	}
}
