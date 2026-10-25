package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"openbin.ai/binny/internal/agent"
	"openbin.ai/binny/internal/api"
)

// The continue screen appears when a selected project already has a backend
// report AND there's no in-progress BINNY session to resume. Posture is "trust
// as established": the report is loaded as prior analysis and BINNY drops
// straight into the conversational REVIEW stage, so the analyst can verify a
// section, recover a config, or extend the work without re-running the whole
// phase machine.

// continueKind is one action offered on the "how do you want to work this
// project?" screen. The available options depend on whether a report exists,
// so they're built per-render (continueOptions) rather than a fixed slice.
type continueKind int

const (
	kindContinueReport continueKind = iota // trust + extend the existing report
	kindQA                                 // Q&A / verify on the current state
	kindNewAnalysis                        // fresh phase-machine run
	kindBack
)

type continueOption struct {
	kind  continueKind
	label string
	desc  string
}

// continueOptions builds the menu for the current project: the "continue"
// action appears only when a report exists; Q&A is always offered.
func (m *Model) continueOptions() []continueOption {
	var opts []continueOption
	if m.pendingReport != nil {
		opts = append(opts, continueOption{kindContinueReport, "Continue existing report",
			"Trust the report as established and extend it (verify, decrypt, add sections)."})
		opts = append(opts, continueOption{kindQA, "Ask / verify (Q&A)",
			"Question the sample & the report on demand — verify a claim, build a PoC, inspect a function. Nothing is assumed true."})
	} else {
		opts = append(opts, continueOption{kindQA, "Ask / explore (Q&A)",
			"Question the sample on demand — inspect a function, build a PoC, or /sample a local binary. No report needed."})
	}
	opts = append(opts, continueOption{kindNewAnalysis, "New analysis",
		"Fresh run from triage → playbook → investigate → draft."})
	opts = append(opts, continueOption{kindBack, "Back", ""})
	return opts
}

// fetchReportCmd loads the project's report off the UI thread. The GET endpoint
// get-or-creates, so this always returns a report; hasContent decides whether
// there's actually anything to continue.
func (m *Model) fetchReportCmd(projectID string) tea.Cmd {
	client := m.sess.API
	return func() tea.Msg {
		rep, err := client.GetReport(projectID)
		return reportLoadedMsg{report: rep, err: err}
	}
}

// handleReportLoaded routes after the report check. Either way the analyst
// lands on the "how do you want to work this?" menu: with a report, the extend
// + Q&A + fresh-run options; without one (no content or a fetch error), the
// Q&A + fresh-run options — so Q&A is always reachable and the analyst is never
// silently forced into a full pipeline run.
func (m *Model) handleReportLoaded(msg reportLoadedMsg) (tea.Model, tea.Cmd) {
	m.reportChecking = false
	if msg.err != nil || msg.report == nil || !hasContent(msg.report) {
		m.pendingReport = nil
	} else {
		m.pendingReport = msg.report
	}
	m.continueCursor = 0
	return m, nil
}

// hasContent reports whether a report has any non-empty section.
func hasContent(r *api.Report) bool {
	return sectionCount(r) > 0
}

// sectionCount counts sections with actual content.
func sectionCount(r *api.Report) int {
	n := 0
	for _, s := range r.Sections {
		if strings.TrimSpace(s.Content) != "" {
			n++
		}
	}
	return n
}

func (m *Model) updateContinue(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.screen = screenPicker
		return m, nil
	}
	if m.reportChecking {
		return m, nil // ignore navigation until the report check returns
	}
	opts := m.continueOptions()
	switch msg.String() {
	case "up", "k":
		if m.continueCursor > 0 {
			m.continueCursor--
		}
	case "down", "j":
		if m.continueCursor < len(opts)-1 {
			m.continueCursor++
		}
	case "enter":
		switch opts[m.continueCursor].kind {
		case kindContinueReport:
			return m, m.doContinueReport()
		case kindQA:
			return m, m.doQA()
		case kindNewAnalysis:
			m.openAutonomy()
			return m, nil
		default: // Back
			m.screen = screenPicker
			return m, nil
		}
	}
	return m, nil
}

func (m *Model) viewContinue() string {
	var b strings.Builder
	b.WriteString(banner() + "\n\n")
	name := "this project"
	if m.sess.Project != nil {
		name = m.sess.Project.Name
	}
	if m.reportChecking {
		b.WriteString(styleDim.Render("Checking "+truncate(name, 32)+" for an existing report…") + "\n")
		return b.String()
	}
	if r := m.pendingReport; r != nil {
		b.WriteString(styleHeader.Render("How do you want to work "+truncate(name, 32)+"?") + "\n")
		title := r.Title
		if strings.TrimSpace(title) == "" {
			title = name
		}
		b.WriteString(styleDim.Render(fmt.Sprintf("Existing report: %q · %d sections · updated %s",
			truncate(title, 40), sectionCount(r), relTime(r.UpdatedAt))) + "\n")
	} else {
		b.WriteString(styleHeader.Render("How do you want to work "+truncate(name, 32)+"?") + "\n")
		b.WriteString(styleDim.Render("No report yet for this project.") + "\n")
	}
	b.WriteString("\n" + styleDim.Render("↑/↓ move · enter select · esc back") + "\n\n")
	opts := m.continueOptions()
	for i, it := range opts {
		cursor, nameStyle := "  ", styleDim
		if i == m.continueCursor {
			cursor, nameStyle = styleChipHi.Render("▸ "), styleChipHi
		}
		b.WriteString(fmt.Sprintf("%s%s\n", cursor, nameStyle.Render(fmt.Sprintf("%-24s", it.label))))
		if it.desc != "" {
			b.WriteString(styleDim.Render("    "+it.desc) + "\n")
		}
	}
	return b.String()
}

// doQA seeds a Q&A / on-demand session on the project's current state and drops
// into the REPL. Autonomy modes don't apply (Q&A is inherently analyst-paced —
// there's no pipeline to pause), so it skips the autonomy screen. The report,
// if any, is handed to BINNY as claims to check, not established work. Nothing
// is spent until the analyst asks their first question.
func (m *Model) doQA() tea.Cmd {
	m.applyDetectedIntent("")
	eng, inv, err := agent.Build(m.sess, m.sess.API)
	if err != nil {
		m.screen = screenREPL
		m.resizeViewport()
		m.input.Focus()
		m.append(errLine("Couldn't start BINNY: " + err.Error() + " — set a key with /key or /model."))
		return textinput.Blink
	}
	m.engine, m.inv = eng, inv
	prog := m.program
	m.engine.SetStreamSink(func(s string) {
		if prog != nil {
			prog.Send(agentDeltaMsg{text: s})
		}
	})
	lines := m.engine.StartQA(m.pendingReport)
	m.engineStarted = true
	m.reviewIdle = true // conversational: the analyst's next line is a question

	m.screen = screenREPL
	m.sess.Phase = m.engine.Phase()
	m.resizeViewport()
	p := m.sess.Project
	m.append(binnyLine(fmt.Sprintf("Attached to %q (%s, %s) — direct mode (%s). Tell me what to look at; I'll use my tools as you direct.", p.Name, p.Kind, p.Status, modeLabel(m.sess.Mode))))
	m.append(m.toLines(lines)...)
	if !p.Ready() {
		m.append(warnLine(fmt.Sprintf(
			"Status is %s — analysis isn't READY, so read tools may be empty until decompile finishes.", p.Status)))
	}
	if !m.sess.ProviderReady() && m.sess.Provider != nil {
		m.append(warnLine(fmt.Sprintf(
			"No key for provider %q — run /key to set one (BYOK) before asking.", m.sess.Provider.ID)))
	}
	if strings.TrimSpace(m.sess.SamplePath) == "" {
		m.append(sysLine("To build a PoC or inspect raw bytes, attach the binary with /sample <path>."))
	}
	m.append(sysLine(
		"Ask a question — e.g. \"what does sub_401200 do?\", \"verify the C2 section\", or \"build a PoC decryptor for the config\". Your next message spends BYOK tokens."))
	m.input.Focus()
	return textinput.Blink
}

// doContinueReport seeds a conversational REVIEW session from the existing
// report and drops into the REPL. No tokens are spent until the analyst sends
// their first message.
func (m *Model) doContinueReport() tea.Cmd {
	if m.pendingReport == nil {
		m.screen = screenPicker
		return nil
	}
	eng, inv, err := agent.Build(m.sess, m.sess.API)
	if err != nil {
		m.screen = screenREPL
		m.resizeViewport()
		m.input.Focus()
		m.append(errLine("Couldn't start BINNY: " + err.Error() + " — set a key with /key or /model."))
		return textinput.Blink
	}
	m.engine, m.inv = eng, inv
	prog := m.program
	m.engine.SetStreamSink(func(s string) {
		if prog != nil {
			prog.Send(agentDeltaMsg{text: s})
		}
	})
	lines := m.engine.StartFromReport(m.pendingReport)
	m.engineStarted = true
	m.reviewIdle = true // conversational: the analyst's next line is a follow-up

	m.screen = screenREPL
	m.sess.Phase = m.engine.Phase()
	m.resizeViewport()
	p := m.sess.Project
	m.append(binnyLine(fmt.Sprintf("Attached to %q (%s, %s) — continuing the existing report.", p.Name, p.Kind, p.Status)))
	m.append(m.toLines(lines)...)
	if !p.Ready() {
		m.append(warnLine(fmt.Sprintf(
			"Status is %s — analysis isn't READY, so read tools may be empty until decompile finishes.", p.Status)))
	}
	if !m.sess.ProviderReady() && m.sess.Provider != nil {
		m.append(warnLine(fmt.Sprintf(
			"No key for provider %q — run /key to set one (BYOK) before sending a message.", m.sess.Provider.ID)))
	}
	if strings.TrimSpace(m.sess.SamplePath) == "" {
		m.append(sysLine("To recover an encrypted config, attach the raw sample first with /sample <path>."))
	}
	m.append(sysLine(
		"Tell me what to check or extend — e.g. \"verify the exfil-channel section\" or \"decrypt the config\". Your next message spends BYOK tokens. /draft shows the current report."))
	m.input.Focus()
	return textinput.Blink
}
