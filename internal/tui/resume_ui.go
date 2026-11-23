package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"openbin.ai/binny/internal/agent"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/resume"
)

// The resume screen appears when a selected project has a saved session. The
// analyst can pick up where they left off, or discard it and start fresh.

var resumeItems = []string{"Resume", "Start fresh", "Back"}

func (m *Model) updateResume(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.screen = screenPicker
		return m, nil
	case "up", "k":
		if m.resumeCursor > 0 {
			m.resumeCursor--
		}
	case "down", "j":
		if m.resumeCursor < len(resumeItems)-1 {
			m.resumeCursor++
		}
	case "enter":
		switch m.resumeCursor {
		case 0: // Resume
			return m, m.doResume()
		case 1: // Start fresh — discard the saved session
			if m.sess.Project != nil {
				_ = resume.Delete(m.sess.Project.ID)
				delete(m.resumable, m.sess.Project.ID)
			}
			m.pendingResume = nil
			m.openAutonomy()
			return m, nil
		default: // Back
			m.screen = screenPicker
			return m, nil
		}
	}
	return m, nil
}

func (m *Model) viewResume() string {
	var b strings.Builder
	b.WriteString(banner() + "\n\n")
	st := m.pendingResume
	name := "this project"
	if m.sess.Project != nil {
		name = m.sess.Project.Name
	}
	b.WriteString(styleHeader.Render("Resume "+truncate(name, 32)+"?") + "\n")
	if st != nil {
		snap := st.Engine.Investigation
		findings, iocs, sections := 0, 0, 0
		if snap != nil {
			findings, iocs, sections = len(snap.Findings), len(snap.IOCs), len(snap.Sections)
		}
		b.WriteString(styleDim.Render(fmt.Sprintf(
			"Saved %s · phase %s · %s tok spent · %d findings · %d IOCs · %d draft sections",
			relTime(st.SavedAt), phaseName(st.Engine.Stage), humanTokens(st.Engine.SpentTokens),
			findings, iocs, sections)) + "\n")
		b.WriteString(styleDim.Render("Mode: "+st.Mode+" · run: "+app.AutonomyLabel(app.Autonomy(st.Autonomy))+" · llm: "+st.ProviderID+"/"+st.Model) + "\n")
	}
	b.WriteString("\n" + styleDim.Render("↑/↓ move · enter select · esc back") + "\n\n")
	for i, it := range resumeItems {
		cursor, nameStyle := "  ", styleDim
		if i == m.resumeCursor {
			cursor, nameStyle = styleChipHi.Render("▸ "), styleChipHi
		}
		b.WriteString(fmt.Sprintf("%s%s\n", cursor, nameStyle.Render(it)))
	}
	return b.String()
}

// doResume rehydrates the engine, investigation, transcript, and session context
// from the saved state and drops into the REPL where the loop left off.
func (m *Model) doResume() tea.Cmd {
	st := m.pendingResume
	if st == nil {
		m.screen = screenPicker
		return nil
	}
	// Restore session context (provider/model set directly so the model isn't
	// reset the way SetProvider would).
	m.sess.Mode = app.Mode(st.Mode)
	m.sess.Autonomy = app.Autonomy(st.Autonomy)
	m.sess.Intel = st.Intel
	m.sess.SamplePath = st.SamplePath
	if p := m.sess.Config.Find(st.ProviderID); p != nil {
		m.sess.Provider = p
	}
	if st.Model != "" {
		m.sess.Model = st.Model
	}

	eng, inv, err := agent.RestoreEngine(m.sess, m.sess.API, st.Engine)
	if err != nil {
		m.screen = screenREPL
		m.input.Focus()
		m.append(errLine("Couldn't resume: " + err.Error() + " — set a key with /key or /model, then /investigate to start fresh."))
		return textinput.Blink
	}
	m.engine, m.inv = eng, inv
	prog := m.program
	m.engine.SetStreamSink(func(s string) {
		if prog != nil {
			prog.Send(agentDeltaMsg{text: s})
		}
	})
	m.engineStarted = true

	// Restore the visible transcript.
	m.transcript = m.transcript[:0]
	for _, l := range st.Transcript {
		m.transcript = append(m.transcript, line{role: role(l.Role), text: l.Text, agent: l.Agent})
	}
	// Restore idle/wait flags so input routes correctly.
	m.awaiting = st.Awaiting
	m.reviewIdle = st.ReviewIdle
	m.checkpoint = st.Checkpoint
	m.capPaused = st.CapPaused

	m.screen = screenREPL
	m.sess.Phase = m.engine.Phase()
	m.resizeViewport()
	m.append(sysLine(fmt.Sprintf("↻ Resumed (saved %s) — phase %s, %s tokens spent. Type to continue, /draft to view, /stop to synthesize.",
		relTime(st.SavedAt), string(m.engine.Phase()), humanTokens(m.engine.Spent()))))
	if m.awaiting {
		m.append(warnLine("BINNY was waiting on your answer — reply to continue."))
	} else if m.capPaused {
		m.append(warnLine(capDisclaimer(m.engine.CapReason())))
	} else if m.checkpoint {
		m.append(warnLine("Paused at a checkpoint — type to steer, or Enter / /continue to proceed."))
	}
	m.input.Focus()
	return textinput.Blink
}

// persist snapshots the live session to disk (best-effort) so an interrupt can
// resume. No-op until the engine has started (nothing meaningful to save yet).
func (m *Model) persist() {
	if !m.engineStarted || m.engine == nil || m.sess.Project == nil {
		return
	}
	tr := make([]resume.Line, len(m.transcript))
	for i, l := range m.transcript {
		tr[i] = resume.Line{Role: int(l.role), Text: l.text, Agent: l.agent}
	}
	provID := ""
	if m.sess.Provider != nil {
		provID = m.sess.Provider.ID
	}
	_ = resume.Save(resume.State{
		ProjectID:     m.sess.Project.ID,
		ProjectName:   m.sess.Project.Name,
		Mode:          string(m.sess.Mode),
		Autonomy:      string(m.sess.Autonomy),
		ProviderID:    provID,
		Model:         m.sess.Model,
		Intel:         m.sess.Intel,
		SamplePath:    m.sess.SamplePath,
		Engine:        m.engine.State(),
		Transcript:    tr,
		EngineStarted: m.engineStarted,
		Awaiting:      m.awaiting,
		ReviewIdle:    m.reviewIdle,
		Checkpoint:    m.checkpoint,
		CapPaused:     m.capPaused,
	})
}

// relTime renders an RFC3339 timestamp as a short "Nm ago" relative string.
func relTime(rfc3339 string) string {
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return "recently"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// phaseName maps a persisted engine stage int to a display name (mirrors
// Engine.Phase without needing an engine instance).
func phaseName(stage int) string {
	switch stage {
	case 0:
		return "TRIAGE"
	case 1:
		return "INVESTIGATE"
	case 2:
		return "SYNTHESIZE"
	default:
		return "REVIEW"
	}
}
