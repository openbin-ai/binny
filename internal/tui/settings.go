package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/config"
)

// The start menu is BINNY's landing screen: choose to analyze a project or open
// Settings. Settings covers the LLM provider/model, API keys, and the per-project
// token budget. Both are plain cursor menus (↑/↓ · enter · esc).

var startItems = []struct{ label, desc string }{
	{"Analyze a project", "pick a decompiled project (backend or local) and investigate it"},
	{"Decompile a local binary or APK", "Ghidra for binaries (incl. raw firmware), JADX for .apk/.xapk — kept on disk, works offline"},
	{"Settings", "LLM provider & model · API keys · token budget"},
	{"Quit", "exit BINNY"},
}

func (m *Model) updateStart(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		return m, tea.Quit
	case "up", "k":
		if m.startCursor > 0 {
			m.startCursor--
		}
	case "down", "j":
		if m.startCursor < len(startItems)-1 {
			m.startCursor++
		}
	case "enter":
		switch m.startCursor {
		case 0: // analyze a project
			m.screen = screenLoading
			return m, m.loadProjects()
		case 1: // decompile a local binary
			m.screen = screenDecompile
			m.decompErr = ""
			m.decompLog = nil
			m.decompInput.Reset()
			m.decompInput.Focus()
			return m, tea.Batch(m.spinner.Tick, textinput.Blink)
		case 2: // settings
			m.openSettings(screenStart)
			return m, nil
		default: // quit
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *Model) viewStart() string {
	var b strings.Builder
	b.WriteString(bannerFull() + "\n\n")
	b.WriteString(styleDim.Render("↑/↓ move · enter select · q quit") + "\n\n")
	for i, it := range startItems {
		cursor, nameStyle := "  ", styleDim
		if i == m.startCursor {
			cursor, nameStyle = styleChipHi.Render("▸ "), styleChipHi
		}
		b.WriteString(fmt.Sprintf("%s%s\n", cursor, nameStyle.Render(fmt.Sprintf("%-20s", it.label))))
		b.WriteString(styleDim.Render("    "+it.desc) + "\n")
	}
	return b.String()
}

// --- autonomy select ------------------------------------------------------

var autonomyItems = []struct {
	value app.Autonomy
	desc  string
}{
	{app.Autonomous, "runs straight through to a finished draft — no stops"},
	{app.Supervised, "pauses at phase boundaries; asks when it's unsure"},
	{app.Collaborative, "pauses + interviews you on report shape before writing"},
}

// openAutonomy shows the autonomy picker (after a project is chosen), starting
// the cursor on the session's current mode.
func (m *Model) openAutonomy() {
	m.screen = screenAutonomy
	m.autonomyCursor = 1 // default Supervised
	for i, it := range autonomyItems {
		if it.value == m.sess.Autonomy {
			m.autonomyCursor = i
		}
	}
}

func (m *Model) updateAutonomy(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.screen = screenPicker // back to project select
		return m, nil
	case "up", "k":
		if m.autonomyCursor > 0 {
			m.autonomyCursor--
		}
	case "down", "j":
		if m.autonomyCursor < len(autonomyItems)-1 {
			m.autonomyCursor++
		}
	case "enter":
		m.sess.Autonomy = autonomyItems[m.autonomyCursor].value
		m.enterREPL()
		return m, textinput.Blink
	}
	return m, nil
}

func (m *Model) viewAutonomy() string {
	var b strings.Builder
	b.WriteString(banner() + "\n\n")
	name := "this sample"
	if m.sess.Project != nil {
		name = m.sess.Project.Name
	}
	b.WriteString(styleHeader.Render("How should BINNY run on "+truncate(name, 32)+"?") + "\n")
	b.WriteString(styleDim.Render("↑/↓ move · enter select · esc back") + "\n\n")
	for i, it := range autonomyItems {
		cursor, nameStyle := "  ", styleDim
		if i == m.autonomyCursor {
			cursor, nameStyle = styleChipHi.Render("▸ "), styleChipHi
		}
		b.WriteString(fmt.Sprintf("%s%s", cursor, nameStyle.Render(fmt.Sprintf("%-14s", app.AutonomyLabel(it.value)))))
		b.WriteString(styleDim.Render("  "+it.desc) + "\n")
	}
	b.WriteString("\n" + styleDim.Render("You can change this any time with /autonomy.") + "\n")
	return b.String()
}

// --- settings -------------------------------------------------------------

var settingsItems = []string{
	"LLM provider & model",
	"API keys",
	"Token budget (this project)",
	"Back",
}

// openSettings enters the settings menu, remembering where to return.
func (m *Model) openSettings(ret screen) {
	m.screen = screenSettings
	m.settingsReturn = ret
	m.settingsCursor = 0
	m.settingsEditBudget = false
}

func (m *Model) updateSettings(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.settingsEditBudget {
		return m.updateBudgetEdit(msg)
	}
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc", "q":
		return m, m.leaveSettings()
	case "up", "k":
		if m.settingsCursor > 0 {
			m.settingsCursor--
		}
	case "down", "j":
		if m.settingsCursor < len(settingsItems)-1 {
			m.settingsCursor++
		}
	case "enter":
		switch m.settingsCursor {
		case 0: // LLM provider & model → the provider/model picker
			m.openKeySetup(screenSettings, "")
			return m, nil
		case 1: // API keys → jump to key entry for the current provider (rotate)
			pre := ""
			if m.sess.Provider != nil {
				pre = m.sess.Provider.ID
			}
			m.openKeySetup(screenSettings, pre)
			return m, textinput.Blink
		case 2: // token budget (per project)
			if m.sess.Project == nil {
				return m, nil // no project → nothing to scope a budget to (view shows a hint)
			}
			m.settingsEditBudget = true
			m.budgetInput.Placeholder = "e.g. 120000 or 150k"
			m.budgetInput.SetValue(strconv.Itoa(m.sess.TokenBudget()))
			m.budgetInput.CursorEnd()
			m.budgetInput.Focus()
			return m, textinput.Blink
		default: // Back
			return m, m.leaveSettings()
		}
	}
	return m, nil
}

func (m *Model) leaveSettings() tea.Cmd {
	m.screen = m.settingsReturn
	if m.settingsReturn == screenREPL {
		m.input.Focus()
		return textinput.Blink
	}
	return nil
}

func (m *Model) updateBudgetEdit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.settingsEditBudget = false
		m.budgetInput.Blur()
		return m, nil
	case "enter":
		n, ok := parseBudget(m.budgetInput.Value())
		if !ok {
			m.budgetInput.SetValue("")
			m.budgetInput.Placeholder = "invalid — enter a number like 120000 or 150k"
			return m, nil
		}
		m.applyBudget(n)
		m.settingsEditBudget = false
		m.budgetInput.Blur()
		return m, nil
	}
	var cmd tea.Cmd
	m.budgetInput, cmd = m.budgetInput.Update(msg)
	return m, cmd
}

// applyBudget persists the per-project budget and applies it to a live engine.
func (m *Model) applyBudget(n int) {
	if err := m.sess.SetTokenBudget(n); err != nil {
		return
	}
	if m.engine != nil {
		m.engine.SetBudget(n) // takes effect on the current run too
	}
}

func (m *Model) viewSettings() string {
	var b strings.Builder
	b.WriteString(banner() + "\n\n")
	b.WriteString(styleHeader.Render("Settings") + "\n")

	if m.settingsEditBudget {
		proj := "this project"
		if m.sess.Project != nil {
			proj = m.sess.Project.Name
		}
		b.WriteString(styleDim.Render("Per-run token budget for "+proj+" (accepts 120000 or 150k):") + "\n\n")
		b.WriteString(m.budgetInput.View() + "\n\n")
		b.WriteString(styleDim.Render("enter save · esc cancel") + "\n")
		return b.String()
	}

	b.WriteString(styleDim.Render("↑/↓ move · enter select · esc back") + "\n\n")
	for i, label := range settingsItems {
		cursor, nameStyle := "  ", styleDim
		if i == m.settingsCursor {
			cursor, nameStyle = styleChipHi.Render("▸ "), styleChipHi
		}
		b.WriteString(fmt.Sprintf("%s%s", cursor, nameStyle.Render(fmt.Sprintf("%-28s", label))))
		b.WriteString(styleDim.Render("  " + m.settingsValue(i)))
		b.WriteByte('\n')
	}
	return b.String()
}

// settingsValue renders the current value/hint shown next to each row.
func (m *Model) settingsValue(i int) string {
	switch i {
	case 0: // LLM provider & model
		if m.sess.Provider == nil {
			return "(none)"
		}
		return m.sess.Provider.ID + " / " + m.sess.Model
	case 1: // API keys
		ready := 0
		for _, p := range m.sess.Config.Providers {
			if p.Kind != config.KindBedrock && p.Key() != "" {
				ready++
			}
		}
		return fmt.Sprintf("%d key(s) configured", ready)
	case 2: // token budget
		if m.sess.Project == nil {
			return "select a project first"
		}
		return humanTokens(m.sess.TokenBudget()) + " for " + truncate(m.sess.Project.Name, 24)
	default:
		return ""
	}
}

// parseBudget reads a token count as a plain integer or with a k/m suffix
// (120000, 150k, 1m). Returns false on anything non-positive or below a small
// sanity floor.
func parseBudget(s string) (int, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, false
	}
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "k"):
		mult, s = 1e3, strings.TrimSpace(s[:len(s)-1])
	case strings.HasSuffix(s, "m"):
		mult, s = 1e6, strings.TrimSpace(s[:len(s)-1])
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 {
		return 0, false
	}
	n := int(f * mult)
	if n < 1000 {
		return 0, false
	}
	return n, true
}
