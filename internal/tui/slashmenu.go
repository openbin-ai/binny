package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"openbin.ai/binny/internal/config"
)

// The slash menu is an inline command palette: typing "/" (before any space)
// pops a filtered list above the input, navigable with ↑/↓, completed with Tab,
// or run with Enter. Input history is the sibling feature — ↑/↓ when the menu is
// closed walks previously submitted lines (persisted across restarts).

// slashCmd is one entry in the command palette.
type slashCmd struct {
	name     string // "/model"
	desc     string
	takesArg bool // Tab-completing appends a trailing space so args can follow
}

// slashCommands is the palette, in display order. Keep in sync with the
// dispatch in submitSlash / handleSlash.
var slashCommands = []slashCmd{
	{"/start", "direct mode — just talk to BINNY; it uses its tools as you direct", false},
	{"/investigate", "autopilot — triage → playbook → investigate → draft report", false},
	{"/focus", "vuln only: scope the hunt to classes (memory, auth, crypto, …)", false},
	{"/continue", "resume from a checkpoint pause", false},
	{"/stop", "stop investigating early and synthesize now", false},
	{"/autonomy", "set run mode (autonomous | supervised | collaborative)", true},
	{"/draft", "show the current draft report", false},
	{"/findings", "show findings, IOCs, classification, coverage", false},
	{"/save", "push the draft to the project report (review first)", false},
	{"/sample", "attach the raw binary on disk (enables extraction)", true},
	{"/decompile", "decompile a binary locally with Ghidra (path [processor])", true},
	{"/samples", "list this project's extra samples (multi-sample projects)", false},
	{"/switch", "point BINNY's read tools at another sample (#, label, or primary)", true},
	{"/workspace", "show/set the sandbox workspace mounted at /work", true},
	{"/refresh", "drop this project's cached analysis blob (re-fetch next time)", false},
	{"/model", "switch model/provider (no arg opens the picker)", true},
	{"/models", "list configured providers + models", false},
	{"/key", "set/update the BYOK API key", true},
	{"/endpoint", "show/set the active provider's API root (proxy / gateway / self-host)", true},
	{"/mode", "switch analysis lens (malware | vuln)", true},
	{"/project", "re-open the project picker", false},
	{"/settings", "open Settings (LLM, keys, token budget)", false},
	{"/budget", "show/set this project's token budget", true},
	{"/intel", "record analyst intel for this sample", true},
	{"/status", "show current session state", false},
	{"/help", "list all commands", false},
	{"/quit", "exit BINNY", false},
}

// slashMatches returns the palette entries matching what's typed. It's active
// only while typing the command word itself — a "/" prefix with no space yet,
// and not explicitly dismissed (Esc / after a completion).
func (m *Model) slashMatches() []slashCmd {
	if m.menuDismissed {
		return nil
	}
	val := m.input.Value()
	if !strings.HasPrefix(val, "/") || strings.ContainsAny(val, " \t") {
		return nil
	}
	q := strings.ToLower(val)
	var out []slashCmd
	for _, c := range slashCommands {
		if strings.HasPrefix(c.name, q) {
			out = append(out, c)
		}
	}
	return out
}

// acceptMenuTab fills the input with the selected command (without running) so
// the analyst can add arguments.
func (m *Model) acceptMenuTab(c slashCmd) {
	v := c.name
	if c.takesArg {
		v += " "
	}
	m.input.SetValue(v)
	m.input.CursorEnd()
	m.menuDismissed = true
	m.menuIdx = 0
}

// acceptMenuEnter runs the selected command immediately (every command has a
// sensible no-arg behavior).
func (m *Model) acceptMenuEnter(c slashCmd) (tea.Model, tea.Cmd) {
	m.input.Reset()
	m.menuDismissed = false
	m.menuIdx = 0
	m.pushHistory(c.name)
	return m.submit(c.name)
}

func (m *Model) viewSlashMenu() string {
	matches := m.slashMatches()
	if len(matches) == 0 {
		return ""
	}
	const maxShow = 8
	idx := clamp(m.menuIdx, 0, len(matches)-1)
	// Scroll the visible window so the selected item is always shown. Without
	// this, arrowing past the window loses the highlight and hides the entries
	// below it (they become unreachable from the keyboard).
	start := 0
	if idx >= maxShow {
		start = idx - maxShow + 1
	}
	end := start + maxShow
	if end > len(matches) {
		end = len(matches)
	}
	var b strings.Builder
	if start > 0 {
		b.WriteString(styleDim.Render(fmt.Sprintf("  ↑ %d more", start)) + "\n")
	}
	for i := start; i < end; i++ {
		c := matches[i]
		if i == idx {
			b.WriteString(styleChipHi.Render("▸ "+c.name) + styleDim.Render("  "+c.desc) + "\n")
		} else {
			b.WriteString(styleDim.Render("  "+c.name) + styleDim.Render("  "+c.desc) + "\n")
		}
	}
	if end < len(matches) {
		b.WriteString(styleDim.Render(fmt.Sprintf("  ↓ %d more", len(matches)-end)) + "\n")
	}
	return b.String()
}

// --- input history --------------------------------------------------------

// pushHistory records a submitted line (skipping consecutive dupes) and appends
// it to the on-disk history, then resets the navigation cursor.
func (m *Model) pushHistory(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		m.resetHistoryNav()
		return
	}
	if n := len(m.history); n == 0 || m.history[n-1] != s {
		m.history = append(m.history, s)
		appendHistoryFile(s)
	}
	m.resetHistoryNav()
}

func (m *Model) resetHistoryNav() {
	m.histIdx = -1
	m.histStash = ""
}

// historyPrev recalls the previous entry (↑). On first press it stashes the
// in-progress line so historyNext can restore it.
func (m *Model) historyPrev() {
	if len(m.history) == 0 {
		return
	}
	if m.histIdx == -1 {
		m.histStash = m.input.Value()
		m.histIdx = len(m.history)
	}
	if m.histIdx > 0 {
		m.histIdx--
	}
	m.input.SetValue(m.history[m.histIdx])
	m.input.CursorEnd()
}

// historyNext moves forward (↓), restoring the stashed line past the newest.
func (m *Model) historyNext() {
	if m.histIdx == -1 {
		return
	}
	m.histIdx++
	if m.histIdx >= len(m.history) {
		stash := m.histStash // capture before resetHistoryNav clears it
		m.resetHistoryNav()
		m.input.SetValue(stash)
	} else {
		m.input.SetValue(m.history[m.histIdx])
	}
	m.input.CursorEnd()
}

// --- history persistence --------------------------------------------------

const historyKeep = 200

func loadHistoryFile() []string {
	path, err := config.HistoryPath()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	raw := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	if len(out) > historyKeep {
		out = out[len(out)-historyKeep:]
	}
	return out
}

func appendHistoryFile(s string) {
	path, err := config.HistoryPath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(s + "\n")
}

// lineCount counts newline-terminated lines in a rendered fragment.
func lineCount(s string) int { return strings.Count(s, "\n") }
