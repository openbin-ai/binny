// Package tui is BINNY's Bubbletea terminal UI: a project picker followed by a
// slash-command REPL with a scrolling transcript. Slice 1 is the shell — the
// agent loop, streaming LLM output, and phase machine hook into the same
// transcript in later slices via the exported AppendLine / RunAgentTurn seams.
package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"openbin.ai/binny/internal/agent"
	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/resume"
	"openbin.ai/binny/internal/store"
)

// screen is which view is active.
type screen int

const (
	screenLoading   screen = iota // fetching projects
	screenPicker                  // choosing a project
	screenREPL                    // slash + chat REPL
	screenSetup                   // first-run / /key provider key entry
	screenStart                   // landing menu: analyze a project | settings
	screenSettings                // settings menu: LLM / keys / token budget
	screenAutonomy                // pick autonomy mode after selecting a project
	screenResume                  // offer to resume a saved session
	screenContinue                // offer to continue an existing backend report
	screenDecompile               // decompile a local binary (path entry + progress)
)

// --- async messages -------------------------------------------------------

type projectsLoadedMsg struct {
	projects []api.Project
	err      error
}

// reportLoadedMsg carries the result of the backend report check done when a
// project is selected (drives the "continue existing report" offer).
type reportLoadedMsg struct {
	report *api.Report
	err    error
}

// Model is the root Bubbletea model.
type Model struct {
	sess *app.Session

	screen screen
	width  int
	height int

	// picker state
	projects  []api.Project
	cursor    int
	loadErr   error
	resumable map[string]bool       // project id → has a saved session
	localMeta map[string]store.Meta // local project id → its store metadata

	// local-decompile state (screenDecompile + /decompile)
	decompInput  textinput.Model
	decompLog    []string
	decompErr    string
	decompiling  bool
	decompCancel context.CancelFunc
	uploading    bool // /upload of a local APK project in flight

	// resume prompt
	pendingResume *resume.State
	resumeCursor  int

	// continue-existing-report prompt
	pendingReport  *api.Report // backend report found for the selected project
	continueCursor int
	reportChecking bool // report fetch in flight (show a "checking…" line)

	// repl state
	vp         viewport.Model
	input      textinput.Model
	transcript []line
	ready      bool // viewport sized
	follow     bool // keep the transcript pinned to the tail (until the user scrolls up)

	// slash-command palette + input history
	menuIdx       int      // selection within the current slash matches
	menuDismissed bool     // Esc / completion hides the menu until next keystroke
	history       []string // submitted lines (persisted); oldest first
	histIdx       int      // -1 = not navigating; else index into history
	histStash     string   // in-progress line stashed on first ↑

	// agent state
	program       *tea.Program // for pushing streaming deltas from the loop goroutine
	engine        *agent.Engine
	inv           *agent.Investigation
	engineStarted bool // Start() called — follow-up text continues (Ask), never restarts
	agentRunning  bool // engine loop in flight
	awaiting      bool // engine suspended on ask_user; next input answers it
	reviewIdle    bool // draft ready / conversational — free text is a follow-up
	checkpoint    bool // Supervised/Collaborative: paused at a phase boundary
	capPaused     bool // paused on a spend cap — Enter/continue extends, /stop wraps up

	streaming string        // live assistant text being streamed this turn
	spinner   spinner.Model // "working…" indicator while a step is in flight

	runCancel   context.CancelFunc // cancels the in-flight step (Esc interrupt)
	interrupted bool               // set by Esc so a canceled step reads as a pause

	confirmStart     bool   // waiting for y/n to spend tokens
	pendingStartNote string // analyst's opening note, held until confirmed

	// setup screen state
	setupStage    int    // 0 = pick provider, 1 = enter key, 2 = pick model
	setupCursor   int    // provider index in pick stage
	setupProvider string // provider id being keyed / model-picked
	setupReturn   screen // where to go when setup finishes
	keyInput      textinput.Model

	// model-pick stage (stage 2): live-discovered models for setupProvider
	setupModels      []string // candidate model ids (config first, live once fetched)
	setupModelCursor int      // highlighted model index
	setupModelsLive  bool     // list came from a live GET /models fetch
	setupModelsBusy  bool     // a live fetch is in flight

	// start menu + settings
	startCursor        int             // landing menu selection
	autonomyCursor     int             // autonomy-select cursor
	settingsCursor     int             // settings menu selection
	settingsReturn     screen          // where Back / finish returns to
	settingsEditBudget bool            // editing the token-budget field
	budgetInput        textinput.Model // token-budget number entry
}

// New builds the root model for a session. needSetup shows the key-setup screen
// first (first run with no key configured).
func New(sess *app.Session, needSetup bool) *Model {
	ti := textinput.New()
	ti.Placeholder = "message BINNY · type / for commands · ↑ recalls history"
	ti.Prompt = "❯ "
	ti.CharLimit = 8000
	ti.Focus()

	ki := textinput.New()
	ki.Placeholder = "paste your API key"
	ki.Prompt = "key ❯ "
	ki.EchoMode = textinput.EchoPassword
	ki.CharLimit = 400

	bi := textinput.New()
	bi.Placeholder = "e.g. 120000 or 150k"
	bi.Prompt = "budget ❯ "
	bi.CharLimit = 12

	di := textinput.New()
	di.Placeholder = "~/samples/firmware.bin [PROCESSOR:ID]"
	di.Prompt = "binary ❯ "
	di.CharLimit = 1000

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = styleBinny

	m := &Model{
		sess:        sess,
		input:       ti,
		keyInput:    ki,
		budgetInput: bi,
		decompInput: di,
		spinner:     sp,
		setupReturn: screenStart, // first-run setup returns to the landing menu
		history:     loadHistoryFile(),
		histIdx:     -1,
		follow:      true, // pin to the tail by default; scrolling up releases it
	}
	if needSetup {
		m.screen = screenSetup
	} else {
		m.screen = screenStart
	}
	return m
}

// SetProgram wires the tea.Program so the agent goroutine can push streaming
// text deltas via p.Send. Called once after NewProgram.
func (m *Model) SetProgram(p *tea.Program) { m.program = p }

func (m *Model) Init() tea.Cmd {
	// The landing screen (start menu / first-run setup) is static; projects load
	// only when the analyst chooses "Analyze a project".
	return nil
}

// loadProjects fetches the caller's projects off the UI thread.
func (m *Model) loadProjects() tea.Cmd {
	return func() tea.Msg {
		ps, err := m.sess.API.ListProjects()
		return projectsLoadedMsg{projects: ps, err: err}
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.resizeViewport()
		return m, nil

	case projectsLoadedMsg:
		m.loadErr = msg.err
		// Local analyses list first — they work even when the backend is
		// unreachable (fully offline mode).
		m.localMeta = map[string]store.Meta{}
		var merged []api.Project
		for _, meta := range store.List() {
			p := localProject(meta)
			m.localMeta[p.ID] = meta
			merged = append(merged, *p)
		}
		merged = append(merged, msg.projects...)
		m.projects = merged
		m.resumable = map[string]bool{}
		for _, p := range merged {
			if resume.Exists(p.ID) {
				m.resumable[p.ID] = true
			}
		}
		m.screen = screenPicker
		return m, nil

	case decompLogMsg:
		if m.screen == screenDecompile {
			m.appendDecompLog(msg.line)
		} else {
			m.append(sysLine("[decompile] " + msg.line))
		}
		return m, nil

	case decompDoneMsg:
		return m.handleDecompDone(msg)

	case uploadLogMsg:
		m.append(sysLine("[upload] " + msg.line))
		return m, nil

	case uploadDoneMsg:
		m.handleUploadDone(msg)
		return m, nil

	case treeCacheMsg:
		m.append(sysLine("[cache] " + msg.line))
		return m, nil

	case samplesMsg:
		return m.handleSamplesMsg(msg)

	case modelsFetchedMsg:
		return m.handleModelsFetched(msg)

	case reportLoadedMsg:
		return m.handleReportLoaded(msg)

	case agentStepMsg:
		mdl, cmd := m.handleAgentStep(msg.res)
		m.persist() // checkpoint after every step so an interrupt can resume
		return mdl, cmd

	case agentDeltaMsg:
		m.streaming += msg.text
		m.refreshViewport()
		return m, nil

	case spinner.TickMsg:
		if m.agentRunning || m.decompiling {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil

	case tea.MouseMsg:
		// Mouse-wheel scrolling of the transcript in the REPL.
		if m.screen == screenREPL && m.ready {
			var cmd tea.Cmd
			m.vp, cmd = m.vp.Update(msg)
			m.follow = m.vp.AtBottom() // release/re-acquire the tail as the user scrolls
			return m, cmd
		}
		return m, nil

	case tea.KeyMsg:
		switch m.screen {
		case screenSetup:
			return m.updateSetup(msg)
		case screenStart:
			return m.updateStart(msg)
		case screenSettings:
			return m.updateSettings(msg)
		case screenAutonomy:
			return m.updateAutonomy(msg)
		case screenResume:
			return m.updateResume(msg)
		case screenContinue:
			return m.updateContinue(msg)
		case screenDecompile:
			return m.updateDecompile(msg)
		case screenPicker:
			return m.updatePicker(msg)
		case screenREPL:
			return m.updateREPL(msg)
		}
	}

	// forward everything else to whichever input owns focus
	if m.screen == screenREPL {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

// --- picker ---------------------------------------------------------------

func (m *Model) updatePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc", "q":
		// Back to the landing menu rather than quitting outright.
		m.screen = screenStart
		return m, nil
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.projects)-1 {
			m.cursor++
		}
	case "r":
		m.screen = screenLoading
		return m, m.loadProjects()
	case "enter":
		if len(m.projects) == 0 {
			return m, nil
		}
		p := m.projects[m.cursor]
		m.sess.Project = &p
		m.sess.Sample = nil // a fresh pick always starts on the primary binary
		m.sess.Mode = app.Mode(orDefault(p.AnalysisMode, string(app.ModeMalware)))
		if meta, ok := m.localMeta[p.ID]; ok {
			// Local project: re-attach the sample if it's still on disk.
			m.attachLocal(meta)
		}
		// Backend APK project: start pulling its source tree now, while the
		// analyst picks options — reads are then served from disk.
		prefetch := m.prefetchTree(p)
		// A saved BINNY session takes priority — offer to resume it first.
		if st, ok, err := resume.Load(p.ID); err == nil && ok {
			m.pendingResume = st
			m.resumeCursor = 0
			m.screen = screenResume
			return m, prefetch
		}
		// Local projects have no backend report to continue — straight to run mode.
		if p.IsLocal() {
			m.openAutonomy()
			return m, prefetch
		}
		// Otherwise check the backend for an existing report to continue.
		m.pendingReport = nil
		m.continueCursor = 0
		m.reportChecking = true
		m.screen = screenContinue
		return m, tea.Batch(prefetch, m.fetchReportCmd(p.ID))
	}
	return m, nil
}

func (m *Model) enterREPL() {
	m.screen = screenREPL
	m.sess.Phase = app.PhaseMode
	m.resizeViewport()
	p := m.sess.Project
	m.append(
		binnyLine(fmt.Sprintf("Attached to %q (%s, %s).", p.Name, p.Kind, p.Status)),
	)
	if !p.Ready() {
		m.append(warnLine(fmt.Sprintf(
			"Status is %s — analysis isn't READY. Read tools may be empty until decompile finishes.", p.Status)))
	}
	if !m.sess.ProviderReady() && m.sess.Provider != nil {
		m.append(warnLine(fmt.Sprintf(
			"No key for provider %q — run /key to set one (BYOK), or /model to switch provider.",
			m.sess.Provider.ID)))
	}
	m.append(sysLine("Optionally type intel (source, suspected family, hashes), then /investigate to start."))
	m.append(sysLine("During a run: Esc interrupts, /stop cuts to the draft, /findings & /draft show progress. /help for commands."))
	m.input.Focus()
}

func (m *Model) viewPicker() string {
	var b strings.Builder
	b.WriteString(banner() + "\n\n")
	if m.loadErr != nil && len(m.projects) == 0 {
		b.WriteString(styleErr.Render("Couldn't load projects: "+m.loadErr.Error()) + "\n\n")
		b.WriteString(styleDim.Render("Is `openbin login` done? Press r to retry, esc to go back.") + "\n")
		return b.String()
	}
	b.WriteString(styleHeader.Render("Select a project") + styleDim.Render("  (↑/↓ move · enter select · r refresh · esc back)") + "\n\n")
	if m.loadErr != nil {
		// Backend down but local analyses exist — offline mode still works.
		b.WriteString(styleWarn.Render("Backend unreachable ("+truncate(m.loadErr.Error(), 60)+") — showing local analyses only.") + "\n\n")
	}
	if len(m.projects) == 0 {
		b.WriteString(styleDim.Render("No projects yet. Decompile something with the openbin CLI, or use \"Decompile a local binary or APK\" from the start menu.") + "\n")
		return b.String()
	}
	for i, p := range m.projects {
		cursor := "  "
		nameStyle := styleDim
		if i == m.cursor {
			cursor = styleChipHi.Render("▸ ")
			nameStyle = styleChipHi
		}
		kindLabel := fmt.Sprintf("%s · %s%s", p.Kind, p.Status, forkSuffix(p))
		if p.IsLocal() {
			kindLabel = string(p.Kind) + " · local (on-disk)"
		}
		meta := styleDim.Render("  " + kindLabel)
		if m.resumable[p.ID] {
			meta += styleOK.Render("  ⏵ resumable")
		}
		b.WriteString(cursor + nameStyle.Render(truncate(p.Name, 48)) + meta + "\n")
	}
	return b.String()
}

// --- repl -----------------------------------------------------------------

func (m *Model) updateREPL(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	menu := m.slashMatches()
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		// Dismiss the slash menu first if it's open (keep the typed text).
		if len(menu) > 0 {
			m.menuDismissed = true
			return m, nil
		}
		// A running local decompile: Esc cancels it.
		if m.decompiling && m.decompCancel != nil {
			m.decompCancel()
			m.append(warnLine("Canceling the local decompile…"))
			return m, nil
		}
		// Otherwise interrupt a running loop without quitting.
		if m.agentRunning && m.runCancel != nil {
			m.interrupted = true
			m.runCancel()
			m.append(warnLine("Interrupting… (canceling the in-flight request)"))
		}
		return m, nil
	case "up":
		if len(menu) > 0 {
			if m.menuIdx > 0 {
				m.menuIdx--
			}
			return m, nil
		}
		m.historyPrev()
		return m, nil
	case "down":
		if len(menu) > 0 {
			if m.menuIdx < len(menu)-1 {
				m.menuIdx++
			}
			return m, nil
		}
		m.historyNext()
		return m, nil
	case "tab":
		if len(menu) > 0 {
			m.acceptMenuTab(menu[clamp(m.menuIdx, 0, len(menu)-1)])
			return m, nil
		}
	case "enter":
		if len(menu) > 0 {
			return m.acceptMenuEnter(menu[clamp(m.menuIdx, 0, len(menu)-1)])
		}
		val := strings.TrimSpace(m.input.Value())
		m.input.Reset()
		m.resetHistoryNav()
		if val == "" {
			// At a spend-cap pause, empty Enter means "extend and continue".
			if m.capPaused {
				return m, m.resumePastCap("")
			}
			// At a checkpoint, an empty Enter means "proceed".
			if m.checkpoint {
				return m, m.beginRun()
			}
			return m, nil
		}
		m.pushHistory(val)
		return m.submit(val)
	case "pgup":
		m.vp.LineUp(m.vp.Height / 2)
		m.follow = false // reading history — stop auto-scrolling
		return m, nil
	case "pgdown":
		m.vp.LineDown(m.vp.Height / 2)
		m.follow = m.vp.AtBottom() // re-follow once back at the tail
		return m, nil
	case "ctrl+u":
		m.vp.LineUp(m.vp.Height / 2)
		m.follow = false
		return m, nil
	case "ctrl+d":
		m.vp.LineDown(m.vp.Height / 2)
		m.follow = m.vp.AtBottom()
		return m, nil
	case "home":
		m.vp.GotoTop()
		m.follow = false
		return m, nil
	case "end":
		m.vp.GotoBottom()
		m.follow = true
		return m, nil
	}
	// A normal keystroke: feed the input, and reset menu/history navigation so
	// the palette re-filters and ↑/↓ starts fresh next time.
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.menuDismissed = false
	m.menuIdx = 0
	m.histIdx = -1
	return m, cmd
}

func (m *Model) submit(val string) (tea.Model, tea.Cmd) {
	m.follow = true // any input means the user is at the prompt — show new output
	// A pending token-spend confirmation consumes this input first.
	if m.confirmStart {
		m.confirmStart = false
		switch strings.ToLower(strings.TrimSpace(val)) {
		case "y", "yes":
			return m, m.startAgentNow(m.pendingStartNote)
		default:
			m.append(sysLine("Cancelled — no tokens spent."))
			return m, nil
		}
	}
	if strings.HasPrefix(val, "/") {
		return m.submitSlash(val)
	}
	// Commit any assistant text still streaming so the user's line lands AFTER
	// it (chronological order) rather than before the deferred commit.
	if m.streaming != "" {
		m.append(binnyLine(m.streaming))
		m.streaming = ""
	}
	m.append(userLine(val))

	// If the message names a real file and no sample is attached, attach it
	// automatically and direct BINNY to extract now.
	engineText := val
	if abs := m.maybeAttachSample(val); abs != "" {
		note := "\n\n[system: the analyst attached the raw sample at " + abs +
			" — active extraction is now available. Do this NOW before continuing/finalizing: write_file a decryptor and run it against /sample, then read_artifact the output and record the recovered config/IOCs."
		if m.hasUnrecoveredConfig() {
			note += " You previously identified an encrypted/encoded config but have not recovered it — recover it now."
		}
		note += "]"
		engineText = val + note
	}

	// Paused on a spend cap: a typed message means "extend, take this guidance,
	// and keep going" (rather than wrap up — that's /stop).
	if m.capPaused {
		return m, m.resumePastCap(engineText)
	}
	// If BINNY is waiting on an ask_user question, this input is the answer.
	if m.awaiting {
		m.engine.Provide(engineText)
		return m, m.beginRun()
	}
	// If the loop is mid-run, queue the text as steering (seen next turn).
	if m.agentRunning {
		m.engine.Provide(engineText)
		m.append(sysLine("(queued — BINNY will see this shortly)"))
		return m, nil
	}
	// Draft is ready / conversational: continue the SAME conversation (memory
	// intact) — never restart the loop.
	if m.engineStarted {
		m.engine.Ask(engineText)
		return m, m.beginRun()
	}
	// Not started yet: idle text is collected as intel. Starting is an explicit
	// /investigate (which confirms the spend) — so stray input can't kick off a
	// run or produce a confirm cascade.
	if strings.TrimSpace(m.sess.Intel) == "" {
		m.sess.Intel = val
	} else {
		m.sess.Intel += "\n" + val
	}
	m.append(sysLine("Noted as intel. Type /investigate to start (Esc or Ctrl+C to quit)."))
	return m, nil
}

func (m *Model) submitSlash(val string) (tea.Model, tea.Cmd) {
	fields := strings.Fields(val)
	switch strings.ToLower(fields[0]) {
	case "/investigate", "/run", "/go":
		if m.engineStarted {
			m.append(sysLine("Already started — just type to continue, or /stop to synthesize."))
			return m, nil
		}
		m.requestStart("")
		return m, nil
	case "/ask", "/qa":
		if m.engineStarted {
			m.append(sysLine("A session is already running — just type your question. (/ask starts a fresh Q&A session; use /project to re-pick the sample to switch.)"))
			return m, nil
		}
		return m, m.doQA()
	case "/stop":
		return m, m.cmdStop()
	case "/continue", "/c":
		if m.capPaused {
			return m, m.resumePastCap("")
		}
		if m.checkpoint {
			return m, m.beginRun()
		}
		m.append(sysLine("Nothing paused — BINNY pauses at checkpoints or when a spend cap is hit."))
		return m, nil
	case "/autonomy", "/auto":
		m.cmdAutonomy(fields)
		return m, nil
	case "/draft":
		m.cmdDraft()
		return m, nil
	case "/findings":
		m.cmdFindings()
		return m, nil
	case "/save":
		m.cmdSave()
		return m, nil
	case "/sample":
		if len(fields) < 2 {
			m.cmdSampleStatus()
			return m, nil
		}
		// Path may contain spaces — take everything after the command word.
		m.cmdSample(strings.TrimSpace(strings.TrimPrefix(val, fields[0])))
		return m, nil
	case "/decompile":
		return m, tea.Batch(m.spinner.Tick,
			m.cmdDecompile(strings.TrimSpace(strings.TrimPrefix(val, fields[0]))))
	case "/upload":
		return m, m.cmdUpload()
	case "/samples":
		return m, m.cmdSamples()
	case "/switch", "/use":
		return m, m.cmdSwitch(strings.TrimSpace(strings.TrimPrefix(val, fields[0])))
	case "/workspace", "/work":
		m.cmdWorkspace(strings.TrimSpace(strings.TrimPrefix(val, fields[0])))
		return m, nil
	case "/refresh":
		if m.sess.Project == nil || m.sess.Project.IsLocal() {
			m.append(sysLine("Nothing to refresh — /refresh drops the on-disk cache of a BACKEND project's analysis blob or source tree."))
			return m, nil
		}
		store.DropRemote(m.sess.Project.ID)
		store.DropRemoteTree(m.sess.Project.ID) // APK: the cached source tree
		if m.sess.Sample != nil {
			store.DropRemote(m.sess.Project.ID + ":" + m.sess.Sample.ID)
		}
		m.append(okLine("Dropped the cached analysis for this project — the next session re-fetches it from the backend."))
		return m, nil
	case "/settings":
		m.openSettings(screenREPL)
		return m, nil
	case "/budget":
		m.cmdBudget(fields)
		return m, nil
	case "/key":
		preselect := ""
		if len(fields) > 1 {
			preselect = fields[1]
		} else if m.sess.Provider != nil {
			preselect = m.sess.Provider.ID
		}
		m.openKeySetup(screenREPL, preselect)
		return m, nil
	case "/model":
		if len(fields) < 2 {
			// No argument → open the interactive up/down provider picker.
			m.openKeySetup(screenREPL, "")
			return m, nil
		}
		m.append(m.switchModel(fields[1])...)
		// Switched to a provider with no key → drop straight into key entry.
		if m.sess.Provider != nil && !m.sess.ProviderReady() {
			m.append(sysLine("That provider has no key yet — enter it:"))
			m.openKeySetup(screenREPL, m.sess.Provider.ID)
		}
		return m, nil
	}
	res := m.handleSlash(val)
	m.append(res.lines...)
	if res.openPicker {
		m.screen = screenPicker
		return m, nil
	}
	if res.quit {
		return m, tea.Quit
	}
	return m, nil
}

func (m *Model) viewREPL() string {
	if !m.ready {
		return "\n  initializing…"
	}
	header := m.renderHeader()
	status := m.statusLine()
	menu := m.viewSlashMenu()
	footer := m.input.View()

	// Size the transcript viewport around the variable-height chrome (status
	// spinner + slash menu) so the input never scrolls off the bottom.
	reserve := 3 + 1 + lineCount(status) + lineCount(menu) // header(2)+footer(1) + gap + status + menu
	if vpH := m.height - reserve; vpH >= 3 && vpH != m.vp.Height {
		m.vp.Height = vpH
		m.refreshViewport()
	}
	return header + "\n" + m.vp.View() + "\n" + status + menu + footer
}

// statusLine shows a live "working…" spinner while a step is in flight (so
// multi-second model calls read as active, not frozen), or a hint when BINNY is
// waiting on the analyst.
func (m *Model) statusLine() string {
	// When scrolled up, always show how to get back — the tail may be moving.
	if !m.follow {
		return styleWarn.Render("↑ scrolled up") + styleDim.Render(" — PgDn/End (or scroll down) to return to the latest") + "\n"
	}
	switch {
	case m.agentRunning:
		return m.spinner.View() + styleDim.Render(" working… (Esc to interrupt · PgUp to scroll)") + "\n"
	case m.awaiting:
		return styleWarn.Render("↳ BINNY is waiting for your answer") + "\n"
	default:
		return ""
	}
}

func (m *Model) renderHeader() string {
	s := m.sess
	proj := "no project"
	if s.Project != nil {
		proj = truncate(s.Project.Name, 28)
	}
	prov := "(no provider)"
	if s.Provider != nil {
		prov = s.Provider.ID + "/" + s.Model
	}
	chips := []string{
		styleChipHi.Render("BINNY"),
		chip("mode", modeLabel(s.Mode)),
		chip("run", app.AutonomyLabel(s.Autonomy)),
		chip("llm", prov),
		chip("project", proj),
		chip("phase", string(s.Phase)),
	}
	// Live spend meter once the engine exists.
	if m.engine != nil {
		spent := m.engine.Spent()
		round, maxr := m.engine.Rounds()
		meter := fmt.Sprintf("%s tok · round %d/%d", humanTokens(spent), round, maxr)
		if cached := m.engine.CacheRead(); cached > 0 {
			meter += fmt.Sprintf(" · %s cached", humanTokens(cached))
		}
		if m.agentRunning {
			meter = "⏳ " + meter
		}
		chips = append(chips, chip("spend", meter))
	}
	bar := strings.Join(chips, styleDim.Render(" · "))
	rule := styleDim.Render(strings.Repeat("─", max(1, m.width)))
	return bar + "\n" + rule
}

// --- transcript plumbing --------------------------------------------------

// AppendLine appends a system/tool/binny line to the transcript from outside
// the TUI package (the agent loop uses this seam in later slices).
func (m *Model) append(lines ...line) {
	m.transcript = append(m.transcript, lines...)
	m.refreshViewport()
}

func (m *Model) resizeViewport() {
	if m.width == 0 || m.height == 0 {
		return
	}
	headerH := 2 // chips + rule
	footerH := 1 // input
	gaps := 2
	vpH := m.height - headerH - footerH - gaps
	if vpH < 3 {
		vpH = 3
	}
	if !m.ready {
		m.vp = viewport.New(m.width, vpH)
		m.vp.MouseWheelEnabled = true // wheel scrolls the transcript (mouse capture is on)
		m.vp.MouseWheelDelta = 3
		m.ready = true
	} else {
		m.vp.Width = m.width
		m.vp.Height = vpH
	}
	m.input.Width = m.width - 4
	m.keyInput.Width = m.width - 8
	m.refreshViewport()
}

func (m *Model) refreshViewport() {
	if !m.ready {
		return
	}
	var b strings.Builder
	for i, l := range m.transcript {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(l.render(m.vp.Width))
	}
	// Render the in-flight streamed assistant text as a live trailing line.
	if m.streaming != "" {
		if len(m.transcript) > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(binnyLine(m.streaming).render(m.vp.Width))
	}
	m.vp.SetContent(b.String())
	// Follow the tail unless the analyst has deliberately scrolled up (m.follow).
	// Using an explicit flag — not vp.AtBottom() — because the viewport height
	// changes mid-run (the "working…" line appears/disappears), which would make
	// an AtBottom check spuriously false and hide streamed output.
	if m.follow {
		m.vp.GotoBottom()
	}
}

func (m *Model) View() string {
	switch m.screen {
	case screenSetup:
		return m.viewSetup()
	case screenStart:
		return m.viewStart()
	case screenSettings:
		return m.viewSettings()
	case screenAutonomy:
		return m.viewAutonomy()
	case screenResume:
		return m.viewResume()
	case screenContinue:
		return m.viewContinue()
	case screenDecompile:
		return m.viewDecompile()
	case screenLoading:
		return "\n  " + styleDim.Render("Loading projects…")
	case screenPicker:
		return m.viewPicker()
	default:
		return m.viewREPL()
	}
}

// --- small helpers --------------------------------------------------------

// banner is the compact mascot mark for the cramped menu/REPL screens: the
// small robot + a one-line caption. The full robot (bannerFull) is reserved
// for the landing screen, which has the vertical room for it.
func banner() string {
	return lipgloss.NewStyle().Foreground(colAccent).Render(strings.Trim(bannyArtMini, "\n")) + "\n" +
		styleChipHi.Render("  BINNY") + styleDim.Render(" · interactive reverse-engineering agent")
}

// bannerFull renders the full Binny robot — the hero on the landing screen.
func bannerFull() string {
	return lipgloss.NewStyle().Foreground(colAccent).Render(strings.Trim(bannyArtFull, "\n")) + "\n" +
		styleChipHi.Render("  BINNY") + styleDim.Render(" · interactive reverse-engineering agent")
}

func chip(k, v string) string { return styleChip.Render(k+":") + " " + v }

// humanTokens renders a token count compactly (e.g. 12.3k).
func humanTokens(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	return fmt.Sprintf("%.1fk", float64(n)/1000)
}

func forkSuffix(p api.Project) string {
	if p.ForkedFromID != "" {
		return " · fork"
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
