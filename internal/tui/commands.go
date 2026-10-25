package tui

import (
	"fmt"
	"sort"
	"strings"

	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/playbook"
)

// slashResult is what a slash command produces: transcript lines to append and
// whether the app should quit. Commands never do I/O directly here — anything
// async (like re-listing projects) returns a follow-up via the model.
type slashResult struct {
	lines []line
	quit  bool
	// openPicker re-opens the project picker (for /project).
	openPicker bool
}

// handleSlash dispatches a "/..." input line against the session, mutating
// state and returning transcript output. Unknown commands are reported, not
// fatal.
func (m *Model) handleSlash(input string) slashResult {
	fields := strings.Fields(input)
	cmd := strings.ToLower(fields[0])
	args := fields[1:]
	s := m.sess

	switch cmd {
	case "/help", "/?":
		return slashResult{lines: helpLines()}

	case "/quit", "/exit", "/q":
		return slashResult{lines: []line{sysLine("Bye.")}, quit: true}

	case "/mode":
		return slashResult{lines: m.cmdMode(args)}

	case "/focus":
		return slashResult{lines: m.cmdFocus(args)}

	case "/models":
		return slashResult{lines: modelsLines(m)}

	case "/model":
		if len(args) == 0 {
			return slashResult{lines: []line{sysLine(fmt.Sprintf(
				"Current: %s / %s. Usage: /model <providerId | modelId>",
				providerID(m), s.Model))}}
		}
		return slashResult{lines: m.switchModel(args[0])}

	case "/endpoint", "/baseurl":
		return slashResult{lines: m.cmdEndpoint(args)}

	case "/project", "/open":
		return slashResult{openPicker: true}

	case "/intel":
		if len(args) == 0 {
			if s.Intel == "" {
				return slashResult{lines: []line{sysLine("No intel recorded. Usage: /intel <free text>")}}
			}
			return slashResult{lines: []line{sysLine("Intel: " + s.Intel)}}
		}
		s.Intel = strings.TrimSpace(strings.TrimPrefix(input, fields[0]))
		return slashResult{lines: []line{okLine("Intel recorded.")}}

	case "/status", "/info":
		return slashResult{lines: statusLines(m)}

	default:
		return slashResult{lines: []line{errLine(fmt.Sprintf(
			"unknown command %q — /help for the list", cmd))}}
	}
}

func (m *Model) switchModel(arg string) []line {
	s := m.sess
	// Prefer interpreting the arg as a provider id (switches provider + default
	// model); fall back to a model id.
	if p := s.Config.Find(arg); p != nil {
		if err := s.SetProvider(arg); err != nil {
			return []line{errLine(err.Error())}
		}
	} else if err := s.SetModel(arg); err != nil {
		return []line{errLine(err.Error())}
	}
	return []line{okLine(fmt.Sprintf("Now using %s / %s", providerID(m), s.Model))}
}

// cmdEndpoint shows or changes the API root the active provider talks to.
//
//	/endpoint                 show the current and shipped endpoint
//	/endpoint <url>           point the active provider at <url>
//	/endpoint <provider> <url>
//	/endpoint reset           back to the shipped endpoint
//
// This is how a hosted gateway for a frontier model (your own
// anthropic.<host> that fronts the Messages API, an OpenAI-compatible
// router, a self-hosted server) gets used: same adapter, same key header,
// different host. The /models cache is keyed by base URL, so the model list
// refreshes on the next /model pick without a restart.
func (m *Model) cmdEndpoint(args []string) []line {
	s := m.sess
	target := s.Provider
	if len(args) == 2 {
		target = s.Config.Find(args[0])
		if target == nil {
			return []line{errLine(fmt.Sprintf("unknown provider %q — /models lists them", args[0]))}
		}
		args = args[1:]
	}
	if target == nil {
		return []line{errLine("no active provider — /model to pick one first")}
	}
	shipped := config.DefaultBaseURL(target.ID)
	if len(args) == 0 {
		out := []line{sysLine(fmt.Sprintf("%s endpoint: %s", target.ID, target.BaseURL))}
		if shipped != "" && shipped != target.BaseURL {
			out = append(out, sysLine("  shipped default: "+shipped+"  (/endpoint reset to go back)"))
		}
		out = append(out, sysLine("Usage: /endpoint <url> | /endpoint <provider> <url> | /endpoint reset"))
		return out
	}
	if strings.EqualFold(args[0], "reset") {
		if shipped == "" {
			return []line{errLine(fmt.Sprintf("%s has no shipped endpoint to reset to", target.ID))}
		}
		if err := s.Config.SetBaseURL(target.ID, shipped); err != nil {
			return []line{errLine(err.Error())}
		}
		return []line{okLine(fmt.Sprintf("%s endpoint → %s (shipped default)", target.ID, shipped))}
	}
	if err := s.Config.SetBaseURL(target.ID, args[0]); err != nil {
		return []line{errLine(err.Error())}
	}
	out := []line{okLine(fmt.Sprintf("%s endpoint → %s", target.ID, target.BaseURL))}
	if target.Kind == config.KindAnthropic {
		out = append(out, sysLine("Requests go to "+target.BaseURL+"/v1/messages with your key in x-api-key."))
	} else {
		out = append(out, sysLine("Requests go to "+target.BaseURL+"/chat/completions with your key as a Bearer token."))
	}
	return out
}

// cmdMode shows or switches the analysis mode. Mode can't change once the
// engine is running — the toolset and report schema are fixed at Start.
// `/mode vuln <class...>` also scopes the vuln hunt (see cmdFocus).
func (m *Model) cmdMode(args []string) []line {
	s := m.sess
	if len(args) == 0 {
		out := []line{sysLine(fmt.Sprintf("Mode: %s. Usage: /mode malware | vuln [class...]", modeLabel(s.Mode)))}
		if s.Mode == app.ModeVuln {
			out = append(out, sysLine("  focus: "+focusLabel(s.VulnFocus)+"  (/focus to change)"))
		}
		return out
	}
	want := s.Mode
	switch strings.ToLower(args[0]) {
	case "malware", "mar", "m":
		want = app.ModeMalware
	case "vuln", "vulnerability", "vrr", "vr", "v":
		want = app.ModeVuln
	default:
		return []line{errLine(fmt.Sprintf("unknown mode %q — use 'malware' or 'vuln'", args[0]))}
	}
	if m.engineStarted && want != s.Mode {
		return []line{errLine("Can't switch mode mid-session — the toolset and report type are fixed when BINNY starts. /quit and relaunch to change mode.")}
	}
	m.modeExplicit = true
	s.Mode = want
	if want == app.ModeMalware {
		s.VulnFocus = nil
		return []line{okLine("Mode → " + modeLabel(s.Mode))}
	}
	// Any trailing args are a focus spec.
	out := []line{okLine("Mode → " + modeLabel(s.Mode))}
	if len(args) > 1 {
		out = append(out, m.cmdFocus(args[1:])...)
	} else {
		out = append(out, sysLine("  focus: "+focusLabel(s.VulnFocus)+"  (/focus <class...> to scope the hunt)"))
	}
	return out
}

// cmdFocus scopes a vuln-mode session to specific vulnerability classes.
func (m *Model) cmdFocus(args []string) []line {
	s := m.sess
	if s.Mode != app.ModeVuln {
		return []line{sysLine("/focus scopes VULN research. Switch with /mode vuln first.")}
	}
	if len(args) == 0 {
		return append([]line{
			sysLine("Vuln focus: " + focusLabel(s.VulnFocus)),
			sysLine("Scope the hunt to one or more classes: /focus memory   ·   /focus auth crypto   ·   /focus all (survey)"),
			sysLine("Classes:"),
		}, sysLine(playbook.VulnClassList()))
	}
	if m.engineStarted {
		return []line{errLine("Focus is fixed once the hunt is running — the objectives are already loaded. /quit and relaunch to re-scope.")}
	}
	if len(args) == 1 {
		switch strings.ToLower(args[0]) {
		case "all", "clear", "none", "survey":
			s.VulnFocus = nil
			return []line{okLine("Focus cleared — BINNY will survey every vulnerability class.")}
		}
	}
	var keys, unknown []string
	seen := map[string]bool{}
	for _, a := range args {
		if c, ok := playbook.LookupVulnClass(a); ok {
			if !seen[c.Key] {
				seen[c.Key] = true
				keys = append(keys, c.Key)
			}
		} else {
			unknown = append(unknown, a)
		}
	}
	if len(keys) == 0 {
		return []line{errLine(fmt.Sprintf("no known vulnerability class in %q — /focus with no args lists them", strings.Join(args, " ")))}
	}
	s.VulnFocus = keys
	out := []line{okLine("Focus → " + focusLabel(keys) + ". BINNY will hunt only these.")}
	if len(unknown) > 0 {
		out = append(out, warnLine("ignored (unknown): "+strings.Join(unknown, ", ")))
	}
	return out
}

// focusLabel renders the focused class names, or "all classes (survey)".
func focusLabel(keys []string) string {
	if len(keys) == 0 {
		return "all classes (survey)"
	}
	var names []string
	for _, k := range keys {
		if c, ok := playbook.LookupVulnClass(k); ok {
			names = append(names, c.Name)
		}
	}
	return strings.Join(names, ", ")
}

func modeLabel(mode app.Mode) string {
	if mode == app.ModeVuln {
		return "VULN_RESEARCH (VRR)"
	}
	return "MALWARE (MAR)"
}

func providerID(m *Model) string {
	if m.sess.Provider == nil {
		return "(none)"
	}
	return m.sess.Provider.ID
}

func helpLines() []line {
	return []line{
		sysLine("Commands:"),
		sysLine("  /start                 direct mode — talk to BINNY and direct it; it uses its tools on demand (no autopilot)"),
		sysLine("  /investigate           autopilot — triage → playbook → investigate → draft a report"),
		sysLine("  /ask                   Q&A mode — question the sample on demand (verify a claim, build a PoC, inspect a function)"),
		sysLine("  /continue              resume from a checkpoint pause (Supervised/Collaborative)"),
		sysLine("  /autonomy <mode>       run mode: autonomous | supervised | collaborative"),
		sysLine("  /stop                  stop investigating early and synthesize the draft now"),
		sysLine("  /draft                 show the current draft report"),
		sysLine("  /findings              show recorded findings, IOCs, classification, coverage"),
		sysLine("  /save                  push the draft to the project report (DRAFT — review first)"),
		sysLine("  /sample [path]         attach the raw binary on disk to enable active extraction"),
		sysLine("  /decompile <path> [proc]  decompile locally — Ghidra for a binary, JADX for an .apk/.xapk (kept on disk, no upload; proc = Ghidra ID like ARM:LE:32:v7 for raw firmware)"),
		sysLine("  /upload                create an OpenAPK project from the attached local APK (reuses the local decompile)"),
		sysLine("  /samples               list this project's extra samples (dropper + payloads, firmware revisions)"),
		sysLine("  /switch <#|label>      point BINNY's read tools at another sample ('primary' = the project's own binary)"),
		sysLine("  /workspace [path]      show/set the persistent sandbox workspace mounted at /work"),
		sysLine("  /refresh               drop this backend project's cached analysis blob"),
		sysLine("  /mode malware|vuln     switch analysis lens (MAR / VRR); /mode vuln <class...> also scopes the hunt"),
		sysLine("  /focus <class...>      vuln only: hunt specific classes (memory, auth, crypto, …); /focus to list, /focus all to survey"),
		sysLine("  /models                list configured LLM providers + models"),
		sysLine("  /model [id]            switch model/provider — no arg opens the ↑/↓ picker"),
		sysLine("  /key [provider]        set/update the BYOK API key (opens key entry)"),
		sysLine("  /endpoint [url|reset]  show/set the API root for the active provider (proxies, gateways, self-host)"),
		sysLine("  /project               re-open the project picker"),
		sysLine("  /settings              open Settings (LLM · keys · token budget)"),
		sysLine("  /budget [n]            show/set this project's token budget (e.g. /budget 200k)"),
		sysLine("  /intel [text]          record analyst intel for this sample"),
		sysLine("  /status                show current session state"),
		sysLine("  /help                  this help"),
		sysLine("  /quit                  exit BINNY"),
		sysLine("Type a message to start BINNY (your text becomes opening intel). While it runs,"),
		sysLine("answer any question it asks by typing; use /stop to cut to the draft."),
		sysLine("Tip: type / for the command palette (↑/↓ select · Tab complete · Enter run); ↑/↓ on an empty line recalls history."),
		sysLine("Sessions auto-save — if BINNY is interrupted, re-open the project (marked ⏵ resumable) to pick up where you left off."),
	}
}

func modelsLines(m *Model) []line {
	out := []line{sysLine("Configured providers (BYOK — set a key with /key, or its env var; local servers need none):")}
	cfg := m.sess.Config
	ids := make([]string, 0, len(cfg.Providers))
	for _, p := range cfg.Providers {
		ids = append(ids, p.ID)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := cfg.Find(id)
		mark := styleErr.Render("no key")
		if p.Local {
			mark = styleOK.Render("local")
		} else if p.HasKey() {
			mark = styleOK.Render("ready")
		}
		active := "  "
		if m.sess.Provider != nil && m.sess.Provider.ID == p.ID {
			active = styleChipHi.Render("▸ ")
		}
		out = append(out, sysLine(fmt.Sprintf("%s%-10s [%s] %s  models: %s",
			active, p.ID, p.Kind, mark, strings.Join(p.Models, ", "))))
		if d := config.DefaultBaseURL(p.ID); p.BaseURL != "" && p.BaseURL != d {
			out = append(out, sysLine(fmt.Sprintf("  %-10s endpoint: %s", "", p.BaseURL)))
		}
	}
	out = append(out, sysLine("Switch with /model <id>, or just /model to pick with ↑/↓."))
	return out
}

func statusLines(m *Model) []line {
	s := m.sess
	proj := "(none — /project to pick)"
	if s.Project != nil {
		proj = fmt.Sprintf("%s [%s, %s]", s.Project.Name, s.Project.Kind, s.Project.Status)
	}
	out := []line{
		sysLine("BINNY session:"),
		sysLine("  provider/model : " + providerID(m) + " / " + s.Model),
		sysLine("  mode           : " + modeLabel(s.Mode)),
	}
	if s.Mode == app.ModeVuln {
		out = append(out, sysLine("  vuln focus     : "+focusLabel(s.VulnFocus)))
	}
	out = append(out,
		sysLine("  phase          : "+string(s.Phase)),
		sysLine("  project        : "+proj),
	)
	if s.Sample != nil {
		out = append(out, sysLine(fmt.Sprintf("  active sample  : %s (extra sample — /switch primary to go back)", s.Sample.DisplayName())))
	}
	return out
}
