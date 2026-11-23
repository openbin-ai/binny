package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"openbin.ai/binny/internal/agent"
	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/experience"
	"openbin.ai/binny/internal/mission"
)

// Crew, missions and experience in the terminal. The mission EDITOR lives in
// BINNY Desktop; here missions are run, listed, sketched in one line, and a
// finished run can be kept as one.

// missionChoice is the mission /investigate will run.
func (m *Model) missionChoice() *mission.Mission {
	if m.mission != nil {
		return m.mission
	}
	return mission.Default()
}

// crewNames renders a mission's crew in order, "‖" joining parallel steps.
func crewNames(ms *mission.Mission) string {
	if ms.Auto && len(ms.Steps) == 0 {
		return "crew assembled after triage → Parity"
	}
	var parts []string
	for _, st := range ms.Steps {
		name := st.RoleID
		if r, ok := agent.RoleByID(st.RoleID); ok {
			name = r.Name
		}
		if st.Checkpoint {
			name += " ⏸"
		}
		if st.Parallel && len(parts) > 0 {
			parts[len(parts)-1] += " ‖ " + name
			continue
		}
		parts = append(parts, name)
	}
	return strings.Join(parts, " → ")
}

// cmdCrew shows the crew: before a run, the lineup; during and after one, who
// did what, what they are doing now, and what each has spent.
func (m *Model) cmdCrew() []line {
	var ms *mission.Mission
	if m.engine != nil {
		ms = m.engine.Mission()
	}
	if ms == nil {
		out := []line{sysLine("The crew — BINNY is the captain; each member is a specialist with its own tools:")}
		for _, r := range agent.Lineup() {
			out = append(out, sysLine(fmt.Sprintf("  %-8s %s", r.Name, r.Title)).by(r.ID))
		}
		next := "/investigate runs mission \"" + m.missionChoice().Name + "\" (" + crewNames(m.missionChoice()) + ")."
		if m.soloRun {
			next = "/investigate will run BINNY solo (no crew). /mission <name> to pick a mission."
		}
		if m.engineStarted {
			next = "This session is running without a crew (direct / Q&A, or /mission solo)."
		}
		return append(out, sysLine(next), sysLine("/missions lists the saved missions."))
	}

	log := m.engine.MissionLog()
	out := []line{sysLine(fmt.Sprintf("Mission %q — %s", ms.Name, crewNames(ms)))}
	if len(log) == 0 {
		return append(out, sysLine("  The crew goes out once BINNY has triaged the sample."))
	}
	total := 0
	for _, r := range log {
		total += r.Spent
		var state string
		switch r.Status {
		case "running":
			state = fmt.Sprintf("▶ working · round %d · ~%s of %s tokens", r.Turns, humanTokens(r.Spent), humanTokens(r.Budget))
		case "skipped":
			state = "⏭ skipped — " + r.Reason
		case "stopped":
			state = fmt.Sprintf("■ stopped (%s) · %d finding(s) · ~%s tokens", r.Reason, r.Findings, humanTokens(r.Spent))
		default:
			state = fmt.Sprintf("✓ done · %d finding(s), %d IOC(s) · ~%s tokens", r.Findings, r.IOCs, humanTokens(r.Spent))
		}
		out = append(out, sysLine(state).by(r.RoleID))
		if r.Tasking != "" && r.Status != "skipped" {
			out = append(out, sysLine("      task: "+api.Abbrev(strings.Join(strings.Fields(r.Tasking), " "), 160)))
		}
	}
	spent := m.engine.Spent()
	out = append(out, sysLine(fmt.Sprintf("  Crew spend ~%s · session ~%s of %s tokens (BINNY's triage and report make up the rest).",
		humanTokens(total), humanTokens(spent), humanTokens(m.engine.Budget()))))
	return out
}

// cmdMissions lists the starters and saved missions.
func (m *Model) cmdMissions() []line {
	out := []line{sysLine("Missions — /mission <name> runs one · /mission solo runs BINNY alone:")}
	current := m.missionChoice().Name
	for _, ms := range mission.List() {
		mark := "  "
		if !m.soloRun && strings.EqualFold(ms.Name, current) {
			mark = styleChipHi.Render("▸ ")
		}
		kind := "saved"
		if ms.Starter {
			kind = "starter"
		}
		out = append(out, sysLine(fmt.Sprintf("%s%-18s [%s] %s", mark, ms.Name, kind, crewNames(ms))))
		if ms.Desc != "" {
			out = append(out, sysLine("      "+ms.Desc))
		}
	}
	return append(out, sysLine("Starters are read-only. Sketch your own with /mission new <name> <crew…>, or build one in BINNY Desktop's mission editor."))
}

// cmdMission picks, shows, creates, deletes or saves a mission.
//
//	/mission                       show what /investigate will run
//	/mission <name>                pick it and start (asks to confirm the spend)
//	/mission solo                  BINNY alone, no crew
//	/mission show <name>           print its steps
//	/mission new <name> <crew…>    save a mission from crew ids (a trailing + = checkpoint after)
//	/mission rm <name>             delete a saved mission
//	/mission save <name>           keep the run that just happened as a mission
func (m *Model) cmdMission(args []string) tea.Cmd {
	if len(args) == 0 {
		if m.soloRun {
			m.append(sysLine("/investigate will run BINNY solo (no crew). /mission <name> to pick a mission, /missions to list them."))
		} else {
			ms := m.missionChoice()
			m.append(sysLine(fmt.Sprintf("Mission: %q — %s. /missions lists the others.", ms.Name, crewNames(ms))))
		}
		return nil
	}
	rest := strings.Join(args[1:], " ")
	switch strings.ToLower(args[0]) {
	case "show":
		ms, err := mission.Load(rest)
		if err != nil {
			m.append(errLine(err.Error()))
			return nil
		}
		m.append(missionLines(ms)...)
		return nil
	case "rm", "delete":
		if err := mission.Delete(rest); err != nil {
			m.append(errLine(err.Error()))
			return nil
		}
		if m.mission != nil && strings.EqualFold(m.mission.Name, rest) {
			m.mission = nil
		}
		m.append(okLine("Deleted mission " + rest + "."))
		return nil
	case "new":
		m.append(m.newMission(args[1:])...)
		return nil
	case "save":
		if m.engine == nil {
			m.append(errLine("Nothing to save yet — /mission save <name> keeps the run you just did as a reusable mission."))
			return nil
		}
		if rest == "" {
			m.append(errLine("Usage: /mission save <name>"))
			return nil
		}
		ms, err := m.engine.RunAsMission(rest)
		if err == nil {
			err = mission.Save(ms)
		}
		if err != nil {
			m.append(errLine("Couldn't save the mission: " + err.Error()))
			return nil
		}
		m.append(okLine(fmt.Sprintf("Saved this run as mission %q — %s. /mission %s runs it on the next sample.", ms.Name, crewNames(ms), ms.Name)))
		return nil
	}

	if m.engineStarted {
		m.append(errLine("A session is already running — a mission is chosen before /investigate. (/mission save <name> keeps this run as a mission.)"))
		return nil
	}
	name := strings.Join(args, " ")
	if strings.EqualFold(name, "solo") || strings.EqualFold(name, "none") {
		m.soloRun, m.mission = true, nil
		m.append(okLine("Solo — /investigate will run BINNY alone, the way it worked before the crew."))
		return nil
	}
	ms, err := mission.Load(name)
	if err != nil {
		m.append(errLine(err.Error() + " — /missions lists them."))
		return nil
	}
	if err := ms.Validate(agent.KnownRole); err != nil {
		m.append(errLine(fmt.Sprintf("Mission %q can't run: %s", ms.Name, err)))
		return nil
	}
	m.mission, m.soloRun = ms, false
	m.append(okLine(fmt.Sprintf("Mission → %q — %s", ms.Name, crewNames(ms))))
	m.requestStart("")
	return nil
}

// newMission saves a mission sketched as crew ids: `/mission new Recon siggy
// twine+ parity` (a trailing + puts a checkpoint after that step, a leading |
// runs it alongside the one before).
func (m *Model) newMission(args []string) []line {
	if len(args) < 2 {
		return []line{sysLine("Usage: /mission new <name> <crew…>   e.g. /mission new Recon siggy twine+ parity   (+ = checkpoint after, |trace = parallel with the step before)")}
	}
	ms := &mission.Mission{Name: args[0]}
	for _, a := range args[1:] {
		st := mission.Step{}
		if strings.HasPrefix(a, "|") {
			st.Parallel, a = true, strings.TrimPrefix(a, "|")
		}
		if strings.HasSuffix(a, "+") {
			st.Checkpoint, a = true, strings.TrimSuffix(a, "+")
		}
		st.RoleID = strings.ToLower(a)
		ms.Steps = append(ms.Steps, st)
	}
	if err := ms.Validate(agent.KnownRole); err != nil {
		return []line{errLine(err.Error() + " — crew: siggy, twine, trace, hex, dex, parity")}
	}
	if err := mission.Save(ms); err != nil {
		return []line{errLine(err.Error())}
	}
	out := []line{okLine(fmt.Sprintf("Saved mission %q — %s. /mission %s runs it.", ms.Name, crewNames(ms), ms.Name))}
	if !ms.HasRole(agent.ParityID) {
		out = append(out, warnLine("No Parity on this mission — its drafts will be labelled unverified."))
	}
	return out
}

func missionLines(ms *mission.Mission) []line {
	kind := "saved"
	if ms.Starter {
		kind = "starter, read-only"
	}
	out := []line{sysLine(fmt.Sprintf("Mission %q (%s) — autonomy: %s", ms.Name, kind, ms.AutonomyPreset()))}
	if ms.Desc != "" {
		out = append(out, sysLine("  "+ms.Desc))
	}
	if ms.Tasking != "" {
		out = append(out, sysLine("  mission tasking: "+ms.Tasking))
	}
	out = append(out, sysLine("  1. BINNY — triage").by(agent.CaptainID))
	if ms.Auto && len(ms.Steps) == 0 {
		out = append(out, sysLine("  …  crew assembled from whoever owns the objectives triage loads, then Parity"))
	}
	for i, st := range ms.Steps {
		name := st.RoleID
		if r, ok := agent.RoleByID(st.RoleID); ok {
			name = r.Name + " — " + r.Title
		}
		var notes []string
		if st.Parallel {
			notes = append(notes, "parallel with the step before")
		}
		if len(st.Focus) > 0 {
			notes = append(notes, "focus: "+strings.Join(st.Focus, ", "))
		}
		if st.Model != "" {
			notes = append(notes, "model: "+st.Model)
		}
		if st.TokenBudget > 0 {
			notes = append(notes, "budget: "+humanTokens(st.TokenBudget))
		}
		if st.Checkpoint {
			notes = append(notes, "⏸ checkpoint after")
		}
		l := fmt.Sprintf("  %d. %s", i+2, name)
		if len(notes) > 0 {
			l += "  (" + strings.Join(notes, " · ") + ")"
		}
		out = append(out, sysLine(l).by(strings.ToLower(st.RoleID)))
		if st.Tasking != "" {
			out = append(out, sysLine("       tasking: "+st.Tasking))
		}
	}
	out = append(out, sysLine(fmt.Sprintf("  %d. BINNY — report", len(ms.Steps)+2)).by(agent.CaptainID))
	if ms.AllowAdd {
		out = append(out, sysLine("  Captain may add steps: on"))
	}
	if !ms.Auto && !ms.HasRole(agent.ParityID) {
		out = append(out, warnLine("No Parity — drafts from this mission are labelled unverified."))
	}
	return out
}

// cmdSkip ends the crew member at work and moves the mission on.
func (m *Model) cmdSkip() tea.Cmd {
	if m.engine == nil || len(m.engine.ActiveCrew()) == 0 {
		m.append(sysLine("No crew member is at work — /skip ends the current mission step."))
		return nil
	}
	if m.agentRunning {
		m.append(sysLine("Press Esc to pause first, then /skip."))
		return nil
	}
	m.append(m.toLines(m.engine.SkipStep())...)
	m.awaiting, m.capPaused, m.checkpoint = false, false, false
	return m.beginRun()
}

// cmdExperience reviews the crew's method notes and the lessons this run
// proposed. Nothing is ever saved on its own: `keep` is the only way in.
//
//	/experience                 list saved notes + this run's proposals
//	/experience keep <n…|all>   save proposals by number
//	/experience rm <id>         prune a saved note
//	/experience edit <id> <text>
func (m *Model) cmdExperience(args []string, raw string) []line {
	var proposed []experience.Note
	if m.engine != nil {
		proposed = m.engine.Lessons()
	}
	if len(args) > 0 {
		switch strings.ToLower(args[0]) {
		case "keep", "save":
			if len(proposed) == 0 {
				return []line{sysLine("This run proposed no lessons to keep.")}
			}
			var out []line
			for _, i := range pickIndexes(args[1:], len(proposed)) {
				n, err := experience.Add(proposed[i])
				if err != nil {
					out = append(out, errLine(fmt.Sprintf("%d: %s", i+1, err)))
					continue
				}
				out = append(out, okLine(fmt.Sprintf("Kept %s [%s] %s", n.ID, n.TargetType, n.Lesson)))
			}
			if len(out) == 0 {
				return []line{sysLine("Usage: /experience keep <n…|all> — the numbers are from the proposals list.")}
			}
			return out
		case "rm", "delete", "prune":
			if len(args) < 2 {
				return []line{sysLine("Usage: /experience rm <id>")}
			}
			if err := experience.Delete(args[1]); err != nil {
				return []line{errLine(err.Error())}
			}
			return []line{okLine("Pruned note " + args[1] + ".")}
		case "edit":
			if len(args) < 3 {
				return []line{sysLine("Usage: /experience edit <id> <the corrected lesson>")}
			}
			text := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(raw, args[0])), args[1]))
			n, err := experience.Update(args[1], text)
			if err != nil {
				return []line{errLine(err.Error())}
			}
			return []line{okLine(fmt.Sprintf("Updated %s: %s", n.ID, n.Lesson))}
		}
	}

	out := []line{sysLine("Experience — the crew's METHOD notes (where to look, how to approach), never conclusions about a sample. Given to matching crew as hints only.")}
	saved := experience.All()
	if len(saved) == 0 {
		out = append(out, sysLine("  No notes saved. Nothing is saved automatically — you keep the lessons worth keeping."))
	}
	group := ""
	for _, n := range saved {
		if n.TargetType != group {
			group = n.TargetType
			out = append(out, sysLine("  "+group+":"))
		}
		who := "any crew"
		if n.Role != "" {
			who = n.Role
		}
		out = append(out, sysLine(fmt.Sprintf("    %s  %s  (from %s)", n.ID, n.Lesson, orDash(n.FromRun))).by(strings.ToLower(who)))
	}
	if len(proposed) > 0 {
		out = append(out, sysLine("  Proposed by this run — /experience keep <n…|all> to save:"))
		for i, n := range proposed {
			out = append(out, sysLine(fmt.Sprintf("    %d. [%s] %s", i+1, n.TargetType, n.Lesson)).by(n.Role))
		}
	}
	return append(out, sysLine("  /experience rm <id> prunes a note · /experience edit <id> <text> corrects one. A confidently wrong lesson is worse than none."))
}

// pickIndexes parses "1 3" / "all" into zero-based indexes below n.
func pickIndexes(args []string, n int) []int {
	var out []int
	seen := map[int]bool{}
	for _, a := range args {
		if strings.EqualFold(a, "all") {
			out = out[:0]
			for i := 0; i < n; i++ {
				out = append(out, i)
			}
			return out
		}
		for _, tok := range strings.Split(a, ",") {
			i, err := strconv.Atoi(strings.TrimSpace(tok))
			if err != nil || i < 1 || i > n || seen[i-1] {
				continue
			}
			seen[i-1] = true
			out = append(out, i-1)
		}
	}
	return out
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}
