package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"unicode"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/experience"
	"openbin.ai/binny/internal/llm"
	"openbin.ai/binny/internal/mission"
	"openbin.ai/binny/internal/tools"
)

// Mission dispatch. With a mission set, the INVESTIGATE stage is not the
// captain's loop: Go code walks the mission's steps and runs each crew member
// to completion in a fresh conversation over its role's tools, all writing to
// the one shared Investigation. No lead model decides who goes next — the
// playbooks already decompose the work, and BINNY has to hold up on weak
// local models. (One opt-in switch, Mission.AllowAdd, lets the captain add
// steps after the planned ones.)

const (
	crewStepRounds     = 12     // provider round-trips a crew step gets
	crewRoundExtension = 6      // more rounds per "continue" at a step's round cap
	crewTokenExtension = 20_000 // more tokens per "continue" at a step's share
	crewMinShare       = 15_000 // a step's share never drops below this
	maxAddedSteps      = 3      // how many steps the captain may add (AllowAdd)
	debriefMax         = 1500   // chars of a debrief kept in the log / briefs
)

// crewState is the Engine's mission bookkeeping.
type crewState struct {
	mission   *mission.Mission // nil = single-agent run
	crewTools *tools.Registry  // set_verdict + the shared notebook
	resolved  bool             // steps resolved against the loaded objectives
	stepIdx   int              // next mission step to start
	active    []*crewRun       // crew at work: one runner, or a parallel group
	log       []StepRecord     // the mission log
	steer     string           // analyst steering waiting for the next step
	added     int              // steps the captain added
	reviewed  bool             // the captain's add-steps review has run

	hints   []experience.Note // saved method notes (opt-in, loaded by Build)
	lessons []experience.Note // lessons this run proposed; nothing is saved until the analyst picks

	providers map[string]llm.Provider // clients for steps that name another provider
}

// crewRun is one crew member at work on one step.
type crewRun struct {
	*Runner
	st       mission.Step
	stepNo   int // 1-based mission step (0 = an interim Parity pass)
	rec      int // index of this run's StepRecord in the log
	budget   int // token share
	maxTurns int
	model    string
	provider llm.Provider
	scope    []string // Parity: the finding ids it was asked to verify
	nudged   bool     // Parity was reminded of findings it skipped
	interim  bool     // a verify-each-step Parity pass, not a mission step
	pauseEnd bool     // checkpoint when this run finishes
	done     bool
}

// StepRecord is one entry of the mission log: who ran, with what tasking, and
// what they handed back.
type StepRecord struct {
	Step       int      `json:"step"` // 1-based mission step (0 = interim Parity pass)
	RoleID     string   `json:"role"`
	Name       string   `json:"name"`
	Tasking    string   `json:"tasking,omitempty"`
	Objectives []string `json:"objectives,omitempty"`
	Model      string   `json:"model,omitempty"`
	// Status is running | done | skipped | stopped.
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"` // why it was skipped / stopped
	Debrief string `json:"debrief,omitempty"`
	// Handoffs are the pointers this step left for named crewmates.
	Handoffs []Handoff `json:"handoffs,omitempty"`
	Findings int       `json:"findings"`
	IOCs     int       `json:"iocs"`
	Spent    int       `json:"spent"`
	Turns    int       `json:"turns"`
	Budget   int       `json:"budget,omitempty"`
}

// SetMission puts the engine under a mission: the crew, not the captain,
// works the INVESTIGATE stage. Call it before Start. The engine keeps its own
// copy, since a run may add steps.
func (e *Engine) SetMission(m *mission.Mission) {
	if m == nil {
		e.mission = nil
		return
	}
	e.mission = m.Clone(m.Name)
	e.mission.Starter = m.Starter
	e.ensureCrewTools()
}

func (e *Engine) ensureCrewTools() {
	if e.crewTools == nil {
		e.crewTools = newCrewTools(e.inv, nil)
	}
}

// SetExperience hands the engine the saved method notes. They are matched to
// each crew member by target type and role and injected as hints.
func (e *Engine) SetExperience(notes []experience.Note) { e.hints = notes }

// Mission returns the mission being run (nil on a single-agent run).
func (e *Engine) Mission() *mission.Mission { return e.mission }

// MissionLog returns a copy of the mission log, with live spend for the crew
// still at work.
func (e *Engine) MissionLog() []StepRecord {
	out := append([]StepRecord(nil), e.log...)
	for _, cr := range e.active {
		if cr.rec < len(out) {
			out[cr.rec].Spent, out[cr.rec].Turns = cr.used, cr.turns
		}
	}
	return out
}

// Lessons returns the method notes this run proposed. None is saved until
// the analyst keeps it.
func (e *Engine) Lessons() []experience.Note { return append([]experience.Note(nil), e.lessons...) }

// ActiveCrew returns the role ids of the crew at work right now.
func (e *Engine) ActiveCrew() []string {
	var ids []string
	for _, cr := range e.active {
		if !cr.done {
			ids = append(ids, cr.agentID())
		}
	}
	return ids
}

// inMission reports whether the crew owns the loop right now.
func (e *Engine) inMission() bool { return e.mission != nil && e.stage == stageInvestigate }

// asker is the runner an outstanding ask_user came from.
func (e *Engine) asker() *Runner {
	if e.inMission() {
		for _, cr := range e.active {
			if !cr.done {
				return cr.Runner
			}
		}
	}
	return e.Runner
}

// target describes this run for experience matching.
func (e *Engine) target() experience.Target {
	return experience.Target{
		Kind:  string(e.sess.Project.Kind),
		Mode:  string(e.sess.Mode),
		Types: e.inv.Snapshot().MalwareTypes,
	}
}

// --- the dispatch loop -----------------------------------------------------

// stepMission advances the mission by one provider round (one per crew
// member in a parallel group).
func (e *Engine) stepMission(ctx context.Context) StepResult {
	var lines []Line
	if !e.resolved {
		lines = append(lines, e.resolveMission()...)
	}
	if len(e.active) == 0 {
		// The mission total gates each new step; a step's own share gates it
		// once it is running.
		if e.stepIdx < len(e.mission.Steps) && e.spentTokens >= e.maxTokens {
			e.capReason = "tokens"
			next := roleName(e.mission.Steps[e.stepIdx].RoleID)
			return StepResult{CapReached: "tokens", Lines: append(lines, Line{Kind: "phase", Text: fmt.Sprintf(
				"Mission budget reached (~%dk tokens) before %s could start — paused, not finished.", e.spentTokens/1000, next)})}
		}
		started := e.startNext()
		lines = append(lines, started...)
		if len(e.active) == 0 {
			if e.mission.AllowAdd && !e.reviewed {
				more, err := e.captainReview(ctx)
				lines = append(lines, more...)
				if err != nil {
					return StepResult{Err: err, Lines: lines}
				}
				if e.stepIdx < len(e.mission.Steps) {
					return StepResult{Lines: lines}
				}
			}
			return StepResult{Lines: append(lines, e.finishMission()...)}
		}
		// Announce who is going out before their first round runs, so a UI
		// shows the step card ahead of the text that streams into it.
		return StepResult{Lines: lines}
	}
	if len(e.active) > 1 {
		return e.stepGroup(ctx, lines)
	}

	cr := e.active[0]
	name := cr.role.Name
	if cr.turns >= cr.maxTurns {
		e.capReason = "rounds"
		return StepResult{CapReached: "rounds", Agent: cr.agentID(), Lines: append(lines, Line{Kind: "phase", Agent: cr.agentID(), Text: fmt.Sprintf(
			"%s has used its %d rounds and isn't finished — paused. Continue gives it %d more; /skip moves on without it.", name, cr.maxTurns, crewRoundExtension)})}
	}
	if cr.used >= cr.budget {
		e.capReason = "tokens"
		return StepResult{CapReached: "tokens", Agent: cr.agentID(), Lines: append(lines, Line{Kind: "phase", Agent: cr.agentID(), Text: fmt.Sprintf(
			"%s has used its share (~%dk tokens) and wants %dk more — paused. Continue grants it; /skip moves on without it.", name, cr.used/1000, crewTokenExtension/1000)})}
	}

	e.rounds++
	t := cr.turn(ctx, turnOpts{provider: cr.provider, model: cr.model, maxTokens: e.perTurnMax, sink: e.streamSink, step: cr.stepNo})
	lines = append(lines, t.lines...)
	if t.err != nil {
		return StepResult{Err: t.err, Lines: lines, Agent: cr.agentID()}
	}
	e.account(t.usage)
	switch {
	case t.refused:
		return StepResult{Lines: lines, Refused: true, Agent: cr.agentID()}
	case t.ask != nil:
		q := e.suspendOnAsk(t)
		if strings.TrimSpace(t.resp.Text()) == "" {
			lines = append(lines, Line{Kind: "binny", Agent: cr.agentID(), Text: q})
		}
		return StepResult{Lines: lines, AwaitQuestion: q, Agent: cr.agentID()}
	case !t.ended:
		return StepResult{Lines: lines, Agent: cr.agentID()}
	}

	// The crew member ended its turn. Parity gets one reminder if it left
	// findings without a verdict; everyone else is done.
	if cr.role.ID == ParityID && !cr.nudged {
		if left := e.pendingVerdicts(cr.scope); len(left) > 0 {
			cr.nudged = true
			cr.appendUser(fmt.Sprintf("These findings still have no verdict: %s. Re-read their evidence and set_verdict on each — or, if you are out of rounds for them, say so in your debrief and they will be reported as unverified.", strings.Join(left, ", ")))
			return StepResult{Lines: lines, Agent: cr.agentID()}
		}
	}
	agent := cr.agentID()
	more, pause := e.finishRun(cr, "done", "")
	return StepResult{Lines: append(lines, more...), Checkpoint: pause, Agent: agent}
}

// stepGroup runs one round for every crew member of a parallel group, at
// most Concurrency() at a time. Each member's lines stay together, so the
// transcript reads as whole turns rather than two agents interleaved line by
// line. Members of a group can't ask the analyst questions or pause on a cap:
// one that runs out of budget hands back what it has.
func (e *Engine) stepGroup(ctx context.Context, lines []Line) StepResult {
	type outcome struct {
		t   turnResult
		ran bool
	}
	outs := make([]outcome, len(e.active))
	limit := 3
	if e.sess.Provider != nil {
		limit = e.sess.Provider.Concurrency()
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	// finishRun edits e.active, so walk a copy.
	group := append([]*crewRun(nil), e.active...)
	for i, cr := range group {
		if cr.done {
			continue
		}
		if cr.turns >= cr.maxTurns || cr.used >= cr.budget {
			continue // handled below: finishes with what it has
		}
		wg.Add(1)
		go func(i int, cr *crewRun) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			outs[i] = outcome{ran: true, t: cr.turn(ctx, turnOpts{
				provider: cr.provider, model: cr.model, maxTokens: e.perTurnMax, step: cr.stepNo, noAsk: true,
			})}
		}(i, cr)
	}
	wg.Wait()

	var firstErr error
	pause := false
	for i, cr := range group {
		if cr.done {
			continue
		}
		o := outs[i]
		if !o.ran {
			why := fmt.Sprintf("used its %d rounds", cr.maxTurns)
			if cr.used >= cr.budget {
				why = fmt.Sprintf("used its share (~%dk tokens)", cr.used/1000)
			}
			more, p := e.finishRun(cr, "stopped", why)
			lines, pause = append(lines, more...), pause || p
			continue
		}
		e.rounds++
		lines = append(lines, o.t.lines...)
		if o.t.err != nil {
			if firstErr == nil {
				firstErr = o.t.err
			}
			continue // nothing was appended; this member retries next step
		}
		e.account(o.t.usage)
		if o.t.refused {
			more, p := e.finishRun(cr, "stopped", "the model declined the task")
			lines, pause = append(lines, more...), pause || p
			continue
		}
		if o.t.ended {
			more, p := e.finishRun(cr, "done", "")
			lines, pause = append(lines, more...), pause || p
		}
	}
	if firstErr != nil {
		return StepResult{Err: firstErr, Lines: lines}
	}
	return StepResult{Lines: lines, Checkpoint: pause && len(e.active) == 0}
}

// resolveMission fixes the mission's steps once the objectives are known:
// assembles an auto mission's crew, places checkpoints for the session's
// autonomy, and runs the coverage check.
func (e *Engine) resolveMission() []Line {
	e.resolved = true
	e.ensureCrewTools()
	m := e.mission
	objs := e.inv.Snapshot().Objectives
	kind := e.sess.Project.Kind
	if m.Auto {
		ok, _ := sandboxReady(e.sess)
		m.Steps = autoSteps(objs, kind, e.sess.Mode, ok)
		if e.sess.Autonomy != app.Autonomous {
			m.ApplyAutonomy(mission.Supervised)
		}
	}
	names := make([]string, 0, len(m.Steps))
	for _, st := range m.Steps {
		n := roleName(st.RoleID)
		if st.Parallel && len(names) > 0 {
			names[len(names)-1] += " ‖ " + n
			continue
		}
		names = append(names, n)
	}
	lines := []Line{{Kind: "phase", Text: fmt.Sprintf("Mission %q — BINNY → %s → report", m.Name, strings.Join(names, " → "))}}
	if gaps := CoverageGaps(m, objs, kind); len(gaps) > 0 {
		lines = append(lines, Line{Kind: "sys", Text: fmt.Sprintf(
			"Coverage: no crew member on this mission owns %s — they will be reported as uncovered.", strings.Join(gaps, ", "))})
	}
	if !m.HasRole(ParityID) {
		lines = append(lines, Line{Kind: "sys", Text: "No Parity on this mission — the draft will be labelled UNVERIFIED."})
	}
	return lines
}

// startNext launches the next step that can run (and any steps marked
// parallel with it), skipping — visibly — those that can't.
func (e *Engine) startNext() []Line {
	var lines []Line
	steps := e.mission.Steps
	for e.stepIdx < len(steps) && len(e.active) == 0 {
		first := e.stepIdx
		last := first
		for last+1 < len(steps) && steps[last+1].Parallel {
			last++
		}
		e.stepIdx = last + 1
		parallel := last > first
		for i := first; i <= last; i++ {
			cr, ls := e.launch(steps[i], i+1, parallel, false)
			lines = append(lines, ls...)
			if cr != nil {
				cr.pauseEnd = steps[i].Checkpoint
				e.active = append(e.active, cr)
			}
		}
		// Split what is left of the mission budget across this group and the
		// steps still to come.
		for _, cr := range e.active {
			cr.budget = e.shareFor(cr.st, len(e.active))
			e.log[cr.rec].Budget = cr.budget
		}
	}
	if len(e.active) > 0 {
		e.steer = "" // delivered in the kickoffs just written
	}
	return lines
}

// launch builds the runner for one step, or records why the step is skipped.
func (e *Engine) launch(st mission.Step, stepNo int, parallel, interim bool) (*crewRun, []Line) {
	rec := StepRecord{Step: stepNo, RoleID: strings.ToLower(st.RoleID), Name: roleName(st.RoleID), Tasking: st.Tasking}
	skip := func(reason string) (*crewRun, []Line) {
		rec.Status, rec.Reason = "skipped", reason
		e.log = append(e.log, rec)
		return nil, []Line{{Kind: "skip", Agent: rec.RoleID, Text: fmt.Sprintf("%s skipped — %s", rec.Name, reason)}}
	}
	role, ok := RoleByID(st.RoleID)
	if !ok {
		return skip("no such crew member")
	}
	view := role.view(e.reg, e.crewTools)
	if parallel {
		// Members of a parallel group can't suspend the loop on a question, and
		// must not re-point the shared read tools under each other.
		view = view.Without(AskUserToolName, "switch_sample", "decompile_sample")
	}
	if why := cantRun(role, e.sess, view); why != "" {
		return skip(why)
	}

	cr := &crewRun{st: st, stepNo: stepNo, interim: interim, maxTurns: crewStepRounds}
	var kickoff string
	if role.ID == ParityID {
		cr.scope = e.inv.Unverified()
		if len(cr.scope) == 0 {
			// Nothing to check is still a completed verification pass.
			e.inv.SetVerification(VerificationDone)
			return skip("there are no unverified findings to check")
		}
		kickoff = e.parityKickoff(cr.scope)
		rec.Tasking = fmt.Sprintf("Verify %d finding(s): %s", len(cr.scope), strings.Join(cr.scope, ", "))
	} else {
		objs := assignedObjectives(st, role, e.inv.Snapshot().Objectives, e.sess.Project.Kind)
		tasking := strings.TrimSpace(e.expandTasking(st.Tasking))
		if tasking == "" {
			if len(objs) > 0 {
				tasking = "Work the objectives assigned to you below."
			} else {
				tasking = role.DefaultTask
			}
		}
		rec.Tasking = tasking
		for _, o := range objs {
			rec.Objectives = append(rec.Objectives, o.ID)
		}
		kickoff = e.crewKickoff(role, tasking, objs, stepNo)
	}

	provider, model, err := e.providerFor(st.Model)
	if err != nil {
		return skip("can't use model " + st.Model + ": " + err.Error())
	}
	cr.provider, cr.model = provider, model
	cr.budget = e.shareFor(st, 1)
	cr.Runner = &Runner{
		role:             &role,
		system:           crewSystem(e.system, role),
		reg:              view,
		messages:         []llm.Message{llm.UserText(kickoff)},
		compactThreshold: e.compactThreshold,
	}
	rec.Status, rec.Model, rec.Budget = "running", model, cr.budget
	cr.rec = len(e.log)
	e.log = append(e.log, rec)

	label := fmt.Sprintf("%s (%s) — %s", role.Name, role.Title, api.Abbrev(strings.Join(strings.Fields(rec.Tasking), " "), 220))
	return cr, []Line{{Kind: "step", Agent: role.ID, Text: label}}
}

// finishRun closes a crew member's step: records its debrief and spend,
// collects any lesson it proposed, and — on a verify-each-step mission —
// queues Parity over what it just found. It reports whether the mission
// should pause here (the step's checkpoint).
func (e *Engine) finishRun(cr *crewRun, status, reason string) ([]Line, bool) {
	cr.done = true
	role := *cr.role
	debrief := cr.lastText()
	rec := &e.log[cr.rec]
	rec.Status, rec.Reason = status, reason
	rec.Spent, rec.Turns = cr.used, cr.turns
	snap := e.inv.Snapshot()
	for _, f := range snap.Findings {
		if cr.stepNo > 0 && f.Step == cr.stepNo && f.FoundBy == role.ID {
			rec.Findings++
		}
	}
	for _, i := range snap.IOCs {
		if cr.stepNo > 0 && i.Step == cr.stepNo && i.FoundBy == role.ID {
			rec.IOCs++
		}
	}

	var lines []Line
	if role.ID == ParityID {
		e.inv.SetVerification(VerificationDone)
		c, d, r, u := verdictCounts(snap.Findings, cr.scope)
		tally := fmt.Sprintf("%d confirmed, %d downgraded, %d rejected", c, d, r)
		if u > 0 {
			tally += fmt.Sprintf(", %d not reached (unverified)", u)
		}
		if debrief == "" {
			debrief = tally
		} else {
			debrief = tally + ". " + debrief
		}
		for _, f := range snap.Findings {
			if f.Verdict == "" || !containsFold(cr.scope, f.ID) {
				continue
			}
			lines = append(lines, Line{Kind: "verdict", Agent: role.ID, Text: fmt.Sprintf("%s %s — %s", f.ID, f.Verdict, api.Abbrev(f.VerdictNote, 160))})
		}
	} else {
		debrief = e.takeLessons(role, debrief)
		debrief, rec.Handoffs = HandoffsFrom(debrief, role.ID)
		if debrief == "" {
			debrief = fmt.Sprintf("(no debrief written) recorded %d finding(s), %d IOC(s)", rec.Findings, rec.IOCs)
		}
	}
	if reason != "" {
		debrief = strings.TrimSpace("[stopped: " + reason + "] " + debrief)
	}
	rec.Debrief = clip(debrief, debriefMax)
	lines = append(lines, Line{Kind: "debrief", Agent: role.ID, Text: fmt.Sprintf(
		"%s debrief (%d finding(s), %d IOC(s), ~%dk tokens): %s%s", role.Name, rec.Findings, rec.IOCs, cr.used/1000, rec.Debrief, HandoffLines(rec.Handoffs))})

	// Drop the run from the active set.
	live := e.active[:0]
	for _, a := range e.active {
		if a != cr {
			live = append(live, a)
		}
	}
	e.active = live

	pause := cr.pauseEnd
	// Verify-each-step: once the step (or the whole parallel group) is back,
	// Parity checks what it found before the mission moves on.
	if e.mission != nil && e.mission.VerifyEachStep && role.ID != ParityID && len(e.active) == 0 &&
		e.mission.HasRole(ParityID) && len(e.inv.Unverified()) > 0 {
		p, ls := e.launch(mission.Step{RoleID: ParityID}, 0, false, true)
		lines = append(lines, ls...)
		if p != nil {
			p.pauseEnd = pause
			e.active = append(e.active, p)
			pause = false
		}
	}
	return lines, pause && len(e.active) == 0
}

// finishMission hands the loop back to the captain for synthesis.
func (e *Engine) finishMission() []Line {
	var lines []Line
	if e.inv.Snapshot().Verification != VerificationDone {
		e.inv.SetVerification(VerificationNone)
		lines = append(lines, Line{Kind: "sys", Text: "No verification pass ran — the draft is labelled UNVERIFIED."})
	}
	c, t := e.inv.Coverage()
	e.stage = stageSynthesize
	return append(lines, Line{Kind: "phase", Text: fmt.Sprintf("Mission complete (%d/%d objectives). Phase: SYNTHESIZE — BINNY writes the report.", c, t)})
}

// abandonMission ends the mission early (the analyst hit /stop): crew at work
// are recorded as stopped, and the draft is unverified unless Parity already
// finished.
func (e *Engine) abandonMission() {
	if e.mission == nil {
		return
	}
	// A question a crew member was waiting on dies with its conversation: the
	// answer must not land in the captain's history as an orphan tool result.
	if len(e.active) > 0 && e.pending != nil && e.pending.kind == askTool {
		e.pending = nil
	}
	for _, cr := range append([]*crewRun(nil), e.active...) {
		e.finishRun(cr, "stopped", "the analyst stopped the mission")
	}
	e.dropActive("the analyst stopped the mission")
	if e.inv.Snapshot().Verification != VerificationDone {
		e.inv.SetVerification(VerificationNone)
	}
}

// SkipStep ends the crew member(s) at work and moves the mission on — the
// "carry on without Hex" choice at a cap pause. Their findings so far stand.
func (e *Engine) SkipStep() []Line {
	if !e.inMission() || len(e.active) == 0 {
		return nil
	}
	e.capReason = ""
	e.pending = nil
	var lines []Line
	for _, cr := range append([]*crewRun(nil), e.active...) {
		if cr.interim {
			cr.pauseEnd = false
		}
		ls, _ := e.finishRun(cr, "stopped", "skipped by the analyst")
		lines = append(lines, ls...)
	}
	// A skip must not leave an interim Parity pass queued behind it.
	e.dropActive("skipped by the analyst")
	return lines
}

// dropActive discards whatever is still in the active set (an interim Parity
// pass queued by the run that was just ended) and marks it stopped in the log.
func (e *Engine) dropActive(reason string) {
	for _, cr := range e.active {
		cr.done = true
		e.log[cr.rec].Status, e.log[cr.rec].Reason = "stopped", reason
	}
	e.active = nil
}

// continueCrewCap extends a crew member's own cap. ok=false means the pause
// wasn't a crew step's (the caller falls through to the session-level caps).
func (e *Engine) continueCrewCap() ([]Line, bool) {
	if !e.inMission() || len(e.active) != 1 {
		return nil, false
	}
	cr := e.active[0]
	switch e.capReason {
	case "rounds":
		cr.maxTurns += crewRoundExtension
		e.capReason = ""
		return []Line{{Kind: "ok", Agent: cr.agentID(), Text: fmt.Sprintf(
			"Continuing: %s gets +%d rounds. This spends more of your BYOK tokens.", cr.role.Name, crewRoundExtension)}}, true
	case "tokens":
		cr.budget += crewTokenExtension
		e.maxTokens += crewTokenExtension
		e.log[cr.rec].Budget = cr.budget
		e.capReason = ""
		return []Line{{Kind: "ok", Agent: cr.agentID(), Text: fmt.Sprintf(
			"Continuing: %s gets +%dk tokens (mission budget now ~%dk). This spends more of your BYOK tokens.", cr.role.Name, crewTokenExtension/1000, e.maxTokens/1000)}}, true
	}
	return nil, false
}

// shareFor is a step's token share: its own budget when the mission sets
// one, else an even split of what is left of the mission total across the
// steps still to run.
func (e *Engine) shareFor(st mission.Step, peers int) int {
	if st.TokenBudget > 0 {
		return st.TokenBudget
	}
	left := e.maxTokens - e.spentTokens
	// stepIdx already points past the group being launched, so the steps
	// still to run are the group itself (peers) plus everything after it.
	remaining := len(e.mission.Steps) - e.stepIdx + peers
	if remaining < 1 {
		remaining = 1
	}
	share := left / remaining
	if share < crewMinShare {
		share = crewMinShare
	}
	return share
}

// providerFor resolves a step's model. "" is the session's; "provider/model"
// crosses to another configured provider (the usual reason: Parity on a
// different model from the finder); anything else is a model id on the
// session's provider.
func (e *Engine) providerFor(model string) (llm.Provider, string, error) {
	model = strings.TrimSpace(model)
	if model == "" {
		return e.provider, e.sess.Model, nil
	}
	if i := strings.IndexByte(model, '/'); i > 0 && e.sess.Config != nil {
		if p := e.sess.Config.Find(model[:i]); p != nil {
			if e.sess.Provider != nil && p.ID == e.sess.Provider.ID {
				return e.provider, model[i+1:], nil
			}
			if c, ok := e.providers[p.ID]; ok {
				return c, model[i+1:], nil
			}
			c, err := llm.New(*p)
			if err != nil {
				return nil, "", err
			}
			if e.providers == nil {
				e.providers = map[string]llm.Provider{}
			}
			e.providers[p.ID] = c
			return c, model[i+1:], nil
		}
	}
	return e.provider, model, nil
}

// pendingVerdicts returns the in-scope findings that still carry no verdict.
func (e *Engine) pendingVerdicts(scope []string) []string {
	var left []string
	for _, id := range e.inv.Unverified() {
		if containsFold(scope, id) {
			left = append(left, id)
		}
	}
	return left
}

// --- the captain's add-steps review (Mission.AllowAdd) ----------------------

// captainReview gives the captain one look at the debriefs after the planned
// steps and lets it dispatch up to maxAddedSteps more. It is a single
// provider call with a single tool; the conversation isn't kept.
func (e *Engine) captainReview(ctx context.Context) ([]Line, error) {
	var b strings.Builder
	writeSampleHeader(&b, e.sess)
	b.WriteString(").\n\nMISSION REVIEW. Your crew has finished the planned steps. Their debriefs:\n")
	b.WriteString(e.debriefs())
	snap := e.inv.Snapshot()
	fmt.Fprintf(&b, "\nCoverage: %s\n\nRecorded evidence:\n%s\n", snap.CoverageLine(), snap.EvidenceSummary())
	b.WriteString("Crew you can dispatch:\n")
	for _, r := range Roles() {
		if r.ID == ParityID || cantRun(r, e.sess, r.view(e.reg, e.crewTools)) != "" {
			continue
		}
		fmt.Fprintf(&b, "- %s — %s\n", r.ID, r.Title)
	}
	fmt.Fprintf(&b, "\nIf a specific gap is worth more work, call dispatch_crew (at most %d times) with the crew member and a precise tasking. If the crew's work is enough for the report, reply without calling it.\n", maxAddedSteps)

	e.rounds++
	resp, err := e.provider.Stream(ctx, llm.Request{
		System:   e.system,
		Messages: []llm.Message{llm.UserText(b.String())},
		Tools: []llm.Tool{tools.Def("dispatch_crew",
			"Add one more step to the mission: send a crew member back out with a precise tasking.",
			tools.Obj(map[string]any{
				"role":    tools.StrProp("crew member id, e.g. trace, hex, twine"),
				"tasking": tools.StrProp("exactly what to establish, and where to start"),
			}, "role", "tasking"))},
		Model:     e.sess.Model,
		MaxTokens: e.perTurnMax,
	}, nil)
	if err != nil {
		e.rounds--
		return nil, err
	}
	e.reviewed = true
	e.account(resp.Usage)
	e.used += resp.Usage.InputTokens + resp.Usage.CacheCreationTokens + resp.Usage.OutputTokens

	var lines []Line
	if txt := strings.TrimSpace(resp.Text()); txt != "" {
		lines = append(lines, Line{Kind: "binny", Text: txt})
	}
	parityRan := e.inv.Snapshot().Verification == VerificationDone
	for _, c := range resp.ToolCalls() {
		if c.Name != "dispatch_crew" || e.added >= maxAddedSteps {
			continue
		}
		var a struct{ Role, Tasking string }
		if json.Unmarshal(c.Input, &a) != nil || strings.TrimSpace(a.Tasking) == "" {
			continue
		}
		role, ok := RoleByID(a.Role)
		if !ok || role.ID == ParityID {
			continue
		}
		e.mission.Steps = append(e.mission.Steps, mission.Step{RoleID: role.ID, Tasking: strings.TrimSpace(a.Tasking)})
		e.added++
		lines = append(lines, Line{Kind: "phase", Text: fmt.Sprintf("BINNY added a step: %s — %s", role.Name, api.Abbrev(a.Tasking, 200))})
	}
	// What the added steps find gets verified too.
	if e.added > 0 && parityRan && e.mission.HasRole(ParityID) {
		e.mission.Steps = append(e.mission.Steps, mission.Step{RoleID: ParityID})
	}
	return lines, nil
}

// --- kickoffs and briefs ---------------------------------------------------

// expandTasking fills the run-time placeholders in a tasking prompt.
func (e *Engine) expandTasking(t string) string {
	if !strings.Contains(t, "{") {
		return t
	}
	snap := e.inv.Snapshot()
	sample := e.sess.Project.Name
	if e.sess.Sample != nil {
		sample = e.sess.Sample.DisplayName()
	}
	class := "unclassified"
	if len(snap.MalwareTypes) > 0 {
		class = strings.Join(snap.MalwareTypes, ", ")
	}
	findings := strings.TrimSpace(snap.EvidenceSummary())
	if findings == "" {
		findings = "(nothing recorded yet)"
	}
	return strings.NewReplacer("{sample}", sample, "{classification}", class, "{findings}", findings).Replace(t)
}

// crewKickoff is a crew member's opening message: the sample, what triage
// decided, its tasking and objectives, and everything the crew before it
// recorded — so it builds on their work in a fresh context.
func (e *Engine) crewKickoff(role Role, tasking string, objs []Objective, stepNo int) string {
	var b strings.Builder
	writeSampleHeader(&b, e.sess)
	b.WriteString(").\n")
	if s := strings.TrimSpace(e.sess.Intel); s != "" {
		fmt.Fprintf(&b, "\nAnalyst intel: %s\n", s)
	}
	snap := e.inv.Snapshot()
	if len(snap.MalwareTypes) > 0 {
		fmt.Fprintf(&b, "\nTriage classified it as: %s (confidence %s).\n", strings.Join(snap.MalwareTypes, ", "), orUnknown(snap.Confidence))
	}
	who := role.Name
	if role.ID == CaptainID {
		who = "BINNY, on a Captain task card"
	}
	fmt.Fprintf(&b, "\nMISSION %q — step %d. You are %s.\n", e.mission.Name, stepNo, who)
	b.WriteString(MissionCrewLine(e.mission.Steps, stepNo, role.ID))
	if t := strings.TrimSpace(e.expandTasking(e.mission.Tasking)); t != "" {
		fmt.Fprintf(&b, "\nMission tasking (the whole crew has this):\n%s\n", t)
	}
	fmt.Fprintf(&b, "\nYOUR TASKING:\n%s\n", tasking)
	if len(objs) > 0 && len(e.pbs) > 0 {
		brief := investigateBrief(e.pbs, objs, e.sess.Project.Kind, e.sess.Mode, e.sess.VulnFocus)
		brief = strings.ReplaceAll(brief, "PHASE — INVESTIGATE. ", "")
		brief = strings.ReplaceAll(brief, "I'll move you to synthesis", "then give your debrief")
		b.WriteString("\n" + brief)
	}

	if ev := strings.TrimSpace(snap.EvidenceSummary()); len(snap.Findings)+len(snap.IOCs)+len(snap.Artifacts) > 0 {
		fmt.Fprintf(&b, "\nRECORDED SO FAR by the crew before you — build on it, don't redo it:\n%s\n", ev)
	}
	if nb := snap.NotebookSummary(); nb != "" {
		fmt.Fprintf(&b, "\nSHARED NOTEBOOK — what the crew already worked out (read_notes for the current list):\n%s", nb)
	}
	if d := e.debriefs(); d != "" {
		fmt.Fprintf(&b, "\nCREW DEBRIEFS so far:\n%s", d)
	}
	b.WriteString(HandoffsFor(role.ID, e.log))
	if hints := experience.Match(e.hints, e.target(), role.ID); len(hints) > 0 {
		b.WriteString("\nEXPERIENCE — method hints from past runs on this kind of target. They say WHERE TO LOOK and nothing about this sample: verify everything here, and a hint is never an evidence_ref.\n")
		for _, h := range hints {
			fmt.Fprintf(&b, "- %s\n", h.Lesson)
		}
	}
	if s := strings.TrimSpace(e.steer); s != "" {
		fmt.Fprintf(&b, "\nANALYST STEERING (given at the last checkpoint):\n%s\n", s)
	}
	b.WriteString("\nBegin. When you are done, stop calling tools and give your DEBRIEF. If this run taught you a reusable METHOD for this kind of target — where to look, how to approach it, never a conclusion about this sample — you may end the debrief with one line starting `LESSON:`.\n")
	return b.String()
}

// parityKickoff lists the findings to verify, most severe first.
func (e *Engine) parityKickoff(scope []string) string {
	var b strings.Builder
	writeSampleHeader(&b, e.sess)
	b.WriteString(").\n")
	b.WriteString(ParityBrief(e.mission.Name, e.inv.Snapshot(), scope))
	b.WriteString(HandoffsFor(ParityID, e.log))
	return b.String()
}

// ParityBrief is the body of Parity's kickoff: the findings in scope with the
// evidence each cites, and how to rule. Shared with BINNY Desktop's mission
// runner, which has its own target header.
func ParityBrief(missionName string, snap InvestigationSnapshot, scope []string) string {
	var b strings.Builder
	if len(snap.MalwareTypes) > 0 {
		fmt.Fprintf(&b, "\nTriage classified it as: %s (confidence %s) — a claim like any other; don't lean on it.\n", strings.Join(snap.MalwareTypes, ", "), orUnknown(snap.Confidence))
	}
	var fs []Finding
	for _, f := range snap.Findings {
		if containsFold(scope, f.ID) {
			fs = append(fs, f)
		}
	}
	sort.SliceStable(fs, func(i, j int) bool { return severityRank[fs[i].Severity] > severityRank[fs[j].Severity] })

	fmt.Fprintf(&b, "\nVERIFICATION PASS — MISSION %q. The crew recorded the %d finding(s) below. You start from a clean slate: for EACH one, re-read the evidence it cites with your own tools, then set_verdict.\n\n", missionName, len(fs))
	for _, f := range fs {
		by := f.FoundBy
		if by == "" {
			by = CaptainID
		}
		cwe := ""
		if f.CWE != "" {
			cwe = " " + f.CWE
		}
		fmt.Fprintf(&b, "%s [%s/%s%s] recorded by %s\n  claim: %s\n  evidence: %s\n", f.ID, f.Category, f.Severity, cwe, by, f.Note, strings.Join(f.EvidenceRefs, ", "))
		if f.IsVuln() {
			fmt.Fprintf(&b, "  reachability claimed: %s\n  source: %s\n  sink: %s\n", f.Reachability, f.Source, f.Sink)
			if len(f.Path) > 0 {
				fmt.Fprintf(&b, "  path: %s\n", strings.Join(f.Path, " → "))
			}
		}
	}
	b.WriteString("\nHOW TO RULE:\n")
	b.WriteString("- confirmed — you read the cited function/string/data and it shows what the finding claims.\n")
	b.WriteString("- downgraded — something is there, but the finding overstates it (a capability inferred from an import alone, a path with an unproven hop, a severity the evidence doesn't carry). Give the lower severity.\n")
	b.WriteString("- rejected — the evidence doesn't exist, doesn't say that, or the claim is a guess. Rejected findings are kept as negative results, not thrown away.\n")
	fmt.Fprintf(&b, "- You have about %d rounds. Take the highest-severity findings first; a finding you don't reach stays unverified, which is honest. Never confirm one you didn't re-read.\n", crewStepRounds)
	b.WriteString("\nBegin. When every finding has a verdict, stop calling tools and give your DEBRIEF.\n")
	return b.String()
}

// debriefs renders the mission log's debriefs and skips, one entry each.
func (e *Engine) debriefs() string {
	var b strings.Builder
	for _, r := range e.log {
		switch r.Status {
		case "skipped":
			fmt.Fprintf(&b, "- %s: SKIPPED — %s\n", r.Name, r.Reason)
		case "done", "stopped":
			fmt.Fprintf(&b, "- %s: %s%s\n", r.Name, r.Debrief, HandoffLines(r.Handoffs))
		}
	}
	return b.String()
}

// missionBrief is appended to the captain's synthesis brief after a mission:
// the captain did not do the investigating, so it needs the crew's debriefs,
// the notebook, and the rule for what verification allows into the draft.
func (e *Engine) missionBrief() string {
	if e.mission == nil {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n\nCREW MISSION %q — your crew ran the investigation; you write the report from what they recorded. Their debriefs:\n", e.mission.Name)
	if d := e.debriefs(); d != "" {
		b.WriteString(d)
	} else {
		b.WriteString("(no crew step completed)\n")
	}
	snap := e.inv.Snapshot()
	if nb := snap.NotebookSummary(); nb != "" {
		b.WriteString("\nShared notebook (what functions and symbols are):\n" + nb)
	}
	b.WriteString(VerificationBrief(snap))
	var open []string
	for _, o := range snap.Objectives {
		if !o.Covered {
			open = append(open, o.ID)
		}
	}
	if len(open) > 0 {
		fmt.Fprintf(&b, "\nObjectives the crew did not establish: %s. Say so where it matters — don't fill the gap with inference.\n", strings.Join(open, ", "))
	}
	return b.String()
}

// VerificationBrief is the rule the report writer is given for what
// verification allows into the draft: confirmed and downgraded findings only
// after a Parity pass, or a plain "unverified" label when none ran.
func VerificationBrief(snap InvestigationSnapshot) string {
	var b strings.Builder
	if snap.Verification == VerificationDone {
		c, d, r, u := verdictCounts(snap.Findings, nil)
		fmt.Fprintf(&b, "\nVERIFICATION — Parity re-read the evidence: %d confirmed, %d downgraded, %d rejected, %d not reached.\n", c, d, r, u)
		b.WriteString("- Write the report from the CONFIRMED and DOWNGRADED findings only, at the severity shown (a downgrade is already applied).\n")
		b.WriteString("- REJECTED findings are negative results: never present one as a finding. You may list them as checked-and-cleared.\n")
		if u > 0 {
			b.WriteString("- A finding tagged ?unverified was not reached by Parity: if you use it, say in the text that it is unverified.\n")
		}
	} else {
		b.WriteString("\nVERIFICATION — none ran on this mission. The draft is UNVERIFIED: open the summary section with one plain line saying these findings have not been independently verified.\n")
	}
	return b.String()
}

// takeLessons pulls `LESSON:` lines out of a debrief into the run's proposed
// method notes and returns the debrief without them.
func (e *Engine) takeLessons(role Role, debrief string) string {
	rest, found := LessonsFrom(debrief, role.ID, e.target(), e.sess.Project.Name)
	for _, n := range found {
		dup := false
		for _, l := range e.lessons {
			dup = dup || strings.EqualFold(l.Lesson, n.Lesson)
		}
		if !dup {
			e.lessons = append(e.lessons, n)
		}
	}
	return rest
}

// LessonsFrom splits a debrief into its text and the method notes it proposed
// on `LESSON:` lines. A line that reads as a conclusion about the sample is
// dropped — it is exactly what experience must not carry forward. Nothing
// returned here is saved: the analyst picks what to keep.
func LessonsFrom(debrief, roleID string, t experience.Target, project string) (string, []experience.Note) {
	if !strings.Contains(strings.ToUpper(debrief), "LESSON:") {
		return debrief, nil
	}
	var keep []string
	var notes []experience.Note
	for _, ln := range strings.Split(debrief, "\n") {
		trim := strings.TrimLeft(strings.TrimSpace(ln), "-*• ")
		if len(trim) < 7 || !strings.EqualFold(trim[:7], "LESSON:") {
			keep = append(keep, ln)
			continue
		}
		lesson, err := experience.Clean(trim[7:])
		if err != nil {
			continue
		}
		notes = append(notes, experience.Note{
			TargetType: t.Label(), Kind: t.Kind, Mode: t.Mode, Types: t.Types,
			Role: roleID, Lesson: lesson, FromRun: project,
		})
	}
	return strings.TrimSpace(strings.Join(keep, "\n")), notes
}

// --- handoffs --------------------------------------------------------------

// Handoff is a pointer one crew member leaves for another: "this is your job,
// and here is exactly where it is". It is a lead, never evidence.
type Handoff struct {
	To   string `json:"to"` // role id
	Text string `json:"text"`
}

const handoffMax = 300 // chars of one handoff kept

// HandoffsFrom splits a debrief into its text and the handoffs it left on
// `HANDOFF: <crewmate> — <what and where>` lines. A line that names nobody on
// the crew (or the writer itself) is not a handoff and stays in the debrief.
func HandoffsFrom(debrief, fromID string) (string, []Handoff) {
	if !strings.Contains(strings.ToUpper(debrief), "HANDOFF:") {
		return debrief, nil
	}
	var keep []string
	var out []Handoff
	for _, ln := range strings.Split(debrief, "\n") {
		trim := strings.TrimLeft(strings.TrimSpace(ln), "-*•`> ")
		if len(trim) < 8 || !strings.EqualFold(trim[:8], "HANDOFF:") {
			keep = append(keep, ln)
			continue
		}
		body := strings.Trim(strings.TrimSpace(trim[8:]), "`")
		// The addressee is the leading word; whatever punctuation follows it
		// (—, -, :, ,) separates it from the pointer.
		end := strings.IndexFunc(body, func(r rune) bool { return !unicode.IsLetter(r) })
		if end <= 0 {
			keep = append(keep, ln)
			continue
		}
		name := strings.ToLower(body[:end])
		if name == "captain" {
			name = CaptainID
		}
		role, ok := RoleByID(name)
		text := strings.TrimSpace(strings.TrimLeft(body[end:], " \t—–-:,>"))
		if !ok || role.ID == fromID || text == "" {
			keep = append(keep, ln)
			continue
		}
		out = append(out, Handoff{To: role.ID, Text: clip(text, handoffMax)})
	}
	return strings.TrimSpace(strings.Join(keep, "\n")), out
}

// HandoffLines renders a step's handoffs under its debrief ("" when none).
func HandoffLines(hs []Handoff) string {
	var b strings.Builder
	for _, h := range hs {
		fmt.Fprintf(&b, "\n  ↳ handoff for %s: %s", roleName(h.To), h.Text)
	}
	return b.String()
}

// HandoffsFor is the kickoff block listing what crewmates left for a role in
// the steps before it ("" when nothing was).
func HandoffsFor(roleID string, log []StepRecord) string {
	var b strings.Builder
	for _, r := range log {
		for _, h := range r.Handoffs {
			if h.To == roleID {
				fmt.Fprintf(&b, "- from %s: %s\n", r.Name, h.Text)
			}
		}
	}
	if b.Len() == 0 {
		return ""
	}
	return "\nHANDOFFS — your crewmates left these for YOU. Each is a lead, not a fact: go and look, then work it or say in your debrief why it led nowhere.\n" + b.String()
}

// MissionCrewLine tells a crew member who else is on this mission: who went
// out before it (their debriefs follow) and who is still to go, so a handoff
// is addressed to someone who will actually read it. stepNo is 1-based.
func MissionCrewLine(steps []mission.Step, stepNo int, selfID string) string {
	names := func(part []mission.Step) string {
		var out []string
		seen := map[string]bool{strings.ToLower(selfID): true}
		for _, st := range part {
			id := strings.ToLower(st.RoleID)
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, roleName(id))
		}
		return strings.Join(out, ", ")
	}
	if stepNo < 1 || stepNo > len(steps) {
		return ""
	}
	var b strings.Builder
	if before := names(steps[:stepNo-1]); before != "" {
		fmt.Fprintf(&b, "Ahead of you on this mission: %s. ", before)
	}
	if after := names(steps[stepNo:]); after != "" {
		fmt.Fprintf(&b, "Still to go, after or alongside you: %s — a handoff to one of them will be read.", after)
	} else {
		b.WriteString("You are the last one out before the captain writes the report — a handoff now reaches only the captain.")
	}
	return b.String() + "\n"
}

// RunAsMission serializes the run that just happened into a reusable mission:
// the crew order and the tasking each step was GIVEN (placeholders intact,
// not the expanded text), so it generalizes to the next sample.
func (e *Engine) RunAsMission(name string) (*mission.Mission, error) {
	if e.mission == nil {
		return nil, fmt.Errorf("this session didn't run a mission")
	}
	if !e.resolved {
		return nil, fmt.Errorf("the mission hasn't started yet — its crew is assembled after triage")
	}
	m := e.mission.Clone(name)
	m.Auto = false
	m.Desc = fmt.Sprintf("Saved from the %q run on %s.", e.mission.Name, e.sess.Project.Name)
	if err := m.Validate(KnownRole); err != nil {
		return nil, err
	}
	return m, nil
}

// --- small helpers ---------------------------------------------------------

func roleName(id string) string {
	if r, ok := RoleByID(id); ok {
		return r.Name
	}
	return id
}

func containsFold(ss []string, v string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// verdictCounts tallies verdicts over the scoped findings (nil scope = all).
func verdictCounts(findings []Finding, scope []string) (confirmed, downgraded, rejected, unverified int) {
	for _, f := range findings {
		if scope != nil && !containsFold(scope, f.ID) {
			continue
		}
		switch f.Verdict {
		case VerdictConfirmed:
			confirmed++
		case VerdictDowngraded:
			downgraded++
		case VerdictRejected:
			rejected++
		default:
			unverified++
		}
	}
	return
}
