package agent

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/experience"
	"openbin.ai/binny/internal/llm"
	"openbin.ai/binny/internal/mission"
	"openbin.ai/binny/internal/tools"
)

// recProvider is a scripted provider that also records every request, so a
// test can check what each crew member was actually sent (system prompt,
// tools, kickoff).
type recProvider struct {
	turns []*llm.Response
	reqs  []llm.Request
}

func (p *recProvider) Name() string { return "rec" }
func (p *recProvider) Stream(_ context.Context, req llm.Request, onText func(string)) (*llm.Response, error) {
	// Copy the messages: the engine keeps appending to the same slice.
	req.Messages = append([]llm.Message(nil), req.Messages...)
	p.reqs = append(p.reqs, req)
	r := p.turns[len(p.reqs)-1]
	if onText != nil {
		if t := r.Text(); t != "" {
			onText(t)
		}
	}
	return r, nil
}

func say(text string) *llm.Response {
	return &llm.Response{StopReason: llm.StopEndTurn, Blocks: []llm.Block{{Kind: llm.BlockText, Text: text}},
		Usage: llm.Usage{InputTokens: 100, OutputTokens: 50}}
}

func call(blocks ...llm.Block) *llm.Response {
	return &llm.Response{StopReason: llm.StopToolUse, Blocks: blocks, Usage: llm.Usage{InputTokens: 100, OutputTokens: 50}}
}

func toolNames(req llm.Request) map[string]bool {
	m := map[string]bool{}
	for _, t := range req.Tools {
		m[t.Name] = true
	}
	return m
}

func kickoffText(req llm.Request) string { return renderMessageText(req.Messages[0]) }

// fakeRead registers stand-ins for the read tools, so role views have
// something to filter and cantRun sees a usable toolset.
func fakeRead(reg *tools.Registry, names ...string) {
	for _, n := range names {
		name := n
		reg.Add(&tools.Tool{
			Def: tools.Def(name, "test stand-in", tools.Obj(map[string]any{})),
			Handler: func(context.Context, json.RawMessage) (string, error) {
				return name + " output", nil
			},
		})
	}
}

// crewEngine builds a malware-mode engine over a BIN project with stand-in
// read tools and the given mission.
func crewEngine(t *testing.T, p llm.Provider, m *mission.Mission) (*Engine, *Investigation) {
	t.Helper()
	sess := &app.Session{
		Mode: app.ModeMalware, Autonomy: app.Autonomous, Model: "test", Config: &config.Config{},
		Project: &api.Project{ID: "p1", Name: "sample.bin", Kind: api.KindBIN, Status: "READY"},
	}
	inv := NewInvestigation()
	reg := tools.NewRegistry()
	fakeRead(reg, "get_metadata", "get_imports", "get_strings", "list_functions", "get_function", "xrefs", "read_data", "search")
	registerOutputTools(reg, inv, nil, sess.Project, sess.Mode)
	eng := NewEngine(sess, inv, reg, p)
	eng.SetMission(m)
	eng.Start()
	return eng, inv
}

// drive steps the engine until it pauses or finishes, returning the last
// result and every line produced.
func drive(t *testing.T, eng *Engine) (StepResult, []Line) {
	t.Helper()
	var lines []Line
	for i := 0; i < 60; i++ {
		res := eng.Step(context.Background())
		lines = append(lines, res.Lines...)
		if res.Err != nil {
			t.Fatalf("step %d: %v", i, res.Err)
		}
		if res.Done || res.TurnComplete || res.Checkpoint || res.CapReached != "" || res.AwaitQuestion != "" || res.Refused {
			return res, lines
		}
	}
	t.Fatal("engine did not settle")
	return StepResult{}, nil
}

func hasLine(lines []Line, kind, agent, sub string) bool {
	for _, l := range lines {
		if l.Kind == kind && l.Agent == agent && strings.Contains(l.Text, sub) {
			return true
		}
	}
	return false
}

var classify = call(toolUse("t0", "set_classification", `{"malware_types":["trojan"],"confidence":"medium"}`))

func TestMissionRunsCrewThenParityThenReport(t *testing.T) {
	p := &recProvider{turns: []*llm.Response{
		classify, // BINNY triage
		// Siggy: two findings, then debrief
		call(
			toolUse("s1", "record_finding", `{"category":"capability","severity":"high","note":"spawns a remote shell","evidence_refs":["CreateProcessA"]}`),
			toolUse("s2", "record_finding", `{"category":"capability","severity":"medium","note":"keylogs","evidence_refs":["GetAsyncKeyState"]}`),
			toolUse("s3", "mark_objective", `{"id":"capabilities"}`),
		),
		say("Imports show process creation and key polling. Open: where the C2 is."),
		// Parity: confirm one, reject one, debrief
		call(
			toolUse("v1", "set_verdict", `{"finding_id":"F1","verdict":"downgraded","severity":"low","reason":"re-read imports: CreateProcessA is present but nothing ties it to a socket"}`),
			toolUse("v2", "set_verdict", `{"finding_id":"F2","verdict":"rejected","reason":"get_imports shows no GetAsyncKeyState import"}`),
		),
		say("One overstated, one unsupported."),
		// BINNY synthesis
		call(toolUse("w1", "write_report_section", `{"id":"summary","title":"Summary","content":"A trojan."}`)),
		say("Draft complete."),
	}}
	m := &mission.Mission{Name: "Test", Tasking: "Stay on {sample}.", Steps: []mission.Step{{RoleID: "siggy"}, {RoleID: "parity"}}}
	eng, inv := crewEngine(t, p, m)
	res, lines := drive(t, eng)
	if !res.TurnComplete || eng.Phase() != app.PhaseReview {
		t.Fatalf("want REVIEW after the mission, got phase %s (%+v)", eng.Phase(), res)
	}

	// Siggy got a role-filtered toolset and a fresh context.
	siggy := p.reqs[1]
	names := toolNames(siggy)
	for _, want := range []string{"get_imports", "get_strings", "record_finding", "add_note", "ask_user"} {
		if !names[want] {
			t.Errorf("Siggy is missing tool %s", want)
		}
	}
	for _, not := range []string{"get_function", "write_report_section", "set_classification", "set_verdict", "add_ioc"} {
		if names[not] {
			t.Errorf("Siggy must not have tool %s", not)
		}
	}
	if !strings.Contains(siggy.System, "SIGGY") || !strings.Contains(siggy.System, "EVIDENCE-GROUNDING") {
		t.Error("Siggy's system prompt should be the base rules plus its role")
	}
	if len(siggy.Messages) != 1 {
		t.Errorf("a crew member starts in a fresh context, got %d messages", len(siggy.Messages))
	}
	k := kickoffText(siggy)
	for _, want := range []string{"Stay on sample.bin.", "[capabilities]", "trojan", "DEBRIEF"} {
		if !strings.Contains(k, want) {
			t.Errorf("Siggy's kickoff is missing %q", want)
		}
	}

	// Parity: read tools + set_verdict only, and the findings to verify.
	parity := p.reqs[3]
	pn := toolNames(parity)
	if !pn["set_verdict"] || !pn["get_imports"] || pn["record_finding"] || pn["mark_objective"] {
		t.Errorf("Parity's toolset is wrong: %v", pn)
	}
	if pk := kickoffText(parity); !strings.Contains(pk, "F1") || !strings.Contains(pk, "GetAsyncKeyState") {
		t.Errorf("Parity's kickoff should list the findings and their evidence:\n%s", pk)
	}

	// Provenance and verdicts landed on the shared investigation.
	snap := inv.Snapshot()
	if len(snap.Findings) != 2 {
		t.Fatalf("findings = %d", len(snap.Findings))
	}
	f1, f2 := snap.Findings[0], snap.Findings[1]
	if f1.FoundBy != "siggy" || f1.Step != 1 || f1.ID != "F1" {
		t.Errorf("provenance: %+v", f1)
	}
	if f1.Verdict != VerdictDowngraded || f1.Severity != "low" || f1.WasSeverity != "high" || f1.VerifiedBy != "parity" {
		t.Errorf("downgrade not applied: %+v", f1)
	}
	if f2.Verdict != VerdictRejected {
		t.Errorf("F2 verdict = %q", f2.Verdict)
	}
	if snap.Verification != VerificationDone {
		t.Errorf("verification = %q", snap.Verification)
	}

	// Only what survived verification feeds the draft.
	synth := renderMessageText(p.reqs[5].Messages[len(p.reqs[5].Messages)-1])
	if !strings.Contains(synth, "spawns a remote shell") || !strings.Contains(synth, "downgraded from high") {
		t.Errorf("synthesis brief should carry the downgraded finding:\n%s", synth)
	}
	if i := strings.Index(synth, "Rejected by verification"); i < 0 || !strings.Contains(synth[i:], "keylogs") {
		t.Error("the rejected finding should be listed as a negative result")
	}
	if strings.Contains(synth[:strings.Index(synth, "Rejected by verification")], "keylogs") {
		t.Error("a rejected finding must not appear among the findings the draft is written from")
	}
	if !strings.Contains(synth, "Imports show process creation") {
		t.Error("the captain should get the crew's debriefs for synthesis")
	}

	// The mission log and the transcript events.
	log := eng.MissionLog()
	if len(log) != 2 || log[0].RoleID != "siggy" || log[0].Status != "done" || log[0].Findings != 2 || log[0].Spent == 0 {
		t.Errorf("mission log: %+v", log)
	}
	for _, want := range []struct{ kind, agent, sub string }{
		{"step", "siggy", "Siggy"}, {"debrief", "siggy", "Imports show"},
		{"step", "parity", "Verify 2 finding"}, {"verdict", "parity", "F2 rejected"}, {"debrief", "parity", "1 rejected"},
		{"tool", "siggy", "record_finding"},
	} {
		if !hasLine(lines, want.kind, want.agent, want.sub) {
			t.Errorf("missing %s line for %s containing %q", want.kind, want.agent, want.sub)
		}
	}
}

func TestMissionSkipsStepsThatCantRunAndLabelsUnverified(t *testing.T) {
	p := &recProvider{turns: []*llm.Response{
		classify,
		say("Nothing notable in the strings."), // Twine
		say("Draft complete."),                 // BINNY synthesis
	}}
	// Dex only works APKs; Hex needs the raw sample. Neither may fail the run.
	m := &mission.Mission{Name: "Mixed", Steps: []mission.Step{{RoleID: "dex"}, {RoleID: "hex"}, {RoleID: "twine"}}}
	eng, inv := crewEngine(t, p, m)
	res, lines := drive(t, eng)
	if !res.TurnComplete {
		t.Fatalf("mission should finish: %+v", res)
	}
	if !hasLine(lines, "skip", "dex", "only works Android") || !hasLine(lines, "skip", "hex", "no raw sample attached") {
		t.Errorf("skips should be visible with a reason: %+v", lines)
	}
	log := eng.MissionLog()
	if len(log) != 3 || log[0].Status != "skipped" || log[1].Status != "skipped" || log[2].Status != "done" {
		t.Errorf("log: %+v", log)
	}
	if inv.Snapshot().Verification != VerificationNone {
		t.Error("a mission without Parity leaves the draft unverified")
	}
	synth := renderMessageText(p.reqs[2].Messages[len(p.reqs[2].Messages)-1])
	if !strings.Contains(synth, "UNVERIFIED") || !strings.Contains(synth, "Dex: SKIPPED") {
		t.Errorf("synthesis brief should say the draft is unverified and what was skipped:\n%s", synth)
	}
}

func TestMissionCheckpointAndSteering(t *testing.T) {
	p := &recProvider{turns: []*llm.Response{
		classify,
		say("Siggy done."),
		say("Twine done."),
		say("Draft complete."),
	}}
	m := &mission.Mission{Name: "Gated", Steps: []mission.Step{{RoleID: "siggy", Checkpoint: true}, {RoleID: "twine"}}}
	eng, _ := crewEngine(t, p, m)
	res, _ := drive(t, eng)
	if !res.Checkpoint || res.Agent != "siggy" {
		t.Fatalf("want a checkpoint after Siggy, got %+v", res)
	}
	eng.Ask("Look for the mutex name.")
	res, _ = drive(t, eng)
	if !res.TurnComplete {
		t.Fatalf("want the mission to finish, got %+v", res)
	}
	if k := kickoffText(p.reqs[2]); !strings.Contains(k, "Look for the mutex name.") || !strings.Contains(k, "Siggy done.") {
		t.Errorf("Twine should get the analyst's steering and Siggy's debrief:\n%s", k)
	}
}

func TestCrewShareCapIsNamedAndExtendable(t *testing.T) {
	p := &recProvider{turns: []*llm.Response{
		classify,
		call(toolUse("a", "get_strings", `{}`)),
		call(toolUse("b", "get_strings", `{}`)),
		say("Twine done."),
		say("Draft complete."),
	}}
	m := &mission.Mission{Name: "Tight", Steps: []mission.Step{{RoleID: "twine", TokenBudget: 100}}}
	eng, _ := crewEngine(t, p, m)
	res, lines := drive(t, eng)
	if res.CapReached != "tokens" || !hasLine(lines, "phase", "twine", "Twine has used its share") {
		t.Fatalf("want Twine's named share cap, got %+v / %+v", res, lines)
	}
	before := eng.Budget()
	if out := eng.ContinuePastCap(); len(out) == 0 || !strings.Contains(out[0].Text, "Twine gets +20k") {
		t.Errorf("continue should extend Twine's share: %+v", out)
	}
	if eng.Budget() != before+crewTokenExtension {
		t.Errorf("mission budget should grow with the extension")
	}
	if res, _ = drive(t, eng); !res.TurnComplete {
		t.Fatalf("mission should finish after the extension: %+v", res)
	}
}

func TestSkipStepMovesOnWithoutTheCrewMember(t *testing.T) {
	p := &recProvider{turns: []*llm.Response{
		classify,
		call(toolUse("a", "get_strings", `{}`)),
		say("Siggy done."),
		say("Draft complete."),
	}}
	m := &mission.Mission{Name: "Skip", Steps: []mission.Step{{RoleID: "twine", TokenBudget: 100}, {RoleID: "siggy"}}}
	eng, _ := crewEngine(t, p, m)
	if res, _ := drive(t, eng); res.CapReached != "tokens" {
		t.Fatalf("want a cap pause, got %+v", res)
	}
	if out := eng.SkipStep(); !hasLine(out, "debrief", "twine", "skipped by the analyst") {
		t.Errorf("skip should close Twine's step: %+v", out)
	}
	if res, _ := drive(t, eng); !res.TurnComplete {
		t.Fatalf("mission should carry on to Siggy and finish: %+v", res)
	}
	if log := eng.MissionLog(); log[0].Status != "stopped" || log[1].Status != "done" {
		t.Errorf("log: %+v", log)
	}
}

func TestAutoMissionAssemblesCrewFromObjectiveOwners(t *testing.T) {
	objs := []Objective{{ID: "persistence"}, {ID: "c2-network"}, {ID: "capabilities"}, {ID: "anti-analysis"}, {ID: "made-up"}}
	ids := func(steps []mission.Step) string {
		var s []string
		for _, st := range steps {
			s = append(s, st.RoleID)
		}
		return strings.Join(s, ",")
	}
	// BIN, no sandbox: Hex still owns anti-analysis (it is skipped at run time,
	// visibly); the unowned objective falls to a Captain task card.
	steps := autoSteps(objs, api.KindBIN, app.ModeMalware, false)
	if got := ids(steps); got != "siggy,twine,trace,hex,binny,parity" {
		t.Errorf("BIN crew = %s", got)
	}
	if st := steps[4]; len(st.Focus) != 1 || st.Focus[0] != "made-up" {
		t.Errorf("the Captain card should carry the orphan objective: %+v", st)
	}
	// APK: Dex leads and owns everything; Trace can't work it.
	if got := ids(autoSteps(objs, api.KindAPK, app.ModeMalware, true)); got != "dex,hex,parity" {
		t.Errorf("APK crew = %s", got)
	}
	// A saved mission that leaves objectives unowned is flagged.
	gaps := CoverageGaps(&mission.Mission{Name: "x", Steps: []mission.Step{{RoleID: "siggy"}}}, objs, api.KindBIN)
	if strings.Join(gaps, ",") != "persistence,c2-network,anti-analysis,made-up" {
		t.Errorf("coverage gaps = %v", gaps)
	}
}

func TestMissionStateSurvivesResumeMidStep(t *testing.T) {
	p := &recProvider{turns: []*llm.Response{
		classify,
		call(toolUse("a", "record_finding", `{"category":"c2","severity":"low","note":"beacons","evidence_refs":["connect_c2"]}`)),
	}}
	m := &mission.Mission{Name: "Resume", Steps: []mission.Step{{RoleID: "siggy"}, {RoleID: "parity"}}}
	eng, _ := crewEngine(t, p, m)
	for i := 0; i < 3; i++ { // triage, Siggy's launch, then Siggy's first round
		if res := eng.Step(context.Background()); res.Err != nil {
			t.Fatal(res.Err)
		}
	}
	raw, err := json.Marshal(eng.State())
	if err != nil {
		t.Fatal(err)
	}
	var st EngineState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}

	// Rebuild the way RestoreEngine does, minus the network-backed pieces.
	p2 := &recProvider{turns: []*llm.Response{
		say("Siggy done."),
		call(toolUse("v", "set_verdict", `{"finding_id":"F1","verdict":"confirmed","reason":"re-read connect_c2"}`)),
		say("Parity done."),
		say("Draft complete."),
	}}
	reg := tools.NewRegistry()
	fakeRead(reg, "get_metadata", "get_imports", "get_strings")
	registerOutputTools(reg, st.Investigation, nil, eng.sess.Project, eng.sess.Mode)
	eng2 := NewEngine(eng.sess, st.Investigation, reg, p2)
	eng2.messages, eng2.stage, eng2.rounds, eng2.spentTokens = st.Messages, stage(st.Stage), st.Rounds, st.SpentTokens
	eng2.pbs = eng.pbs
	eng2.restoreMission(st)

	if got := eng2.ActiveCrew(); len(got) != 1 || got[0] != "siggy" {
		t.Fatalf("resume should land back on Siggy mid-step, got %v", got)
	}
	if res, _ := drive(t, eng2); !res.TurnComplete {
		t.Fatalf("resumed mission should finish: %+v", res)
	}
	// Siggy continued its own conversation rather than starting over.
	if n := len(p2.reqs[0].Messages); n != 3 {
		t.Errorf("Siggy resumed with %d messages, want its kickoff + the tool round (3)", n)
	}
	f := st.Investigation.Snapshot().Findings[0]
	if f.Verdict != VerdictConfirmed || f.FoundBy != "siggy" {
		t.Errorf("finding after resume: %+v", f)
	}
	if log := eng2.MissionLog(); len(log) != 2 || log[0].Spent == 0 || log[1].Status != "done" {
		t.Errorf("per-step spend should survive the resume: %+v", log)
	}
}

// routedProvider answers by which crew member is asking (matched on the
// system prompt), so a parallel group can be scripted without depending on
// goroutine order.
type routedProvider struct {
	mu     sync.Mutex
	routes map[string][]*llm.Response
	calls  map[string]int
	live   int
	peak   int
}

func (p *routedProvider) Name() string { return "routed" }
func (p *routedProvider) Stream(_ context.Context, req llm.Request, _ func(string)) (*llm.Response, error) {
	p.mu.Lock()
	p.live++
	if p.live > p.peak {
		p.peak = p.live
	}
	key := "binny"
	for k := range p.routes {
		if k != "binny" && strings.Contains(req.System, k) {
			key = k
		}
	}
	r := p.routes[key][p.calls[key]]
	p.calls[key]++
	p.mu.Unlock()
	p.mu.Lock()
	p.live--
	p.mu.Unlock()
	return r, nil
}

func TestParallelStepsRunAsAGroup(t *testing.T) {
	p := &routedProvider{calls: map[string]int{}, routes: map[string][]*llm.Response{
		"binny": {classify, say("Draft complete.")},
		"SIGGY": {
			call(toolUse("s", "record_finding", `{"category":"capability","severity":"low","note":"from siggy","evidence_refs":["imp"]}`)),
			say("Siggy done."),
		},
		"TWINE": {
			call(toolUse("t", "record_finding", `{"category":"c2","severity":"low","note":"from twine","evidence_refs":["str"]}`)),
			say("Twine done."),
		},
	}}
	m := &mission.Mission{Name: "Fan", Steps: []mission.Step{{RoleID: "siggy"}, {RoleID: "twine", Parallel: true, Checkpoint: true}}}
	eng, inv := crewEngine(t, p, m)
	eng.sess.Provider = &config.Provider{ID: "x", MaxConcurrency: 2}
	eng.providerID = "x"

	res, lines := drive(t, eng)
	if !res.Checkpoint {
		t.Fatalf("the group's checkpoint should fire once both are back: %+v", res)
	}
	if got := eng.rounds; got != 5 { // triage + 2 rounds each for two crew
		t.Errorf("rounds = %d, want 5", got)
	}
	by := map[string]string{}
	for _, f := range inv.Snapshot().Findings {
		by[f.Note] = f.FoundBy
	}
	if by["from siggy"] != "siggy" || by["from twine"] != "twine" {
		t.Errorf("parallel provenance crossed over: %v", by)
	}
	// Each member's lines stay contiguous — no interleaving within a round.
	var order []string
	for _, l := range lines {
		if l.Kind == "tool" && l.Agent != "" && (len(order) == 0 || order[len(order)-1] != l.Agent) {
			order = append(order, l.Agent)
		}
	}
	if strings.Join(order, ",") != "siggy,twine" {
		t.Errorf("tool lines should group by crew member, got %v", order)
	}
	if res, _ = drive(t, eng); !res.TurnComplete {
		t.Fatalf("mission should finish: %+v", res)
	}
}

func TestCaptainMayAddStepsOnlyWhenAllowed(t *testing.T) {
	p := &recProvider{turns: []*llm.Response{
		classify,
		say("Siggy done."),
		// BINNY's review: send Twine out with a precise task.
		call(toolUse("d", "dispatch_crew", `{"role":"twine","tasking":"Find the mutex string."}`)),
		say("Twine done."),
		say("Draft complete."),
	}}
	m := &mission.Mission{Name: "Adaptive", AllowAdd: true, Steps: []mission.Step{{RoleID: "siggy"}}}
	eng, _ := crewEngine(t, p, m)
	res, lines := drive(t, eng)
	if !res.TurnComplete {
		t.Fatalf("mission should finish: %+v", res)
	}
	if !hasLine(lines, "phase", "", "BINNY added a step: Twine") {
		t.Errorf("the added step should be announced: %+v", lines)
	}
	if n := toolNames(p.reqs[2]); len(n) != 1 || !n["dispatch_crew"] {
		t.Errorf("the review offers only dispatch_crew, got %v", n)
	}
	if k := kickoffText(p.reqs[3]); !strings.Contains(k, "Find the mutex string.") {
		t.Errorf("Twine should get the captain's tasking:\n%s", k)
	}
	if len(m.Steps) != 1 {
		t.Error("a run must not edit the saved mission it was started from")
	}
}

func TestExperienceIsHintsInAndLessonsOutNeverConclusions(t *testing.T) {
	p := &recProvider{turns: []*llm.Response{
		classify,
		say("Done.\nLESSON: In droppers, the resource section usually holds the next stage; check its entropy first.\nLESSON: The C2 is 10.2.3.4 on port 443."),
		say("Draft complete."),
	}}
	m := &mission.Mission{Name: "Exp", Steps: []mission.Step{{RoleID: "siggy"}}}
	eng, _ := crewEngine(t, p, m)
	eng.SetExperience([]experience.Note{
		{Kind: "BIN", Mode: "MALWARE", Types: []string{"trojan"}, Role: "siggy", Lesson: "Start from the import table's networking group."},
		{Kind: "APK", Mode: "MALWARE", Lesson: "Read the manifest receivers first."},
		{Kind: "BIN", Mode: "MALWARE", Role: "hex", Lesson: "Look for the RC4 key schedule loop."},
	})
	if res, _ := drive(t, eng); !res.TurnComplete {
		t.Fatalf("mission should finish: %+v", res)
	}
	k := kickoffText(p.reqs[1])
	if !strings.Contains(k, "Start from the import table's networking group.") {
		t.Error("a matching note should reach the crew member as a hint")
	}
	if strings.Contains(k, "manifest receivers") || strings.Contains(k, "RC4 key schedule") {
		t.Error("a note scoped to another kind or role must not fire")
	}
	lessons := eng.Lessons()
	if len(lessons) != 1 || !strings.Contains(lessons[0].Lesson, "resource section") || lessons[0].Role != "siggy" {
		t.Fatalf("want the one method lesson proposed, got %+v", lessons)
	}
	if strings.Contains(eng.MissionLog()[0].Debrief, "LESSON") {
		t.Error("lesson lines should be lifted out of the debrief")
	}
}

func TestNotebookIsSharedAndGraduatesIntoRenames(t *testing.T) {
	p := &recProvider{turns: []*llm.Response{
		classify,
		call(toolUse("n", "add_note", `{"symbol":"FUN_00401000","meaning":"RC4 key schedule over the config blob","suggested_name":"rc4_ksa"}`)),
		say("Siggy done."),
		call(toolUse("r", "read_notes", `{"filter":"rc4"}`)),
		say("Twine done."),
		say("Draft complete."),
	}}
	m := &mission.Mission{Name: "Notes", Steps: []mission.Step{{RoleID: "siggy"}, {RoleID: "twine"}}}
	eng, inv := crewEngine(t, p, m)
	if res, _ := drive(t, eng); !res.TurnComplete {
		t.Fatalf("mission should finish: %+v", res)
	}
	snap := inv.Snapshot()
	if len(snap.Notes) != 1 || snap.Notes[0].By != "siggy" {
		t.Fatalf("notes: %+v", snap.Notes)
	}
	if len(snap.Renames) != 1 || snap.Renames[0].Suggested != "rc4_ksa" {
		t.Errorf("a named note should become a rename suggestion: %+v", snap.Renames)
	}
	if k := kickoffText(p.reqs[3]); !strings.Contains(k, "FUN_00401000 — RC4 key schedule") {
		t.Errorf("Twine should start with the notebook:\n%s", k)
	}
	// Twine's read_notes result came back through the shared board.
	last := p.reqs[4].Messages[len(p.reqs[4].Messages)-1]
	if !strings.Contains(last.Blocks[0].Content, "RC4 key schedule") {
		t.Errorf("read_notes should return Siggy's note: %q", last.Blocks[0].Content)
	}
}

func TestVerdictRules(t *testing.T) {
	inv := NewInvestigation()
	_ = inv.AddFinding(Finding{Category: "c2", Severity: "medium", Note: "n", EvidenceRefs: []string{"f"}})
	if _, err := inv.SetVerdict("F1", "confirmed", "", "", "parity"); err == nil {
		t.Error("a verdict without a reason must be refused")
	}
	if _, err := inv.SetVerdict("F1", "downgraded", "high", "why", "parity"); err == nil {
		t.Error("a downgrade must lower the severity")
	}
	if _, err := inv.SetVerdict("F9", "confirmed", "", "why", "parity"); err == nil {
		t.Error("an unknown finding id must be refused")
	}
	if f, err := inv.SetVerdict("f1", "downgraded", "low", "why", "parity"); err != nil || f.Severity != "low" || f.WasSeverity != "medium" {
		t.Errorf("downgrade: %+v %v", f, err)
	}
	// Changing its mind to confirmed restores the original severity.
	if f, _ := inv.SetVerdict("F1", "confirmed", "", "re-read it", "parity"); f.Severity != "medium" || f.WasSeverity != "" {
		t.Errorf("confirm after downgrade: %+v", f)
	}
}

func TestSingleAgentRunIsUntouchedByTheCrew(t *testing.T) {
	// No mission: the captain's toolset has no crew tools and findings carry
	// no provenance tags in the summary.
	p := &recProvider{turns: []*llm.Response{
		classify,
		call(toolUse("a", "record_finding", `{"category":"c2","severity":"low","note":"beacons","evidence_refs":["connect_c2"]}`)),
		say("done"), say("Draft complete."),
	}}
	eng, inv := crewEngine(t, p, nil)
	if res, _ := drive(t, eng); !res.TurnComplete {
		t.Fatalf("run should finish: %+v", res)
	}
	n := toolNames(p.reqs[0])
	if n["set_verdict"] || n["add_note"] || n["dispatch_crew"] {
		t.Errorf("a single-agent run must not see crew tools: %v", n)
	}
	sum := inv.Snapshot().EvidenceSummary()
	if strings.Contains(sum, "unverified") || strings.Contains(sum, "confirmed") {
		t.Errorf("no verdict tags without a mission:\n%s", sum)
	}
	if inv.Snapshot().Verification != "" {
		t.Error("verification state is only set by a mission")
	}
}

func TestStopWhileACrewMemberIsAskingDoesNotOrphanTheAnswer(t *testing.T) {
	p := &recProvider{turns: []*llm.Response{
		classify,
		call(toolUse("q", "ask_user", `{"question":"Which build is this?"}`)), // Siggy asks
		say("Draft complete."), // BINNY synthesizes after /stop
	}}
	m := &mission.Mission{Name: "Ask", Steps: []mission.Step{{RoleID: "siggy"}, {RoleID: "twine"}}}
	eng, inv := crewEngine(t, p, m)
	res, _ := drive(t, eng)
	if res.AwaitQuestion != "Which build is this?" || res.Agent != "siggy" {
		t.Fatalf("want Siggy's question, got %+v", res)
	}
	// What the TUI's /stop does: stop, then hand the engine a note.
	eng.Stop()
	eng.Provide("(analyst asked to stop and synthesize)")
	if res, _ = drive(t, eng); !res.TurnComplete {
		t.Fatalf("stop should go straight to the report: %+v", res)
	}
	for _, msg := range p.reqs[2].Messages {
		for _, b := range msg.Blocks {
			if b.Kind == llm.BlockToolResult && b.ToolUseID == "q" {
				t.Fatal("the answer to a crew member's question leaked into the captain's conversation as an orphan tool result")
			}
		}
	}
	if log := eng.MissionLog(); len(log) != 1 || log[0].Status != "stopped" {
		t.Errorf("log: %+v", log)
	}
	if inv.Snapshot().Verification != VerificationNone {
		t.Error("a stopped mission's draft is unverified")
	}
}

func TestCrewQuestionIsAnsweredInItsOwnConversation(t *testing.T) {
	p := &recProvider{turns: []*llm.Response{
		classify,
		call(toolUse("q", "ask_user", `{"question":"Which build is this?"}`)),
		say("Siggy done."),
		say("Draft complete."),
	}}
	eng, _ := crewEngine(t, p, &mission.Mission{Name: "Ask", Steps: []mission.Step{{RoleID: "siggy"}}})
	if res, _ := drive(t, eng); res.AwaitQuestion == "" {
		t.Fatalf("want a question, got %+v", res)
	}
	eng.Provide("The March build.")
	if res, _ := drive(t, eng); !res.TurnComplete {
		t.Fatalf("mission should finish: %+v", res)
	}
	last := p.reqs[2].Messages[len(p.reqs[2].Messages)-1]
	if !strings.Contains(p.reqs[2].System, "SIGGY") || last.Blocks[0].ToolUseID != "q" || last.Blocks[0].Content != "The March build." {
		t.Errorf("the answer should go back to Siggy as the ask_user result: %+v", last)
	}
}
