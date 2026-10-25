package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/llm"
	"openbin.ai/binny/internal/tools"
)

// scriptedProvider returns a canned response per Complete call, letting us
// drive the phase machine deterministically without a real LLM.
type scriptedProvider struct {
	turns []*llm.Response
	i     int
}

func (s *scriptedProvider) Name() string { return "scripted" }
func (s *scriptedProvider) Stream(_ context.Context, _ llm.Request, onText func(string)) (*llm.Response, error) {
	r := s.turns[s.i]
	s.i++
	if onText != nil {
		if t := r.Text(); t != "" {
			onText(t)
		}
	}
	return r, nil
}

func toolUse(id, name, input string) llm.Block {
	return llm.Block{Kind: llm.BlockToolUse, ToolID: id, ToolName: name, Input: json.RawMessage(input)}
}

func TestEngineFullFlow(t *testing.T) {
	script := &scriptedProvider{turns: []*llm.Response{
		// TRIAGE: classify as ransomware
		{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			toolUse("c1", "set_classification", `{"malware_types":["ransomware"],"confidence":"high"}`),
		}},
		// INVESTIGATE: a grounded finding + cover one objective
		{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			toolUse("c2", "record_finding", `{"category":"crypto","severity":"high","note":"AES-CBC over enumerated files","evidence_refs":["encrypt_files"]}`),
			toolUse("c3", "mark_objective", `{"id":"crypto-keygen"}`),
		}},
		// INVESTIGATE: model ends its turn → transition to SYNTHESIZE
		{StopReason: llm.StopEndTurn, Blocks: []llm.Block{{Kind: llm.BlockText, Text: "Covered the crypto; stopping here."}}},
		// SYNTHESIZE: write two sections
		{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			toolUse("c4", "write_report_section", `{"id":"summary","title":"Summary","content":"Ransomware sample."}`),
			toolUse("c5", "write_report_section", `{"id":"iocs","title":"IOCs","content":"None recovered."}`),
		}},
		// SYNTHESIZE: end turn → done
		{StopReason: llm.StopEndTurn, Blocks: []llm.Block{{Kind: llm.BlockText, Text: "Draft complete."}}},
	}}

	sess := &app.Session{
		Mode:    app.ModeMalware,
		Model:   "test",
		Config:  &config.Config{},
		Project: &api.Project{ID: "p1", Name: "sample", Kind: api.KindBIN, Status: "READY"},
	}
	inv := NewInvestigation()
	reg := tools.NewRegistry()
	registerOutputTools(reg, inv, nil, sess.Project, sess.Mode) // highlight tool unused here

	eng := NewEngine(sess, inv, reg, script)
	eng.Start()

	// Step until done (guard against runaway).
	done := false
	for i := 0; i < 20 && !done; i++ {
		res := eng.Step(context.Background())
		if res.Err != nil {
			t.Fatalf("step %d error: %v", i, res.Err)
		}
		if res.AwaitQuestion != "" {
			t.Fatalf("unexpected ask_user: %q", res.AwaitQuestion)
		}
		done = res.Done || res.TurnComplete
	}
	if !done {
		t.Fatal("engine did not finish")
	}

	snap := inv.Snapshot()
	if len(snap.MalwareTypes) != 1 || snap.MalwareTypes[0] != "ransomware" {
		t.Errorf("classification = %v", snap.MalwareTypes)
	}
	if len(snap.Findings) != 1 || snap.Findings[0].Category != "crypto" {
		t.Errorf("findings = %+v", snap.Findings)
	}
	covered, total := 0, len(snap.Objectives)
	for _, o := range snap.Objectives {
		if o.Covered {
			covered++
		}
	}
	if total == 0 || covered != 1 {
		t.Errorf("coverage = %d/%d (want 1/6 ransomware objectives)", covered, total)
	}
	if len(snap.Sections) != 2 {
		t.Errorf("sections = %d, want 2", len(snap.Sections))
	}
	if eng.Phase() != app.PhaseReview {
		t.Errorf("final phase = %s, want REVIEW", eng.Phase())
	}
}

func TestStreamingAndReviewMemory(t *testing.T) {
	script := &scriptedProvider{turns: []*llm.Response{
		{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			toolUse("c1", "set_classification", `{"malware_types":["trojan"],"confidence":"medium"}`),
		}},
		{StopReason: llm.StopEndTurn, Blocks: []llm.Block{{Kind: llm.BlockText, Text: "Enough for now."}}},
		{StopReason: llm.StopEndTurn, Blocks: []llm.Block{{Kind: llm.BlockText, Text: "Draft written."}}},
		// follow-up in REVIEW:
		{StopReason: llm.StopEndTurn, Blocks: []llm.Block{{Kind: llm.BlockText, Text: "The C2 is 1.2.3.4, per connect_c2."}}},
	}}
	sess := &app.Session{
		Mode: app.ModeMalware, Model: "test", Config: &config.Config{},
		Project: &api.Project{ID: "p", Name: "s", Kind: api.KindBIN, Status: "READY"},
	}
	inv := NewInvestigation()
	reg := tools.NewRegistry()
	registerOutputTools(reg, inv, nil, sess.Project, sess.Mode)
	eng := NewEngine(sess, inv, reg, script)

	var streamed strings.Builder
	eng.SetStreamSink(func(s string) { streamed.WriteString(s) })
	eng.Start()

	reachedReview := false
	for i := 0; i < 15 && !reachedReview; i++ {
		res := eng.Step(context.Background())
		if res.Err != nil {
			t.Fatalf("err: %v", res.Err)
		}
		// When text is streamed, it must NOT also be duplicated as a binny line.
		for _, l := range res.Lines {
			if l.Kind == "binny" {
				t.Errorf("streamed text should be suppressed from Lines, got binny line %q", l.Text)
			}
		}
		reachedReview = res.TurnComplete
	}
	if !reachedReview {
		t.Fatal("did not reach REVIEW")
	}
	if !strings.Contains(streamed.String(), "Draft written.") {
		t.Errorf("stream sink missed text; got %q", streamed.String())
	}
	if eng.Phase() != app.PhaseReview {
		t.Fatalf("want REVIEW, got %s", eng.Phase())
	}

	// Follow-up must CONTINUE the same conversation (no reset).
	before := len(eng.messages)
	firstMsg := eng.messages[0]
	eng.Ask("what is the C2?")
	res := eng.Step(context.Background())
	if res.Err != nil {
		t.Fatalf("follow-up err: %v", res.Err)
	}
	if len(eng.messages) <= before {
		t.Errorf("conversation shrank/reset: before=%d after=%d", before, len(eng.messages))
	}
	if len(eng.messages) == 0 || eng.messages[0].Blocks[0].Text != firstMsg.Blocks[0].Text {
		t.Error("first message changed — the loop was restarted (memory lost)")
	}
	if !strings.Contains(streamed.String(), "C2 is 1.2.3.4") {
		t.Errorf("follow-up answer not streamed; got %q", streamed.String())
	}
}

func TestProviderRefusalPausesInPlace(t *testing.T) {
	script := &scriptedProvider{turns: []*llm.Response{
		{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			toolUse("c1", "set_classification", `{"malware_types":["remote-access-trojan"],"confidence":"high"}`),
		}},
		{StopReason: llm.StopRefusal, Blocks: []llm.Block{{Kind: llm.BlockText, Text: "I can't help with that."}}},
	}}
	sess := &app.Session{
		Mode: app.ModeMalware, Model: "claude-opus-4-8", Config: &config.Config{},
		Project: &api.Project{ID: "p", Name: "s", Kind: api.KindBIN, Status: "READY"},
	}
	inv := NewInvestigation()
	reg := tools.NewRegistry()
	registerOutputTools(reg, inv, nil, sess.Project, sess.Mode)
	eng := NewEngine(sess, inv, reg, script)
	eng.Start()

	_ = eng.Step(context.Background())    // classify → investigate
	res := eng.Step(context.Background()) // refusal

	if !res.Refused {
		t.Fatal("expected Refused")
	}
	if res.Done || res.TurnComplete {
		t.Error("refusal must not mark the turn done/complete")
	}
	if eng.Phase() != app.PhaseInvestigate {
		t.Errorf("phase should stay INVESTIGATE, got %s", eng.Phase())
	}
	// The refusal text must NOT be appended (re-sending it would re-trigger the
	// classifier); an injected phase brief is fine.
	for _, m := range eng.messages {
		for _, b := range m.Blocks {
			if strings.Contains(b.Text, "I can't help with that.") {
				t.Error("refusal text should not be in the conversation")
			}
		}
	}
}

func TestEvidenceGroundingRefusal(t *testing.T) {
	inv := NewInvestigation()
	if err := inv.AddFinding(Finding{Category: "c2", Note: "beacon"}); err == nil {
		t.Error("finding with no evidence should be refused")
	}
	if err := inv.AddFinding(Finding{Category: "c2", Note: "beacon", EvidenceRefs: []string{"beacon_fn"}}); err != nil {
		t.Errorf("grounded finding should be accepted: %v", err)
	}
	if err := inv.AddIOC(IOC{Type: "ip", Value: "1.2.3.4"}); err == nil {
		t.Error("IOC with no evidence should be refused")
	}
	if err := inv.AddIOC(IOC{Type: "ip", Value: "1.2.3.4", EvidenceRef: "connect_fn"}); err != nil {
		t.Errorf("grounded IOC should be accepted: %v", err)
	}
}

// classifyOnly builds an engine whose first turn classifies the sample, so the
// triage→investigate boundary can be observed.
func classifyOnlyEngine(t *testing.T, autonomy app.Autonomy) *Engine {
	t.Helper()
	script := &scriptedProvider{turns: []*llm.Response{
		{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			toolUse("c1", "set_classification", `{"malware_types":["trojan"],"confidence":"high"}`),
		}},
	}}
	sess := &app.Session{
		Mode: app.ModeMalware, Autonomy: autonomy, Model: "test", Config: &config.Config{},
		Project: &api.Project{ID: "p", Name: "s", Kind: api.KindBIN, Status: "READY"},
	}
	inv := NewInvestigation()
	reg := tools.NewRegistry()
	registerOutputTools(reg, inv, nil, sess.Project, sess.Mode)
	eng := NewEngine(sess, inv, reg, script)
	eng.Start()
	return eng
}

func TestSupervisedCheckpointsAtBoundary(t *testing.T) {
	eng := classifyOnlyEngine(t, app.Supervised)
	res := eng.Step(context.Background()) // classify → investigate
	if !res.Checkpoint {
		t.Fatal("Supervised should checkpoint at the triage→investigate boundary")
	}
	if eng.Phase() != app.PhaseInvestigate {
		t.Errorf("phase = %s, want INVESTIGATE", eng.Phase())
	}
}

func TestAutonomousDoesNotCheckpoint(t *testing.T) {
	eng := classifyOnlyEngine(t, app.Autonomous)
	res := eng.Step(context.Background())
	if res.Checkpoint {
		t.Fatal("Autonomous must not checkpoint at phase boundaries")
	}
}

func TestCollaborativeReportInterview(t *testing.T) {
	script := &scriptedProvider{turns: []*llm.Response{
		{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			toolUse("c1", "set_classification", `{"malware_types":["trojan"],"confidence":"high"}`),
		}},
		{StopReason: llm.StopEndTurn, Blocks: []llm.Block{{Kind: llm.BlockText, Text: "Enough — synthesize."}}},
		{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			toolUse("c2", "write_report_section", `{"id":"summary","title":"Summary","content":"x"}`),
		}},
		{StopReason: llm.StopEndTurn, Blocks: []llm.Block{{Kind: llm.BlockText, Text: "Done."}}},
	}}
	sess := &app.Session{
		Mode: app.ModeMalware, Autonomy: app.Collaborative, Model: "test", Config: &config.Config{},
		Project: &api.Project{ID: "p", Name: "s", Kind: api.KindBIN, Status: "READY"},
	}
	inv := NewInvestigation()
	reg := tools.NewRegistry()
	registerOutputTools(reg, inv, nil, sess.Project, sess.Mode)
	eng := NewEngine(sess, inv, reg, script)
	eng.Start()

	askedReportPrefs := false
	const prefs = "technical audience, in-depth, add remediation steps"
	done := false
	for i := 0; i < 20 && !done; i++ {
		res := eng.Step(context.Background())
		if res.Err != nil {
			t.Fatalf("step %d: %v", i, res.Err)
		}
		if res.AwaitQuestion != "" {
			if !strings.Contains(res.AwaitQuestion, "shape it") {
				t.Fatalf("unexpected question: %q", res.AwaitQuestion)
			}
			askedReportPrefs = true
			eng.Provide(prefs)
			continue
		}
		done = res.Done || res.TurnComplete
	}
	if !askedReportPrefs {
		t.Fatal("Collaborative must interview the analyst on report shape before synthesis")
	}
	// The prefs must reach the synthesis brief.
	found := false
	for _, m := range eng.messages {
		for _, b := range m.Blocks {
			if strings.Contains(b.Text, "ANALYST REPORT DIRECTIVE") && strings.Contains(b.Text, "remediation steps") {
				found = true
			}
		}
	}
	if !found {
		t.Error("report preferences were not injected into the synthesis brief")
	}
}

func TestSynthesisRunsAfterRoundCap(t *testing.T) {
	// The round cap now PAUSES investigation (offering continue/stop) instead of
	// auto-synthesizing. When the analyst chooses to wrap up (Stop), SYNTHESIZE
	// must still get rounds to write the report — not land in REVIEW with 0
	// sections.
	script := &scriptedProvider{turns: []*llm.Response{
		{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			toolUse("c1", "set_classification", `{"malware_types":["trojan"],"confidence":"high"}`),
		}},
		{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			toolUse("f1", "record_finding", `{"category":"c2","severity":"high","note":"beacon","evidence_refs":["connect_c2"]}`),
		}},
		{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			toolUse("f2", "record_finding", `{"category":"persist","severity":"low","note":"cron","evidence_refs":["install"]}`),
		}},
		// SYNTHESIZE: write a section (this must run despite the round cap).
		{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			toolUse("s1", "write_report_section", `{"id":"summary","title":"Summary","content":"Trojan."}`),
		}},
		{StopReason: llm.StopEndTurn, Blocks: []llm.Block{{Kind: llm.BlockText, Text: "Done."}}},
	}}
	sess := &app.Session{
		Mode: app.ModeMalware, Autonomy: app.Autonomous, Model: "test", Config: &config.Config{},
		Project: &api.Project{ID: "p", Name: "s", Kind: api.KindBIN, Status: "READY"},
	}
	inv := NewInvestigation()
	reg := tools.NewRegistry()
	registerOutputTools(reg, inv, nil, sess.Project, sess.Mode)
	eng := NewEngine(sess, inv, reg, script)
	eng.maxRounds = 3 // force the investigation to exhaust the cap quickly
	eng.Start()

	done, paused := false, false
	for i := 0; i < 20 && !done; i++ {
		res := eng.Step(context.Background())
		if res.Err != nil {
			t.Fatalf("step %d: %v", i, res.Err)
		}
		if res.CapReached != "" {
			// Analyst chooses to wrap up at the cap → synthesize.
			paused = true
			eng.Stop()
			continue
		}
		done = res.Done || res.TurnComplete
	}
	if !paused {
		t.Error("expected the round cap to PAUSE (CapReached), not flow straight to synthesis")
	}
	if !done {
		t.Fatal("engine did not finish")
	}
	if len(inv.Snapshot().Sections) == 0 {
		t.Fatal("BUG: synthesis wrote no sections after the round cap — draft is empty")
	}
	if eng.Phase() != app.PhaseReview {
		t.Errorf("final phase = %s, want REVIEW", eng.Phase())
	}
}

func TestAskUserSuspendResume(t *testing.T) {
	script := &scriptedProvider{turns: []*llm.Response{
		// vuln mode → straight to investigate; ask a question first
		{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			toolUse("q1", "ask_user", `{"question":"Is the parser reachable from untrusted input?"}`),
		}},
		// after the answer, end the turn → synthesize
		{StopReason: llm.StopEndTurn, Blocks: []llm.Block{{Kind: llm.BlockText, Text: "Thanks."}}},
		// synthesize ends immediately
		{StopReason: llm.StopEndTurn, Blocks: []llm.Block{{Kind: llm.BlockText, Text: "Done."}}},
	}}
	sess := &app.Session{
		Mode: app.ModeVuln, Model: "test", Config: &config.Config{},
		Project: &api.Project{ID: "p", Name: "s", Kind: api.KindBIN, Status: "READY"},
	}
	inv := NewInvestigation()
	reg := tools.NewRegistry()
	registerOutputTools(reg, inv, nil, sess.Project, sess.Mode)
	eng := NewEngine(sess, inv, reg, script)
	eng.Start()

	res := eng.Step(context.Background())
	if res.AwaitQuestion == "" {
		t.Fatal("expected ask_user to suspend the engine")
	}
	eng.Provide("yes, from the network handler")

	done := false
	for i := 0; i < 10 && !done; i++ {
		r := eng.Step(context.Background())
		if r.Err != nil {
			t.Fatalf("error: %v", r.Err)
		}
		done = r.Done || r.TurnComplete
	}
	if !done {
		t.Fatal("engine did not finish after answering")
	}
}
