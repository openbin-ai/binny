package serve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"openbin.ai/binny/internal/agent"
	"openbin.ai/binny/internal/llm"
	"openbin.ai/binny/internal/mission"
)

// crewProvider answers by who is asking — matched on the system prompt and,
// for the captain, on which brief it was handed — so a mission can be
// scripted without depending on call order.
type crewProvider struct {
	mu    sync.Mutex
	calls map[string]int
	seen  map[string][]llm.Request
}

func (p *crewProvider) Name() string { return "crew" }
func (p *crewProvider) Stream(_ context.Context, req llm.Request, onText func(string)) (*llm.Response, error) {
	first := req.Messages[0].Blocks[0].Text
	who := "report"
	switch {
	case strings.Contains(req.System, "You are DEX"):
		who = "dex"
	case strings.Contains(req.System, "You are PARITY"):
		who = "parity"
	case strings.Contains(first, "TRIAGE."):
		who = "triage"
	}
	p.mu.Lock()
	if p.calls == nil {
		p.calls, p.seen = map[string]int{}, map[string][]llm.Request{}
	}
	n := p.calls[who]
	p.calls[who]++
	p.seen[who] = append(p.seen[who], req)
	p.mu.Unlock()

	use := func(id, name, input string) *llm.Response {
		return &llm.Response{StopReason: llm.StopToolUse, Usage: llm.Usage{InputTokens: 40, OutputTokens: 10},
			Blocks: []llm.Block{{Kind: llm.BlockToolUse, ToolID: id, ToolName: name, Input: json.RawMessage(input)}}}
	}
	text := func(t string) *llm.Response {
		if onText != nil {
			onText(t)
		}
		return &llm.Response{StopReason: llm.StopEndTurn, Model: "fake", Usage: llm.Usage{InputTokens: 40, OutputTokens: 10}, Blocks: []llm.Block{llm.TextBlock(t)}}
	}
	switch who {
	case "triage":
		return text("An Android app with a WebView bridge; look at Main first."), nil
	case "dex":
		switch n {
		case 0:
			return use("d1", "record_finding", `{"title":"JS bridge exposed","severity":"high","file":"sources/com/evil/Main.java","line":3,"note":"addJavascriptInterface on untrusted content"}`), nil
		case 1:
			return use("d2", "set_verdict", `{"finding_id":"F1","verdict":"confirmed","reason":"mine"}`), nil // not Dex's tool
		case 2:
			return use("d3", "add_note", `{"symbol":"com.evil.Main","meaning":"launcher activity hosting the WebView"}`), nil
		}
		return text("Bridge pinned.\nLESSON: On hybrid apps, list every addJavascriptInterface call before reading activities.\nLESSON: This app is malicious and phones home to 10.0.0.9."), nil
	case "parity":
		if n == 0 {
			return use("p1", "set_verdict", `{"finding_id":"F1","verdict":"downgraded","severity":"medium","reason":"read Main.java: the bridge exists, but the loaded URL is a bundled asset"}`), nil
		}
		return text("One finding overstated."), nil
	}
	return text("## Report\nThe bridge is exposed (Main.java:3), medium severity."), nil
}

func eventsOf(evs []map[string]any, typ string) []map[string]any {
	var out []map[string]any
	for _, e := range evs {
		if e["type"] == typ {
			out = append(out, e)
		}
	}
	return out
}

func TestMissionRunOnATree(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	s := &server{opts: Options{Dir: sampleTree(t)}}
	if k := s.targetKind(); k != "APK" {
		t.Fatalf("target kind = %q, want APK (the tree has a manifest)", k)
	}
	m := &mission.Mission{Name: "Bridge", Steps: []mission.Step{
		{RoleID: "dex", Checkpoint: true}, {RoleID: "trace"}, {RoleID: "hex"}, {RoleID: "parity"},
	}}
	run, err := s.newMissionRun(missionRequest{Mission: m, Mode: "MALWARE", Intel: "seen in a phishing kit"})
	if err != nil {
		t.Fatal(err)
	}
	var evs []map[string]any
	run.emit = func(ev map[string]any) { evs = append(evs, ev) }
	p := &crewProvider{}
	env := runEnv{provider: p, model: "fake", system: "BASE RULES", maxTok: 1000, budget: 100_000}

	// First leg: triage, Dex, then the checkpoint Dex's step carries.
	if _, finished := s.runMission(context.Background(), run, env, false); finished {
		t.Fatal("the mission should pause at the checkpoint after Dex")
	}
	if cp := eventsOf(evs, "checkpoint"); len(cp) != 1 || cp[0]["next"] != "Trace" || cp[0]["runId"] != run.id {
		t.Fatalf("checkpoint event: %+v", cp)
	}
	if st := eventsOf(evs, "mission_start"); len(st) != 1 || len(st[0]["steps"].([]map[string]any)) != 4 {
		t.Fatalf("mission_start should carry the track: %+v", st)
	}
	f := eventsOf(evs, "finding")
	if len(f) != 1 || f[0]["id"] != "F1" || f[0]["agent"] != "dex" || f[0]["step"] != 1 {
		t.Fatalf("a crew finding should carry its id and who pinned it: %+v", f)
	}
	// Dex was refused Parity's tool, and its events are filed under its card.
	var refused bool
	for _, e := range eventsOf(evs, "tool_result") {
		if e["agent"] != "dex" && e["step"] != 0 {
			t.Errorf("tool event without its crew member: %+v", e)
		}
		if e["name"] == "set_verdict" && e["ok"] == false && strings.Contains(e["preview"].(string), "isn't one of your tools") {
			refused = true
		}
	}
	if !refused {
		t.Error("Dex calling set_verdict must be refused")
	}
	if len(eventsOf(evs, "done")) != 0 {
		t.Error("a step ending must not end the stream")
	}
	dex := p.seen["dex"][0]
	if !strings.Contains(dex.System, "BASE RULES") || !strings.Contains(dex.System, "CREW RULES") {
		t.Error("a crew member gets the base prompt plus its role")
	}
	names := map[string]bool{}
	for _, tl := range dex.Tools {
		names[tl.Name] = true
	}
	if !names["search_code"] || !names["read_file"] || !names["record_finding"] || !names["add_note"] || names["set_verdict"] || names["save_report"] {
		t.Errorf("Dex's Desktop toolset is wrong: %v", names)
	}
	kick := dex.Messages[0].Blocks[0].Text
	for _, want := range []string{"seen in a phishing kit", "WebView bridge; look at Main first", "You are Dex", "[persistence]"} {
		if !strings.Contains(kick, want) {
			t.Errorf("Dex's kickoff is missing %q", want)
		}
	}
	db := eventsOf(evs, "step_debrief")
	if len(db) != 2 || db[1]["agent"] != "dex" || db[1]["findings"] != 1 || strings.Contains(db[1]["text"].(string), "LESSON") {
		t.Fatalf("debriefs: %+v", db)
	}

	// Second leg, with steering: Trace and Hex can't run here, Parity rules, BINNY reports.
	evs = nil
	run.steer = "Check whether the URL is remote."
	final, finished := s.runMission(context.Background(), run, env, false)
	if !finished || !strings.Contains(final, "medium severity") {
		t.Fatalf("mission should finish with BINNY's report, got %q (finished=%v)", final, finished)
	}
	skips := eventsOf(evs, "step_skip")
	if len(skips) != 2 || skips[0]["agent"] != "trace" || !strings.Contains(skips[1]["reason"].(string), "no raw sample attached") {
		t.Fatalf("Trace (wrong kind) and Hex (no sample) should be skipped with reasons: %+v", skips)
	}
	v := eventsOf(evs, "verdict")
	if len(v) != 1 || v[0]["id"] != "F1" || v[0]["verdict"] != "downgraded" || v[0]["severity"] != "medium" || v[0]["was"] != "high" {
		t.Fatalf("verdict event: %+v", v)
	}
	done := eventsOf(evs, "mission_done")
	if len(done) != 1 || done[0]["verification"] != agent.VerificationDone {
		t.Fatalf("mission_done: %+v", done)
	}
	// Only the method lesson is proposed; the conclusion is dropped.
	if ls := run.lessons; len(ls) != 1 || !strings.Contains(ls[0].Lesson, "addJavascriptInterface") || ls[0].Kind != "APK" {
		t.Errorf("lessons: %+v", ls)
	}
	report := p.seen["report"][0].Messages[0].Blocks[0].Text
	for _, want := range []string{"downgraded from high", "Hex: SKIPPED", "com.evil.Main — launcher activity", "CONFIRMED and DOWNGRADED findings only"} {
		if !strings.Contains(report, want) {
			t.Errorf("the report brief is missing %q:\n%s", want, report)
		}
	}
	// The report streams as BINNY's own voice — no step card.
	for _, e := range eventsOf(evs, "chunk") {
		if strings.Contains(e["text"].(string), "## Report") && e["step"] != nil {
			t.Error("the report must not be filed under a crew step")
		}
	}
}

func TestMissionWithoutParityIsUnverified(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	s := &server{opts: Options{Dir: sampleTree(t)}}
	run, err := s.newMissionRun(missionRequest{Mission: &mission.Mission{Name: "Solo Dex", Steps: []mission.Step{{RoleID: "dex"}}}})
	if err != nil {
		t.Fatal(err)
	}
	var evs []map[string]any
	run.emit = func(ev map[string]any) { evs = append(evs, ev) }
	p := &crewProvider{}
	if _, finished := s.runMission(context.Background(), run, runEnv{provider: p, model: "fake", maxTok: 1000}, false); !finished {
		t.Fatal("mission should finish")
	}
	if d := eventsOf(evs, "mission_done"); len(d) != 1 || d[0]["verification"] != agent.VerificationNone {
		t.Fatalf("a mission without Parity is unverified: %+v", d)
	}
	if rp := p.seen["report"][0].Messages[0].Blocks[0].Text; !strings.Contains(rp, "UNVERIFIED") {
		t.Error("BINNY should be told to label the report unverified")
	}
}

func TestMissionNeedsATarget(t *testing.T) {
	s := &server{}
	if _, err := s.newMissionRun(missionRequest{}); err == nil || !strings.Contains(err.Error(), "open a target first") {
		t.Errorf("want a clear refusal with nothing open, got %v", err)
	}
}

func TestCrewAndMissionEndpoints(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	s := &server{opts: Options{Dir: sampleTree(t)}}
	h := s.routes()
	do := func(method, path, body string) (int, map[string]any) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	_, crew := do(http.MethodGet, "/api/crew", "")
	lineup := crew["crew"].([]any)
	if len(lineup) != 7 || lineup[0].(map[string]any)["id"] != "binny" {
		t.Fatalf("lineup: %+v", lineup)
	}
	for _, c := range lineup {
		m := c.(map[string]any)
		// Every crew member's art ships embedded: an empty avatar here means
		// the file is missing from web/ and the UI falls back to an initial.
		if m["avatar"] == "" {
			t.Errorf("%v has no avatar — its art is missing from web/", m["id"])
		}
		if m["id"] == "hex" && m["avatar"] != "crew/hex.png" {
			t.Errorf("Hex avatar = %q", m["avatar"])
		}
	}

	if code, out := do(http.MethodPost, "/api/missions", `{"action":"save","mission":{"name":"Mine","steps":[{"role":"siggy"},{"role":"bob"}]}}`); code != 400 || !strings.Contains(out["error"].(string), "unknown crew member") {
		t.Errorf("an invalid mission must be refused: %d %v", code, out)
	}
	code, out := do(http.MethodPost, "/api/missions", `{"action":"save","mode":"MALWARE","mission":{"name":"Mine","steps":[{"role":"dex","checkpoint":true}]}}`)
	if code != 200 {
		t.Fatalf("save: %d %v", code, out)
	}
	if saved := out["mission"].(map[string]any); saved["autonomy"] != "supervised" || saved["starter"] != false {
		t.Errorf("saved mission: %+v", saved)
	}
	if code, out := do(http.MethodPost, "/api/missions", `{"action":"save","mission":{"name":"Full Malware","steps":[{"role":"hex"}]}}`); code != 400 || !strings.Contains(out["error"].(string), "read-only") {
		t.Errorf("starters are read-only: %d %v", code, out)
	}
	_, list := do(http.MethodGet, "/api/missions?mode=MALWARE", "")
	var mine, quick map[string]any
	for _, m := range list["missions"].([]any) {
		mm := m.(map[string]any)
		switch mm["name"] {
		case "Mine":
			mine = mm
		case "Quick Triage":
			quick = mm
		}
	}
	if mine == nil || quick == nil || quick["starter"] != true {
		t.Fatalf("list should hold starters and saved: %+v", list)
	}
	// Coverage check: on an APK Siggy+Twine leave objectives unowned.
	if w, _ := quick["warning"].(string); !strings.Contains(w, "No crew member on this mission owns") {
		t.Errorf("Quick Triage should carry a coverage warning, got %q", w)
	}
	if w, _ := mine["warning"].(string); w != "" {
		t.Errorf("Dex owns everything on an APK, got warning %q", w)
	}

	// Experience: only method is kept, and it is prunable.
	if code, out := do(http.MethodPost, "/api/experience", `{"action":"keep","note":{"targetType":"malware · APK","kind":"APK","lesson":"The C2 is 10.0.0.9"}}`); code != 400 || !strings.Contains(out["error"].(string), "never conclusions") {
		t.Errorf("a conclusion must be refused: %d %v", code, out)
	}
	code, out = do(http.MethodPost, "/api/experience", `{"action":"keep","note":{"targetType":"malware · APK","kind":"APK","role":"dex","lesson":"List every addJavascriptInterface call before reading activities."}}`)
	if code != 200 {
		t.Fatalf("keep: %d %v", code, out)
	}
	id := out["note"].(map[string]any)["id"].(string)
	if _, got := do(http.MethodGet, "/api/experience", ""); len(got["notes"].([]any)) != 1 {
		t.Errorf("notes: %+v", got)
	}
	if code, _ := do(http.MethodPost, "/api/experience", `{"action":"delete","id":"`+id+`"}`); code != 200 {
		t.Error("prune failed")
	}
}
