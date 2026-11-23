package serve

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"openbin.ai/binny/internal/llm"
)

// askProvider plays one crew member answering a direct question: a search,
// a tool that isn't theirs, then the answer.
type askProvider struct {
	reqs []llm.Request
}

func (p *askProvider) Name() string { return "ask" }
func (p *askProvider) Stream(_ context.Context, req llm.Request, onText func(string)) (*llm.Response, error) {
	p.reqs = append(p.reqs, req)
	use := func(id, name, input string) *llm.Response {
		return &llm.Response{StopReason: llm.StopToolUse,
			Blocks: []llm.Block{{Kind: llm.BlockToolUse, ToolID: id, ToolName: name, Input: json.RawMessage(input)}}}
	}
	switch len(p.reqs) {
	case 1:
		return use("a1", "search_code", `{"regex":"package"}`), nil
	case 2:
		return use("a2", "save_report", `{}`), nil
	}
	onText("It's in Main.java:1.")
	return &llm.Response{StopReason: llm.StopEndTurn, Model: "fake", Blocks: []llm.Block{llm.TextBlock("It's in Main.java:1.")}}, nil
}

func TestAskCrewMember(t *testing.T) {
	s := &server{opts: Options{Dir: sampleTree(t)}}
	target, err := s.askTarget("dex")
	if err != nil {
		t.Fatal(err)
	}
	history := []llm.Message{
		llm.UserText("what is this app?"),
		{Role: llm.RoleAssistant, Blocks: []llm.Block{llm.TextBlock("A WebView wrapper.")}},
		llm.UserText("@Dex, where is the package declared?"),
	}
	p := &askProvider{}
	var evs []map[string]any
	out := s.askCrew(context.Background(), p, target, llm.Request{System: "BASE RULES", Model: "fake", MaxTokens: 1000},
		history, func(ev map[string]any) { evs = append(evs, ev) })

	// The member got its own prompt and tools, in a fresh context that carries
	// the conversation as text.
	first := p.reqs[0]
	if !strings.Contains(first.System, "BASE RULES") || !strings.Contains(first.System, "CREW ROLE") {
		t.Errorf("the member should run on the crew system prompt: %q", first.System)
	}
	kick := messageText(first.Messages[0])
	if len(first.Messages) != 1 || !strings.Contains(kick, "BINNY: A WebView wrapper.") || !strings.Contains(kick, "THE ANALYST ASKS YOU:\nwhere is the package declared?") {
		t.Errorf("kickoff should carry the conversation and the bare question:\n%s", kick)
	}
	for _, d := range first.Tools {
		if d.Name == "save_report" || d.Name == "set_verdict" || d.Name == "add_note" {
			t.Errorf("%s is not a tool for a direct question", d.Name)
		}
	}
	// Every event names the member; a tool outside the role is refused.
	var refused bool
	for _, e := range evs {
		if e["agent"] != "dex" {
			t.Errorf("event without its crew member: %+v", e)
		}
		if e["type"] == "tool_result" && e["name"] == "save_report" && e["ok"] == false {
			refused = true
		}
	}
	if !refused {
		t.Error("a tool outside the member's set should be refused")
	}
	// The exchange joins BINNY's transcript, marked as the member's.
	if len(out) != 4 {
		t.Fatalf("transcript = %d messages, want the 2 prior + question + answer", len(out))
	}
	if q := messageText(out[2]); q != "[The analyst asked Dex directly] where is the package declared?" {
		t.Errorf("question in the transcript: %q", q)
	}
	if a := messageText(out[3]); out[3].Role != llm.RoleAssistant || a != "[Dex answered]\nIt's in Main.java:1." {
		t.Errorf("answer in the transcript: %q", a)
	}
}

func TestAskTargetRefusals(t *testing.T) {
	if _, err := (&server{}).askTarget("dex"); err == nil || !strings.Contains(err.Error(), "open a target first") {
		t.Errorf("no target open: %v", err)
	}
	s := &server{opts: Options{Dir: sampleTree(t)}}
	if _, err := s.askTarget("nobody"); err == nil || !strings.Contains(err.Error(), "@dex") {
		t.Errorf("an unknown member should list the crew: %v", err)
	}
	if _, err := s.askTarget("hex"); err == nil || !strings.Contains(err.Error(), "Hex can't take this one") {
		t.Errorf("Hex needs a sample attached: %v", err)
	}
}

// stopProvider streams some text and then fails the way a cancelled request
// does; cancel is called mid-stream, as the Stop button does.
type stopProvider struct{ cancel context.CancelFunc }

func (p *stopProvider) Name() string { return "stop" }
func (p *stopProvider) Stream(ctx context.Context, _ llm.Request, onText func(string)) (*llm.Response, error) {
	onText("The loader starts in")
	p.cancel()
	return nil, ctx.Err()
}

func TestStoppedTurnKeepsWhatWasSaid(t *testing.T) {
	s := &server{opts: Options{Dir: sampleTree(t)}}
	ctx, cancel := context.WithCancel(context.Background())
	var evs []map[string]any
	out := s.runAgentLoop(ctx, &stopProvider{cancel}, llm.Request{Messages: []llm.Message{llm.UserText("walk me through it")}, Tools: s.agentTools()},
		func(ev map[string]any) { evs = append(evs, ev) })
	if len(out) != 2 || out[1].Role != llm.RoleAssistant {
		t.Fatalf("a stopped turn should still end on an assistant message: %+v", out)
	}
	if got := messageText(out[1]); got != "The loader starts in\n\n"+stoppedNote {
		t.Errorf("stopped reply = %q", got)
	}
	if e := eventsOf(evs, "error"); len(e) != 1 || e[0]["stopped"] != true {
		t.Errorf("a stop should be reported as one: %+v", e)
	}
}

// A mission stopped mid-step pauses with the step still to run, and resumes.
func TestStoppedMissionPausesAndResumes(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	s := &server{opts: Options{Dir: sampleTree(t)}}
	run, err := s.newMissionRun(missionRequest{Mode: "MALWARE"})
	if err != nil {
		t.Fatal(err)
	}
	var evs []map[string]any
	run.emit = func(ev map[string]any) { evs = append(evs, ev) }
	ctx, cancel := context.WithCancel(context.Background())
	env := runEnv{provider: &stopProvider{cancel}, model: "fake", system: "BASE RULES", maxTok: 1000}
	if _, finished := s.runMission(ctx, run, env, false); finished {
		t.Fatal("a stopped mission is paused, not finished")
	}
	if run.triaged || run.stepIdx != 0 {
		t.Errorf("the stopped step should still be to run: triaged=%v stepIdx=%d", run.triaged, run.stepIdx)
	}
	if p := eventsOf(evs, "mission_paused"); len(p) != 1 {
		t.Errorf("want one mission_paused, got %+v", p)
	}
	env.provider = &crewProvider{}
	if _, finished := s.runMission(context.Background(), run, env, false); !finished {
		t.Error("the mission should run to its report once resumed")
	}
}
