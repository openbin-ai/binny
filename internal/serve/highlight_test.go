package serve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/llm"
	"openbin.ai/binny/internal/tools"
)

// binaryServer puts a server into binary mode over a tiny fake analysis.
func binaryServer(t *testing.T, projectID string) *server {
	t.Helper()
	project := &api.Project{ID: projectID, Name: "t.elf", Kind: api.KindBIN}
	reg := tools.NewRegistry()
	tb := tools.NewToolbox(nil, project)
	tb.RegisterRead(reg)
	if err := tb.SetAnalysisRaw([]byte(`{"metadata":{"language":"x86:LE:32","executable_format":"ELF"},
		"functions":[{"name":"main","address":"0x1000","decompiled":"int main(void){return 0;}"},
		             {"name":"decrypt_cfg","address":"0x1100","decompiled":"void decrypt_cfg(void){}"}],
		"strings":["hello"],"imports":["printf"]}`)); err != nil {
		t.Fatal(err)
	}
	s := &server{opts: Options{}}
	s.setBinaryProject(projectID, reg, tb)
	return s
}

func TestBinaryFindingMustNameARealFunction(t *testing.T) {
	s := binaryServer(t, "local-1")
	// No function at all → refused, with guidance.
	out, isErr := s.runTool(context.Background(), "record_finding", json.RawMessage(`{"title":"x","severity":"high","note":"n"}`))
	if !isErr || !strings.Contains(out, "function") {
		t.Errorf("no function: out=%q isErr=%v", out, isErr)
	}
	// A made-up function → refused.
	out, isErr = s.runTool(context.Background(), "record_finding", json.RawMessage(`{"title":"x","severity":"high","note":"n","function":"FUN_deadbeef"}`))
	if !isErr || !strings.Contains(out, "FUN_deadbeef") {
		t.Errorf("bogus function: out=%q isErr=%v", out, isErr)
	}
	// A real one → recorded.
	out, isErr = s.runTool(context.Background(), "record_finding", json.RawMessage(`{"title":"x","severity":"high","note":"n","function":"decrypt_cfg"}`))
	if isErr {
		t.Errorf("real function: out=%q isErr=%v", out, isErr)
	}
	// Legacy: the function name in `file` still anchors.
	out, isErr = s.runTool(context.Background(), "record_finding", json.RawMessage(`{"title":"x","severity":"high","note":"n","file":"main"}`))
	if isErr {
		t.Errorf("function via file: out=%q isErr=%v", out, isErr)
	}
}

// binFindingProvider records a finding anchored via `file` (legacy), then stops.
type binFindingProvider struct{ turn int }

func (f *binFindingProvider) Name() string { return "fake" }
func (f *binFindingProvider) Stream(ctx context.Context, req llm.Request, onText func(string)) (*llm.Response, error) {
	f.turn++
	if f.turn == 1 {
		return &llm.Response{StopReason: llm.StopToolUse, Blocks: []llm.Block{{
			Kind: llm.BlockToolUse, ToolID: "f1", ToolName: "record_finding",
			Input: json.RawMessage(`{"title":"Config decryptor","severity":"medium","note":"RC4 over blob","file":"decrypt_cfg"}`),
		}}}, nil
	}
	return &llm.Response{StopReason: llm.StopEndTurn, Model: "fake", Blocks: []llm.Block{llm.TextBlock("done")}}, nil
}

func TestBinaryFindingEventCarriesFunction(t *testing.T) {
	s := binaryServer(t, "local-1")
	var finding map[string]any
	s.runAgentLoop(context.Background(), &binFindingProvider{}, llm.Request{
		Messages: []llm.Message{llm.UserText("audit")}, Tools: s.agentTools(),
	}, func(ev map[string]any) {
		if ev["type"] == "finding" {
			finding = ev
		}
	})
	if finding == nil || finding["function"] != "decrypt_cfg" {
		t.Errorf("finding = %v, want function=decrypt_cfg", finding)
	}
}

func TestHighlightToolOffered(t *testing.T) {
	s := &server{opts: Options{Dir: sampleTree(t)}}
	if !hasTool(s.agentTools(), "highlight_function") {
		t.Error("tree mode: highlight_function missing")
	}
	if !hasTool(binaryServer(t, "p").agentTools(), "highlight_function") {
		t.Error("binary mode: highlight_function missing")
	}
}

// highlightProvider highlights one function, then stops.
type highlightProvider struct {
	turn  int
	input string
}

func (f *highlightProvider) Name() string { return "fake" }
func (f *highlightProvider) Stream(ctx context.Context, req llm.Request, onText func(string)) (*llm.Response, error) {
	f.turn++
	if f.turn == 1 {
		return &llm.Response{StopReason: llm.StopToolUse, Blocks: []llm.Block{{
			Kind: llm.BlockToolUse, ToolID: "h1", ToolName: "highlight_function", Input: json.RawMessage(f.input),
		}}}, nil
	}
	return &llm.Response{StopReason: llm.StopEndTurn, Model: "fake", Blocks: []llm.Block{llm.TextBlock("done")}}, nil
}

func runHighlight(s *server, input string) (events []map[string]any) {
	s.runAgentLoop(context.Background(), &highlightProvider{input: input}, llm.Request{
		Messages: []llm.Message{llm.UserText("highlight it")}, Tools: s.agentTools(),
	}, func(ev map[string]any) { events = append(events, ev) })
	return events
}

func findEvent(events []map[string]any, typ string) map[string]any {
	for _, e := range events {
		if e["type"] == typ {
			return e
		}
	}
	return nil
}

func TestHighlightBinaryPushesToBackend(t *testing.T) {
	isolateCreds(t)
	var gotPath string
	var got api.CreateHighlightRequest
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got)
		json.NewEncoder(w).Encode(api.Highlight{ID: "h-1", Type: got.Type, TargetRef: got.TargetRef})
	}))
	defer backend.Close()
	s := binaryServer(t, "proj-123")
	s.newClient = func() (*api.Client, error) {
		return api.New(config.Endpoints{APIBase: backend.URL}, staticToken("tok")), nil
	}

	events := runHighlight(s, `{"name":"decrypt_cfg","tag":"crypto","note":"RC4 config decryptor"}`)
	if gotPath != "/api/projects/proj-123/highlights" {
		t.Fatalf("backend path = %q\n%v", gotPath, events)
	}
	if got.Type != api.HighlightFunction || got.TargetRef != "decrypt_cfg" || got.Tag != "crypto" {
		t.Errorf("backend body = %+v", got)
	}
	ev := findEvent(events, "highlight")
	if ev == nil || ev["name"] != "decrypt_cfg" || ev["kind"] != "function" || ev["pushed"] != true {
		t.Errorf("highlight event = %v", ev)
	}
	if r := findEvent(events, "tool_result"); r == nil || r["ok"] != true {
		t.Errorf("tool_result = %v", r)
	}
}

func TestHighlightBinaryRejectsUnknownFunction(t *testing.T) {
	s := binaryServer(t, "local-1")
	events := runHighlight(s, `{"name":"FUN_nope","tag":"x"}`)
	if r := findEvent(events, "tool_result"); r == nil || r["ok"] != false || !strings.Contains(r["preview"].(string), "FUN_nope") {
		t.Errorf("tool_result = %v", r)
	}
	if findEvent(events, "highlight") != nil {
		t.Error("highlight event emitted for an unknown function")
	}
}

func TestHighlightTreeLocalIsNotedNotPushed(t *testing.T) {
	isolateCreds(t)
	s := &server{opts: Options{Dir: sampleTree(t)}}
	events := runHighlight(s, `{"name":"sources/com/evil/Main.java:6","tag":"sink","note":"loadUrl"}`)
	r := findEvent(events, "tool_result")
	if r == nil || r["ok"] != true || !strings.Contains(r["preview"].(string), "local") {
		t.Errorf("tool_result = %v", r)
	}
	ev := findEvent(events, "highlight")
	if ev == nil || ev["kind"] != "file" || ev["name"] != "sources/com/evil/Main.java" || ev["line"] != 6 || ev["pushed"] != false {
		t.Errorf("highlight event = %v", ev)
	}
}

func TestHighlightTreeCloudPushesFile(t *testing.T) {
	isolateCreds(t)
	var got api.CreateHighlightRequest
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		json.NewEncoder(w).Encode(api.Highlight{ID: "h-2"})
	}))
	defer backend.Close()
	s := &server{opts: Options{}}
	s.setDirProject(sampleTree(t), "proj-9")
	s.newClient = func() (*api.Client, error) {
		return api.New(config.Endpoints{APIBase: backend.URL}, staticToken("tok")), nil
	}
	runHighlight(s, `{"name":"sources/com/evil/Main.java:6","tag":"sink","note":"loadUrl"}`)
	if got.Type != api.HighlightFile || got.TargetRef != "sources/com/evil/Main.java" || !strings.Contains(got.Note, "line 6") {
		t.Errorf("backend body = %+v", got)
	}
}
