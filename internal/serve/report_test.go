package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/llm"
)

type staticToken string

func (t staticToken) Token() (string, error) { return string(t), nil }

func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestSaveReportNoProject(t *testing.T) {
	isolateCreds(t)
	s := newConnectedServer()
	s.setDir("/tmp/local/src")
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/api/report/save", map[string]any{"title": "x", "sections": []any{}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
}

func TestSaveReportRequiresLogin(t *testing.T) {
	isolateCreds(t)
	s := newConnectedServer()
	s.setDirProject("/tmp/whatever/src", "proj-123")
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/api/report/save", map[string]any{"title": "x", "sections": []any{}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestSaveReportPushesToBackend(t *testing.T) {
	isolateCreds(t)
	var gotMethod, gotPath, gotAuth string
	var gotBody api.UpdateReportRequest
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		json.NewEncoder(w).Encode(api.Report{ID: "rep-1", ProjectID: "proj-123", Title: gotBody.Title, Sections: gotBody.Sections})
	}))
	defer backend.Close()

	s := newConnectedServer()
	s.setDirProject("/tmp/whatever/src", "proj-123")
	s.newClient = func() (*api.Client, error) {
		return api.New(config.Endpoints{APIBase: backend.URL}, staticToken("tok")), nil
	}
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/api/report/save", map[string]any{
		"title": "BINNY draft — demo",
		"sections": []map[string]string{
			{"id": "summary", "title": "Summary", "content": "two findings"},
			{"id": "BINNY-VR-001", "title": "Stack overflow", "content": "details"},
		},
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, raw)
	}
	if gotMethod != http.MethodPut || gotPath != "/api/projects/proj-123/report" {
		t.Errorf("backend got %s %s, want PUT /api/projects/proj-123/report", gotMethod, gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotBody.Title != "BINNY draft — demo" || len(gotBody.Sections) != 2 || gotBody.Sections[1].ID != "BINNY-VR-001" {
		t.Errorf("backend body = %+v", gotBody)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["projectId"] != "proj-123" || out["saved"] != float64(2) {
		t.Errorf("response = %v", out)
	}
}

func TestSaveReportRejectsEmpty(t *testing.T) {
	isolateCreds(t)
	s := newConnectedServer()
	s.setDirProject("/tmp/whatever/src", "proj-123")
	s.newClient = func() (*api.Client, error) {
		return api.New(config.Endpoints{APIBase: "http://127.0.0.1:1"}, staticToken("tok")), nil
	}
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	resp := postJSON(t, srv.URL+"/api/report/save", map[string]any{"title": "x", "sections": []any{}})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// saveProvider asks to push the draft (with an executive summary), then stops.
type saveProvider struct{ turn int }

func (f *saveProvider) Name() string { return "fake" }
func (f *saveProvider) Stream(ctx context.Context, req llm.Request, onText func(string)) (*llm.Response, error) {
	f.turn++
	if f.turn == 1 {
		return &llm.Response{StopReason: llm.StopToolUse, Blocks: []llm.Block{{
			Kind: llm.BlockToolUse, ToolID: "s1", ToolName: "save_report",
			Input: json.RawMessage(`{"summary":"One high-severity sink."}`),
		}}}, nil
	}
	return &llm.Response{StopReason: llm.StopEndTurn, Model: "fake", Blocks: []llm.Block{llm.TextBlock("Pushed.")}}, nil
}

func hasTool(ts []llm.Tool, name string) bool {
	for _, t := range ts {
		if t.Name == name {
			return true
		}
	}
	return false
}

func TestAgentToolsOfferSaveReportOnlyWithProject(t *testing.T) {
	s := &server{opts: Options{Dir: sampleTree(t)}}
	if hasTool(s.agentTools(), "save_report") {
		t.Error("local tree: save_report must not be offered")
	}
	s.setDirProject(sampleTree(t), "proj-123")
	if !hasTool(s.agentTools(), "save_report") {
		t.Error("cloud project: save_report missing")
	}
}

func TestSaveReportToolPushesDraft(t *testing.T) {
	isolateCreds(t)
	var gotPath string
	var gotBody api.UpdateReportRequest
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(api.Report{ID: "rep-1"})
	}))
	defer backend.Close()

	s := &server{opts: Options{Dir: sampleTree(t)}}
	s.setDirProject(sampleTree(t), "proj-123")
	s.setProjectName("demo.apk")
	s.newClient = func() (*api.Client, error) {
		return api.New(config.Endpoints{APIBase: backend.URL}, staticToken("tok")), nil
	}
	draft := &api.UpdateReportRequest{Title: "BINNY draft — demo.apk", Sections: []api.ReportSection{
		{ID: "summary", Title: "Summary", Content: "table"},
		{ID: "BINNY-VR-001", Title: "BINNY-VR-001 — sink", Content: "details"},
	}}

	var events []map[string]any
	send := func(ev map[string]any) { events = append(events, ev) }
	s.runAgentLoop(withDraft(context.Background(), draft), &saveProvider{}, llm.Request{
		Messages: []llm.Message{llm.UserText("push to my project on openbin")}, Tools: s.agentTools(),
	}, send)

	if gotPath != "/api/projects/proj-123/report" {
		t.Fatalf("backend path = %q; events=%v", gotPath, events)
	}
	if gotBody.Title != "BINNY draft — demo.apk" || len(gotBody.Sections) != 3 {
		t.Fatalf("backend body = %+v", gotBody)
	}
	if gotBody.Sections[0].ID != "executive-summary" || gotBody.Sections[0].Content != "One high-severity sink." || gotBody.Sections[2].ID != "BINNY-VR-001" {
		t.Errorf("sections = %+v", gotBody.Sections)
	}
	var okResult, saved bool
	for _, e := range events {
		if e["type"] == "tool_result" && e["name"] == "save_report" && e["ok"] == true {
			okResult = true
		}
		if e["type"] == "saved" && e["saved"] == 3 {
			saved = true
		}
	}
	if !okResult || !saved {
		t.Errorf("tool_result ok=%v saved event=%v\n%v", okResult, saved, events)
	}
}

func TestSaveReportToolNeedsFindings(t *testing.T) {
	s := &server{opts: Options{}}
	s.setDirProject("/tmp/x", "proj-123")
	out, isErr := s.runTool(withDraft(context.Background(), &api.UpdateReportRequest{}), "save_report", json.RawMessage(`{}`))
	if !isErr || !strings.Contains(out, "record_finding") {
		t.Errorf("empty draft: out=%q isErr=%v", out, isErr)
	}
	out, isErr = s.runTool(context.Background(), "save_report", json.RawMessage(`{}`))
	if !isErr {
		t.Errorf("no draft: out=%q isErr=%v", out, isErr)
	}
}

func TestChatContextKnowsOpenBIN(t *testing.T) {
	s := &server{opts: Options{Dir: "/tmp/x"}}
	local := s.chatContext()
	if !strings.Contains(local, "OpenBIN") || strings.Contains(local, "save_report") {
		t.Errorf("local context = %q", local)
	}
	s.setDirProject("/tmp/x", "proj-123")
	s.setProjectName("demo.apk")
	cloud := s.chatContext()
	if !strings.Contains(cloud, "demo.apk") || !strings.Contains(cloud, "save_report") {
		t.Errorf("cloud context = %q", cloud)
	}
}
