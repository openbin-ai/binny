package serve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/llm"
)

// recordThenSaveProvider records a finding and saves in the SAME turn — the case
// that used to push an empty draft because the client's snapshot predated it.
type recordThenSaveProvider struct{ turn int }

func (f *recordThenSaveProvider) Name() string { return "fake" }
func (f *recordThenSaveProvider) Stream(_ context.Context, _ llm.Request, _ func(string)) (*llm.Response, error) {
	f.turn++
	if f.turn == 1 {
		return &llm.Response{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			{Kind: llm.BlockToolUse, ToolID: "r1", ToolName: "record_finding",
				Input: json.RawMessage(`{"title":"Hardcoded backdoor","severity":"critical","cwe":"CWE-798","function":"login","note":"accepts the literal ARTEX token"}`)},
			{Kind: llm.BlockToolUse, ToolID: "s1", ToolName: "save_report",
				Input: json.RawMessage(`{"summary":"One critical backdoor."}`)},
		}}, nil
	}
	return &llm.Response{StopReason: llm.StopEndTurn, Model: "fake", Blocks: []llm.Block{llm.TextBlock("Pushed.")}}, nil
}

func TestSaveReportMergesSameTurnFindings(t *testing.T) {
	isolateCreds(t)
	var gotBody api.UpdateReportRequest
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(api.Report{ID: "rep-1"})
	}))
	defer backend.Close()

	s := &server{opts: Options{}}
	s.setDirProject("/tmp/x/src", "proj-123")
	s.setProjectName("artex")
	s.newClient = func() (*api.Client, error) {
		return api.New(config.Endpoints{APIBase: backend.URL}, staticToken("tok")), nil
	}

	// No client draft at all (report:null) — the finding exists only because it
	// was recorded in this same turn.
	ctx := withFindings(withDraft(context.Background(), nil), &findingsAccum{})
	var saved bool
	s.runAgentLoop(ctx, &recordThenSaveProvider{}, llm.Request{
		Messages: []llm.Message{llm.UserText("record the backdoor and push the report")},
		Tools:    s.agentTools(),
	}, func(ev map[string]any) {
		if ev["type"] == "saved" {
			saved = true
		}
	})

	if !saved {
		t.Fatal("expected a saved event — the same-turn finding should have produced a non-empty draft")
	}
	// executive summary + the one finding section.
	if len(gotBody.Sections) != 2 {
		t.Fatalf("pushed %d sections, want 2: %+v", len(gotBody.Sections), gotBody.Sections)
	}
	if gotBody.Sections[0].ID != "executive-summary" {
		t.Errorf("first section = %+v", gotBody.Sections[0])
	}
	if gotBody.Sections[1].Title != "Hardcoded backdoor" {
		t.Errorf("finding section = %+v", gotBody.Sections[1])
	}
}
