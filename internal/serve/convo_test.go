package serve

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"openbin.ai/binny/internal/llm"
)

// scriptedProvider returns a fixed sequence of responses, one per Stream call,
// and records the history it was handed each time.
type scriptedProvider struct {
	resps []*llm.Response
	seen  [][]llm.Message
	i     int
}

func (p *scriptedProvider) Name() string { return "scripted" }
func (p *scriptedProvider) Stream(_ context.Context, req llm.Request, _ func(string)) (*llm.Response, error) {
	p.seen = append(p.seen, req.Messages)
	r := p.resps[p.i]
	if p.i < len(p.resps)-1 {
		p.i++
	}
	return r, nil
}

func textResp(s string) *llm.Response {
	return &llm.Response{Blocks: []llm.Block{llm.TextBlock(s)}, Model: "m"}
}
func toolResp(id, name, input string) *llm.Response {
	return &llm.Response{Blocks: []llm.Block{{Kind: llm.BlockToolUse, ToolID: id, ToolName: name, Input: json.RawMessage(input)}}, Model: "m"}
}

// A run that calls a tool then answers must return the whole transcript —
// tool_use + tool_result + the final text — so the caller can remember it.
func TestRunAgentLoopReturnsTranscript(t *testing.T) {
	s := &server{}
	prov := &scriptedProvider{resps: []*llm.Response{
		toolResp("t1", "record_finding", `{"title":"x","severity":"low","note":"n"}`),
		textResp("done, here is the summary"),
	}}
	final := s.runAgentLoop(context.Background(), prov, llm.Request{
		Messages: []llm.Message{llm.UserText("investigate")},
	}, func(map[string]any) {})

	var kinds []string
	for _, m := range final {
		for _, b := range m.Blocks {
			kinds = append(kinds, string(m.Role)+"/"+string(b.Kind))
		}
	}
	got := strings.Join(kinds, ",")
	want := "user/text,assistant/tool_use,user/tool_result,assistant/text"
	if got != want {
		t.Fatalf("transcript = %q, want %q", got, want)
	}
}

// loadConvo + the handleChat resume rule: a second turn builds on the stored
// transcript, so the model sees the tools it already ran instead of restarting.
func TestConvoResumeAndReset(t *testing.T) {
	s := &server{}

	// Turn 1 remembers a transcript under an id.
	s.storeConvo("c1", []llm.Message{
		llm.UserText("investigate"),
		{Role: llm.RoleAssistant, Blocks: []llm.Block{{Kind: llm.BlockToolUse, ToolID: "t1", ToolName: "get_metadata"}}},
		{Role: llm.RoleUser, Blocks: []llm.Block{llm.ToolResult("t1", "Go binary, 13826 funcs", false)}},
		{Role: llm.RoleAssistant, Blocks: []llm.Block{llm.TextBlock("found the build info")}},
	})

	prior := s.loadConvo("c1")
	if len(prior) != 4 {
		t.Fatalf("loadConvo len = %d, want 4", len(prior))
	}

	// Eviction keeps the map bounded.
	for i := 0; i < maxConvos+5; i++ {
		s.storeConvo("bulk-"+string(rune('a'+i%26))+string(rune('0'+i/26)), []llm.Message{llm.UserText("x")})
	}
	s.mu.RLock()
	n := len(s.convos)
	s.mu.RUnlock()
	if n > maxConvos {
		t.Errorf("convos not capped: %d > %d", n, maxConvos)
	}
}
