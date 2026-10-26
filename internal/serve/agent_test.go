package serve

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"openbin.ai/binny/internal/llm"
)

func TestToolExecutors(t *testing.T) {
	s := &server{opts: Options{Dir: sampleTree(t)}}

	out, isErr := s.toolListFiles("", "")
	if isErr || !strings.Contains(out, "sources/com/evil/Main.java") {
		t.Errorf("list_files = %q (err=%v)", out, isErr)
	}
	out, isErr = s.toolListFiles("", ".xml")
	if isErr || !strings.Contains(out, "AndroidManifest.xml") || strings.Contains(out, "Main.java") {
		t.Errorf("filtered list_files = %q", out)
	}
	out, isErr = s.toolReadFile("sources/com/evil/Main.java", 1, 0)
	if isErr || !strings.Contains(out, "package com.evil") {
		t.Errorf("read_file = %q (err=%v)", out, isErr)
	}
	out, isErr = s.toolSearch("com\\.evil", "")
	if isErr || !strings.Contains(out, "Main.java:1") {
		t.Errorf("search_code = %q (err=%v)", out, isErr)
	}
	// safety: tool paths can't escape the tree
	if _, isErr := s.toolReadFile("../../../etc/passwd", 1, 0); !isErr {
		t.Error("read_file allowed traversal")
	}
}

// fakeProvider calls one tool on the first turn, then answers with text.
type fakeProvider struct{ turn int }

func (f *fakeProvider) Name() string { return "fake" }
func (f *fakeProvider) Stream(ctx context.Context, req llm.Request, onText func(string)) (*llm.Response, error) {
	f.turn++
	if f.turn == 1 {
		return &llm.Response{
			StopReason: llm.StopToolUse,
			Blocks: []llm.Block{{
				Kind: llm.BlockToolUse, ToolID: "t1", ToolName: "search_code",
				Input: json.RawMessage(`{"regex":"loadUrl"}`),
			}},
		}, nil
	}
	if onText != nil {
		onText("Found the sink.")
	}
	return &llm.Response{StopReason: llm.StopEndTurn, Model: "fake", Blocks: []llm.Block{llm.TextBlock("Found the sink.")}}, nil
}

func TestRunAgentLoop(t *testing.T) {
	s := &server{opts: Options{Dir: sampleTree(t)}}
	var events []map[string]any
	send := func(ev map[string]any) { events = append(events, ev) }

	s.runAgentLoop(context.Background(), &fakeProvider{}, llm.Request{
		Messages: []llm.Message{llm.UserText("find the sink")},
		Tools:    s.agentTools(),
	}, send)

	var sawCall, sawResult, sawChunk, sawDone bool
	for _, e := range events {
		switch e["type"] {
		case "tool_call":
			sawCall = e["name"] == "search_code"
		case "tool_result":
			sawResult = e["ok"] == true
		case "chunk":
			if strings.Contains(e["text"].(string), "sink") {
				sawChunk = true
			}
		case "done":
			sawDone = true
		}
	}
	if !sawCall || !sawResult || !sawChunk || !sawDone {
		t.Errorf("loop events incomplete: call=%v result=%v chunk=%v done=%v\n%v", sawCall, sawResult, sawChunk, sawDone, events)
	}
}
