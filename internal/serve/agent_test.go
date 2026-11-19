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

// findingProvider records one finding, then stops.
type findingProvider struct{ turn int }

func (f *findingProvider) Name() string { return "fake" }
func (f *findingProvider) Stream(ctx context.Context, req llm.Request, onText func(string)) (*llm.Response, error) {
	f.turn++
	if f.turn == 1 {
		return &llm.Response{StopReason: llm.StopToolUse, Blocks: []llm.Block{{
			Kind: llm.BlockToolUse, ToolID: "f1", ToolName: "record_finding",
			Input: json.RawMessage(`{"title":"Unvalidated URL load","severity":"high","cwe":"CWE-939","file":"sources/com/evil/Main.java","line":6,"note":"args[0] flows to loadUrl"}`),
		}}}, nil
	}
	return &llm.Response{StopReason: llm.StopEndTurn, Model: "fake", Blocks: []llm.Block{llm.TextBlock("done")}}, nil
}

func TestRecordFindingEmitsEvent(t *testing.T) {
	s := &server{opts: Options{Dir: sampleTree(t)}}
	var finding map[string]any
	send := func(ev map[string]any) {
		if ev["type"] == "finding" {
			finding = ev
		}
	}
	s.runAgentLoop(context.Background(), &findingProvider{}, llm.Request{
		Messages: []llm.Message{llm.UserText("audit")}, Tools: s.agentTools(),
	}, send)

	if finding == nil {
		t.Fatal("no finding event emitted")
	}
	if finding["severity"] != "high" || finding["title"] != "Unvalidated URL load" || finding["cwe"] != "CWE-939" {
		t.Errorf("finding fields = %+v", finding)
	}
}

// artifactProvider writes an artifact on turn 1 (with usage), then answers.
type artifactProvider struct{ turn int }

func (f *artifactProvider) Name() string { return "fake" }
func (f *artifactProvider) Stream(ctx context.Context, req llm.Request, onText func(string)) (*llm.Response, error) {
	f.turn++
	if f.turn == 1 {
		return &llm.Response{
			StopReason: llm.StopToolUse,
			Usage:      llm.Usage{InputTokens: 1200, OutputTokens: 80},
			Blocks: []llm.Block{{
				Kind: llm.BlockToolUse, ToolID: "a1", ToolName: "write_artifact",
				Input: json.RawMessage(`{"title":"AES decryptor","language":"python","kind":"decryptor","content":"print('x')"}`),
			}},
		}, nil
	}
	return &llm.Response{StopReason: llm.StopEndTurn, Model: "fake",
		Usage:  llm.Usage{InputTokens: 1300, OutputTokens: 40},
		Blocks: []llm.Block{llm.TextBlock("Done.")}}, nil
}

func TestAgentEmitsArtifactAndUsage(t *testing.T) {
	s := &server{opts: Options{}}
	var events []map[string]any
	send := func(ev map[string]any) { events = append(events, ev) }

	s.runAgentLoop(context.Background(), &artifactProvider{}, llm.Request{
		Messages: []llm.Message{llm.UserText("write a decryptor")},
		Tools:    s.agentTools(),
	}, send)

	var art, usage map[string]any
	for _, e := range events {
		if e["type"] == "artifact" {
			art = e
		}
		if e["type"] == "usage" {
			usage = e // keep the last
		}
	}
	if art == nil || art["title"] != "AES decryptor" || art["language"] != "python" {
		t.Fatalf("artifact event wrong: %v", art)
	}
	if usage == nil {
		t.Fatal("no usage event emitted")
	}
	if usage["output"].(int) != 40 {
		t.Errorf("usage output = %v, want 40", usage["output"])
	}
	// write_artifact must be offered even with no tree/binary open.
	var names []string
	for _, d := range s.agentTools() {
		names = append(names, d.Name)
	}
	if !contains(names, "write_artifact") || !contains(names, "record_finding") {
		t.Errorf("base tools missing write_artifact/record_finding: %v", names)
	}
}

// truncatedProvider emits a write_artifact whose argument JSON was cut off by
// the output-token cap (stop_reason=max_tokens), then — after getting the error
// tool_result — finishes with text.
type truncatedProvider struct{ turn int }

func (f *truncatedProvider) Name() string { return "fake" }
func (f *truncatedProvider) Stream(ctx context.Context, req llm.Request, onText func(string)) (*llm.Response, error) {
	f.turn++
	if f.turn == 1 {
		return &llm.Response{
			StopReason: llm.StopMaxTokens,
			Blocks: []llm.Block{{
				Kind: llm.BlockToolUse, ToolID: "t1", ToolName: "write_artifact",
				Input: json.RawMessage(`{"title":"triage","language":"python","content":"#!/usr/bin/env python3\nprint('`), // truncated mid-string
			}},
		}, nil
	}
	return &llm.Response{StopReason: llm.StopEndTurn, Model: "fake", Blocks: []llm.Block{llm.TextBlock("Sent a shorter version.")}}, nil
}

// A tool call cut off by the token cap must NOT be executed as-is: the model gets
// a clear error tool_result (so it can retry smaller) and the UI sees a failed
// tool_result — never a silently-run broken call, and no dead stream.
func TestTruncatedToolCallIsReportedNotRun(t *testing.T) {
	s := &server{opts: Options{}}
	var toolResults []map[string]any
	var sawArtifact bool
	send := func(ev map[string]any) {
		switch ev["type"] {
		case "tool_result":
			toolResults = append(toolResults, ev)
		case "artifact":
			sawArtifact = true
		}
	}
	msgs := s.runAgentLoop(context.Background(), &truncatedProvider{}, llm.Request{
		Messages: []llm.Message{llm.UserText("write a triage script")},
		Tools:    s.agentTools(),
	}, send)

	if len(toolResults) == 0 || toolResults[0]["ok"] != false {
		t.Fatalf("expected a failed tool_result for the truncated call, got %v", toolResults)
	}
	prev, _ := toolResults[0]["preview"].(string)
	if !strings.Contains(prev, "cut off") {
		t.Errorf("tool_result should explain the truncation, got %q", prev)
	}
	if sawArtifact {
		t.Error("a truncated write_artifact must not produce an artifact")
	}
	// The model must have been fed a tool_result so the loop could continue and
	// finish (truncated turn recorded + results + final text = at least 3 msgs
	// beyond the initial user turn).
	if len(msgs) < 3 {
		t.Errorf("loop didn't continue after truncation: %d messages", len(msgs))
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
