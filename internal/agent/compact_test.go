package agent

import (
	"strings"
	"testing"

	"openbin.ai/binny/internal/llm"
)

func TestCompactElidesOldToolResults(t *testing.T) {
	big := strings.Repeat("A", 2000) // a large tool output
	msgs := []llm.Message{
		llm.UserText("kickoff"), // 0 — preserved
		{Role: llm.RoleAssistant, Blocks: []llm.Block{{Kind: llm.BlockToolUse, ToolID: "t1", ToolName: "get_function"}}}, // 1
		{Role: llm.RoleUser, Blocks: []llm.Block{llm.ToolResult("t1", big, false)}},                                      // 2 — OLD, should elide
	}
	// 8 recent filler messages; the last one carries a big result that must stay.
	for i := 0; i < 7; i++ {
		msgs = append(msgs, llm.UserText("filler"))
	}
	msgs = append(msgs, llm.Message{Role: llm.RoleUser, Blocks: []llm.Block{llm.ToolResult("t2", big, false)}}) // recent big — keep

	e := &Engine{Runner: &Runner{messages: msgs, compactThreshold: 100}} // low threshold to force compaction
	notice := e.compact()

	// Old result (index 2) elided.
	if got := e.messages[2].Blocks[0].Content; !strings.Contains(got, "elided") {
		t.Errorf("old tool result should be elided, got %q", got[:min(40, len(got))])
	}
	// Structure preserved — still a tool_result answering t1.
	if e.messages[2].Blocks[0].Kind != llm.BlockToolResult || e.messages[2].Blocks[0].ToolUseID != "t1" {
		t.Error("tool pairing broken by compaction")
	}
	// Recent big result (last message) untouched.
	last := e.messages[len(e.messages)-1].Blocks[0]
	if len(last.Content) != 2000 {
		t.Errorf("recent tool result should be intact, len=%d", len(last.Content))
	}
	// One-time notice fired.
	if len(notice) == 0 {
		t.Error("expected a compaction notice on first elision")
	}
	// Idempotent: a second pass elides nothing new and emits no notice.
	if n := e.compact(); len(n) != 0 {
		t.Error("second compaction should be a no-op notice")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
