package serve

import (
	"context"
	"encoding/json"
	"testing"

	"openbin.ai/binny/internal/tools"
)

// In binary mode the serve agent must offer record_finding PLUS whatever the
// internal/tools registry registered, and dispatch non-finding calls to it.
func TestBinaryModeToolsAndDispatch(t *testing.T) {
	reg := tools.NewRegistry()
	reg.Add(&tools.Tool{
		Def: tools.Def("list_functions", "list funcs", tools.Obj(map[string]any{})),
		Handler: func(_ context.Context, _ json.RawMessage) (string, error) {
			return "func main @ 0x401000", nil
		},
	})

	s := &server{opts: Options{}}
	s.setBinaryProject("proj-1", reg)

	// Tool defs: record_finding + the registry's tools, and NONE of the tree tools.
	names := map[string]bool{}
	for _, d := range s.agentTools() {
		names[d.Name] = true
	}
	if !names["record_finding"] {
		t.Error("record_finding missing in binary mode")
	}
	if !names["list_functions"] {
		t.Error("registry tool list_functions missing in binary mode")
	}
	for _, tree := range []string{"search_code"} {
		if names[tree] {
			t.Errorf("tree tool %q leaked into binary mode", tree)
		}
	}

	// Dispatch: a registry tool runs through the registry.
	out, isErr := s.runTool(context.Background(), "list_functions", json.RawMessage(`{}`))
	if isErr || out != "func main @ 0x401000" {
		t.Errorf("list_functions dispatch = %q, err=%v", out, isErr)
	}

	// record_finding is still handled by the serve agent itself (feeds the drawer).
	out, isErr = s.runTool(context.Background(), `record_finding`, json.RawMessage(`{"title":"x","severity":"high","note":"n"}`))
	if isErr || out == "" {
		t.Errorf("record_finding in binary mode = %q, err=%v", out, isErr)
	}

	// Unknown tool in binary mode is a clean error, not a tree-tool fallthrough.
	if out, isErr := s.runTool(context.Background(), "read_file", json.RawMessage(`{"path":"x"}`)); !isErr {
		t.Errorf("unknown tool should error in binary mode, got %q", out)
	}

	// Leaving binary mode clears the registry.
	s.setDir("/tmp/some/tree")
	if s.reg() != nil {
		t.Error("setDir should clear the binary registry")
	}
}
