package serve

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"openbin.ai/binny/internal/llm"
)

// The agentic tool loop. When a decompiled tree is being served (--serve-dir),
// the model gets read-only tools over it and BINNY *investigates* — it lists,
// searches and reads files on its own and reports back — instead of answering
// from a single pasted file. This is the GUI equivalent of the CLI's direct
// mode, kept deliberately local: the tools only ever touch the served tree.
//
// This is NOT yet the full staged engine (triage→…→review, structured findings,
// CVE reports); that's phase 4 in docs/DESKTOP.md. This is the agentic core it
// builds on, and it runs fully offline against a tool-capable local model.

const (
	maxAgentIters   = 16
	maxListFiles    = 400
	maxSearchHits   = 60
	maxSearchFile   = 1 << 20 // skip files larger than this in search
	maxReadLines    = 400
	toolPreviewSpan = 300
)

// recordFindingTool is always offered so the agent can pin structured findings
// into the Findings drawer, whatever else it's working with.
func recordFindingTool() llm.Tool {
	obj := func(props map[string]any, required ...string) map[string]any {
		m := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			m["required"] = required
		}
		return m
	}
	str := map[string]any{"type": "string"}
	return llm.Tool{
		Name: "record_finding",
		Description: "Pin a structured finding to the Findings panel. Use for each distinct issue. " +
			"severity is one of info|low|medium|high|critical. Include file and line when you have them, " +
			"a CWE id when applicable, and a one-line note with the evidence.",
		InputSchema: obj(map[string]any{
			"title":        str,
			"severity":     map[string]any{"type": "string", "enum": []string{"info", "low", "medium", "high", "critical"}},
			"cwe":          str,
			"file":         str,
			"line":         map[string]any{"type": "integer"},
			"reachability": map[string]any{"type": "string", "enum": []string{"proven", "likely", "unproven", "ruled_out"}},
			"note":         str,
		}, "title", "severity", "note"),
	}
}

// agentTools exposes the tools the model may call. record_finding is always
// available. With a binary project open the agent gets the full Ghidra-backed
// tool set (functions/strings/imports/xrefs/…) from internal/tools; with a
// decompiled tree served it gets read-only tree tools; with neither it's a plain
// chat.
func (s *server) agentTools() []llm.Tool {
	base := []llm.Tool{recordFindingTool()}
	if reg := s.reg(); reg != nil {
		return append(base, reg.Defs()...) // binary mode: the real BIN toolbox
	}
	if s.dir() == "" {
		return base
	}
	obj := func(props map[string]any, required ...string) map[string]any {
		m := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			m["required"] = required
		}
		return m
	}
	str := map[string]any{"type": "string"}
	intp := map[string]any{"type": "integer"}
	return append(base,
		llm.Tool{
			Name:        "list_files",
			Description: "List files in the decompiled tree. Optionally scope to a subdirectory (dir) and/or filter by a path substring (filter).",
			InputSchema: obj(map[string]any{"dir": str, "filter": str}),
		},
		llm.Tool{
			Name:        "read_file",
			Description: "Read a file from the tree by its path (as returned by list_files/search_code). Optional start_line (1-based) and max_lines.",
			InputSchema: obj(map[string]any{"path": str, "start_line": intp, "max_lines": intp}, "path"),
		},
		llm.Tool{
			Name:        "search_code",
			Description: "Regex (RE2) search across the tree. Returns path:line: matching lines. Optional dir to scope.",
			InputSchema: obj(map[string]any{"regex": str, "dir": str}, "regex"),
		},
	)
}

// runTool executes one tool call. record_finding is handled here (it feeds the
// Findings drawer); in binary mode every other tool is dispatched to the real
// internal/tools registry; otherwise the read-only tree tools run.
func (s *server) runTool(ctx context.Context, name string, input json.RawMessage) (string, bool) {
	if name == "record_finding" {
		var in struct{ Title, Severity string }
		_ = json.Unmarshal(input, &in)
		if in.Title == "" || in.Severity == "" {
			return "record_finding needs at least title and severity", true
		}
		return "recorded [" + in.Severity + "] " + in.Title, false
	}
	if reg := s.reg(); reg != nil {
		if reg.Has(name) {
			return reg.Run(ctx, name, input)
		}
		return "unknown tool: " + name, true
	}
	switch name {
	case "list_files":
		var in struct{ Dir, Filter string }
		_ = json.Unmarshal(input, &in)
		return s.toolListFiles(in.Dir, in.Filter)
	case "read_file":
		var in struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
			MaxLines  int    `json:"max_lines"`
		}
		_ = json.Unmarshal(input, &in)
		return s.toolReadFile(in.Path, in.StartLine, in.MaxLines)
	case "search_code":
		var in struct{ Regex, Dir string }
		_ = json.Unmarshal(input, &in)
		return s.toolSearch(in.Regex, in.Dir)
	default:
		return "unknown tool: " + name, true
	}
}

func (s *server) scopeDir(dir string) (string, bool) {
	if dir == "" {
		return s.dir(), true
	}
	return safeJoin(s.dir(), dir)
}

func (s *server) toolListFiles(dir, filter string) (string, bool) {
	base, ok := s.scopeDir(dir)
	if !ok {
		return "invalid dir", true
	}
	var files []string
	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(s.dir(), p)
		rel = filepath.ToSlash(rel)
		if filter == "" || strings.Contains(rel, filter) {
			files = append(files, rel)
		}
		return nil
	})
	sort.Strings(files)
	n := len(files)
	if n == 0 {
		return "no files" + filterNote(filter), false
	}
	trunc := ""
	if n > maxListFiles {
		files = files[:maxListFiles]
		trunc = fmt.Sprintf("\n… %d more (narrow with dir/filter)", n-maxListFiles)
	}
	return fmt.Sprintf("%d files%s:\n%s%s", n, filterNote(filter), strings.Join(files, "\n"), trunc), false
}

func filterNote(f string) string {
	if f == "" {
		return ""
	}
	return " matching " + f
}

func (s *server) toolReadFile(path string, start, max int) (string, bool) {
	abs, ok := safeJoin(s.dir(), path)
	if !ok {
		return "invalid path", true
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "cannot read " + path + ": " + err.Error(), true
	}
	lines := strings.Split(string(data), "\n")
	if start < 1 {
		start = 1
	}
	if start > len(lines) {
		return fmt.Sprintf("%s has %d lines; start_line %d is past the end", path, len(lines), start), true
	}
	if max <= 0 || max > maxReadLines {
		max = maxReadLines
	}
	end := start - 1 + max
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s (lines %d-%d of %d):\n", path, start, end, len(lines))
	for i := start - 1; i < end; i++ {
		fmt.Fprintf(&b, "%6d  %s\n", i+1, lines[i])
	}
	return b.String(), false
}

func (s *server) toolSearch(pattern, dir string) (string, bool) {
	if pattern == "" {
		return "empty regex", true
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "bad regex: " + err.Error(), true
	}
	base, ok := s.scopeDir(dir)
	if !ok {
		return "invalid dir", true
	}
	var hits []string
	total := 0
	_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, e := d.Info(); e == nil && info.Size() > maxSearchFile {
			return nil
		}
		data, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		rel, _ := filepath.Rel(s.dir(), p)
		rel = filepath.ToSlash(rel)
		for i, ln := range strings.Split(string(data), "\n") {
			if re.MatchString(ln) {
				total++
				if len(hits) < maxSearchHits {
					t := strings.TrimSpace(ln)
					if len(t) > toolPreviewSpan {
						t = t[:toolPreviewSpan] + "…"
					}
					hits = append(hits, fmt.Sprintf("%s:%d: %s", rel, i+1, t))
				}
			}
		}
		return nil
	})
	if total == 0 {
		return "no matches for " + pattern, false
	}
	trunc := ""
	if total > len(hits) {
		trunc = fmt.Sprintf("\n… %d more matches (narrow the regex)", total-len(hits))
	}
	return fmt.Sprintf("%d matches:\n%s%s", total, strings.Join(hits, "\n"), trunc), false
}

// runAgentLoop drives the provider with the tool set until the model stops asking
// for tools (or the iteration cap is hit), emitting SSE events via send:
//
//	{type:chunk,text}             incremental assistant text
//	{type:tool_call,name,input}   the model invoked a tool
//	{type:tool_result,name,ok,preview}
//	{type:done,model} | {type:error,error}
func (s *server) runAgentLoop(ctx context.Context, provider llm.Provider, req llm.Request, send func(map[string]any)) {
	for iter := 0; iter < maxAgentIters; iter++ {
		resp, err := provider.Stream(ctx, req, func(delta string) {
			send(map[string]any{"type": "chunk", "text": delta})
		})
		if err != nil {
			send(map[string]any{"type": "error", "error": err.Error()})
			return
		}
		calls := resp.ToolCalls()
		if len(calls) == 0 {
			send(map[string]any{"type": "done", "model": resp.Model})
			return
		}
		// Record the assistant's tool_use turn, then answer each call.
		req.Messages = append(req.Messages, resp.AsMessage())
		results := make([]llm.Block, 0, len(calls))
		for _, c := range calls {
			send(map[string]any{"type": "tool_call", "name": c.Name, "input": json.RawMessage(c.Input)})
			out, isErr := s.runTool(ctx, c.Name, c.Input)
			// A successful finding becomes its own event for the Findings drawer.
			if c.Name == "record_finding" && !isErr {
				var f map[string]any
				if json.Unmarshal(c.Input, &f) == nil {
					f["type"] = "finding"
					send(f)
				}
			}
			send(map[string]any{"type": "tool_result", "name": c.Name, "ok": !isErr, "preview": preview(out)})
			results = append(results, llm.ToolResult(c.ID, out, isErr))
		}
		req.Messages = append(req.Messages, llm.Message{Role: llm.RoleUser, Blocks: results})
	}
	send(map[string]any{"type": "done", "model": req.Model, "note": "reached tool-call limit"})
}

func preview(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > toolPreviewSpan {
		return s[:toolPreviewSpan] + "…"
	}
	return s
}
