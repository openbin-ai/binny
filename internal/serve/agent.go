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

	"openbin.ai/binny/internal/api"
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
	maxAgentIters   = 24
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
			"severity is one of info|low|medium|high|critical. Anchor every finding to the code it is about: " +
			"on a binary set `function` to the exact function name from list_functions/get_function (e.g. FUN_00401a20 or main) — findings without a real function are refused; " +
			"on a source tree set file (+ line) and optionally `function` to the enclosing method. " +
			"Add a CWE id when applicable and a one-line note with the evidence.",
		InputSchema: obj(map[string]any{
			"title":        str,
			"severity":     map[string]any{"type": "string", "enum": []string{"info", "low", "medium", "high", "critical"}},
			"cwe":          str,
			"function":     map[string]any{"type": "string", "description": "function the finding lives in — on a binary the exact Ghidra function name (required there); on source the enclosing method/class"},
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
// writeArtifactTool lets the agent emit generated code — a malware decryptor, a
// vuln PoC, a YARA rule, a helper script — into the Artifacts panel. Always
// available, like record_finding.
func writeArtifactTool() llm.Tool {
	obj := func(props map[string]any, required ...string) map[string]any {
		m := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			m["required"] = required
		}
		return m
	}
	str := map[string]any{"type": "string"}
	return llm.Tool{
		Name: "write_artifact",
		Description: "Create a code artifact (shown in the Artifacts panel, copyable/downloadable): a malware decryptor/unpacker, a vulnerability PoC/exploit, a YARA/Sigma rule, or a helper script. " +
			"Provide a short title, the language (e.g. python, c, go, yara, bash), a kind (decryptor|poc|yara|script|other), and the full runnable content. Prefer this over pasting long code into chat.",
		InputSchema: obj(map[string]any{
			"title":    str,
			"language": str,
			"kind":     map[string]any{"type": "string", "enum": []string{"decryptor", "poc", "yara", "script", "other"}},
			"content":  str,
		}, "title", "language", "content"),
	}
}

// saveReportTool is the chat-side /save: offered only while a project from the
// analyst's OpenBIN account is open (a local tree has no backend report).
func saveReportTool() llm.Tool {
	return llm.Tool{
		Name: "save_report",
		Description: "Push the current draft report to the open OpenBIN project's report on the analyst's account (saved as a DRAFT they review/publish on the web app). " +
			"The draft is every finding recorded with record_finding, rendered as sections, led by the executive summary you pass here. " +
			"Call this when the analyst asks to push, save, upload, sync or publish the report/findings to OpenBIN, their project or their account. Record findings first; an empty draft can't be saved.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{
			"summary": map[string]any{"type": "string", "description": "Executive summary in Markdown: what the target is, the key findings and their impact, and recommended next steps. Ground it in recorded findings only."},
		}},
	}
}

// The draft the UI sent with the chat request rides on the context so the
// save_report tool can push it without threading a new parameter through the
// loop. Nil means the request carried none.
type draftKey struct{}

func withDraft(ctx context.Context, d *api.UpdateReportRequest) context.Context {
	return context.WithValue(ctx, draftKey{}, d)
}

func draftFrom(ctx context.Context) *api.UpdateReportRequest {
	d, _ := ctx.Value(draftKey{}).(*api.UpdateReportRequest)
	return d
}

// toolSaveReport pushes the request's draft (plus the model's summary) to the
// open project's report. Returns the backend result for the model and the
// section count for the UI's "saved" event (0 on failure).
func (s *server) toolSaveReport(ctx context.Context, input json.RawMessage) (string, int, bool) {
	pid := s.projectID()
	if pid == "" {
		return "no OpenBIN project is open — ask the analyst to open one from their account (Cloud button) first", 0, true
	}
	draft := draftFrom(ctx)
	if draft == nil || len(draft.Sections) == 0 {
		return "the draft is empty — pin each issue with record_finding first, then save_report", 0, true
	}
	client, err := s.authClient()
	if err != nil {
		return "not signed in to OpenBIN: " + err.Error() + " — ask the analyst to sign in (Cloud button)", 0, true
	}
	var in struct{ Summary string }
	_ = json.Unmarshal(input, &in)
	req := api.UpdateReportRequest{Title: draft.Title}
	if sum := strings.TrimSpace(in.Summary); sum != "" {
		req.Sections = append(req.Sections, api.ReportSection{ID: "executive-summary", Title: "Executive summary", Content: sum})
	}
	req.Sections = append(req.Sections, draft.Sections...)
	if req.Title == "" {
		req.Title = "BINNY draft — " + s.projectName()
	}
	if _, err := pushReport(client, pid, req); err != nil {
		return "push to OpenBIN failed: " + err.Error(), 0, true
	}
	return fmt.Sprintf("saved %d sections to the project report on OpenBIN (DRAFT — the analyst reviews/publishes it on the web app)", len(req.Sections)), len(req.Sections), false
}

// highlightFunctionTool mirrors the TUI's tool of the same name: with a cloud
// project open it creates a highlight on the project's Highlights board on
// OpenBIN; for a local analysis it is listed in the UI's Highlights panel only.
func highlightFunctionTool(binary bool) llm.Tool {
	desc := "Add a source file to the Highlights board (evidence board) — the files/classes that matter most, and why. Pass the path, optionally as path:line to point at the pivotal line."
	name := "file path to highlight, e.g. sources/com/evil/Crypto.java or sources/com/evil/Crypto.java:42"
	if binary {
		desc = "Add a function to the Highlights board (evidence board) — the functions that matter most (entry, crypto, C2, the vulnerable sink…), and why. Use the exact function name from list_functions/get_function."
		name = "exact function name to highlight"
	}
	str := func(d string) map[string]any { return map[string]any{"type": "string", "description": d} }
	return llm.Tool{
		Name:        "highlight_function",
		Description: desc + " With a project from the analyst's OpenBIN account open this is pushed to the project's board on OpenBIN immediately.",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{
			"name": str(name),
			"tag":  str("short tag, e.g. 'crypto', 'c2', 'entry', 'sink'"),
			"note": str("why this function/file matters"),
		}, "required": []string{"name"}},
	}
}

// binFunctionExists reports whether name is a function in the open binary's
// analysis. ok=false with known=false when no analysis is loaded (nothing to
// check against), so callers don't refuse findings in that case.
func (s *server) binFunctionExists(name string) (exists, known bool) {
	tb := s.binTB()
	if tb == nil {
		return false, false
	}
	a, err := tb.Analysis()
	if err != nil || a == nil {
		return false, false
	}
	for i := range a.Functions {
		if a.Functions[i].Name == name {
			return true, true
		}
	}
	return false, true
}

// splitFileLine splits "path/File.java:42" into path and line; a ref without a
// numeric :line suffix comes back whole with line 0.
func splitFileLine(ref string) (string, int) {
	i := strings.LastIndexByte(ref, ':')
	if i <= 0 || i == len(ref)-1 {
		return ref, 0
	}
	n := 0
	for _, r := range ref[i+1:] {
		if r < '0' || r > '9' {
			return ref, 0
		}
		n = n*10 + int(r-'0')
	}
	return ref[:i], n
}

// checkFinding validates a record_finding call and returns the function it is
// anchored to ("" on a source tree with none given). On a binary with a loaded
// analysis the function must exist: that is what lets the Findings panel jump
// to the code, and it stops the model pinning claims to invented names.
func (s *server) checkFinding(input json.RawMessage) (fn string, errMsg string) {
	var in struct{ Title, Severity, Function, File string }
	_ = json.Unmarshal(input, &in)
	if in.Title == "" || in.Severity == "" {
		return "", "record_finding needs at least title and severity"
	}
	fn = strings.TrimSpace(in.Function)
	if s.reg() == nil {
		return fn, "" // source tree: file/line anchor it; function is optional
	}
	if fn == "" {
		fn = strings.TrimSpace(in.File) // older habit: the function name in `file`
	}
	if fn == "" {
		return "", "binary findings must name the function they are about: set `function` to the exact name from list_functions/get_function"
	}
	if exists, known := s.binFunctionExists(fn); known && !exists {
		return "", fmt.Sprintf("no function %q in this binary — use the exact name from list_functions/get_function", fn)
	}
	return fn, ""
}

// toolHighlight runs highlight_function. The returned event (nil on error) is
// what the UI lists in its Highlights panel: {name, kind, line, tag, note, pushed}.
func (s *server) toolHighlight(input json.RawMessage) (string, map[string]any, bool) {
	var in struct{ Name, Tag, Note string }
	_ = json.Unmarshal(input, &in)
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return "highlight_function needs a name", nil, true
	}
	binary := s.reg() != nil
	req := api.CreateHighlightRequest{Type: api.HighlightFunction, TargetRef: in.Name, Tag: in.Tag, Note: in.Note}
	ev := map[string]any{"type": "highlight", "name": in.Name, "kind": "function", "tag": in.Tag, "note": in.Note, "line": 0}
	what := "function"
	if binary {
		if exists, known := s.binFunctionExists(in.Name); known && !exists {
			return fmt.Sprintf("no function %q in this binary — use the exact name from list_functions/get_function", in.Name), nil, true
		}
	} else {
		// Source trees anchor highlights to a FILE (the web app opens targetRef
		// as a path); a path:line ref keeps its line in the note.
		path, line := splitFileLine(in.Name)
		req.Type, req.TargetRef, what = api.HighlightFile, path, "file"
		ev["kind"], ev["name"], ev["line"] = "file", path, line
		if line > 0 {
			req.Note = strings.TrimSpace(fmt.Sprintf("line %d: %s", line, in.Note))
		}
	}
	pid := s.projectID()
	if pid == "" {
		ev["pushed"] = false
		return fmt.Sprintf("noted highlight %s %s [%s] (local analysis — no OpenBIN board; it is listed in the Highlights panel)", what, in.Name, in.Tag), ev, false
	}
	client, err := s.authClient()
	if err != nil {
		return "not signed in to OpenBIN: " + err.Error() + " — ask the analyst to sign in (Cloud button)", nil, true
	}
	if _, err := client.CreateHighlight(pid, req); err != nil {
		return "create highlight on OpenBIN failed: " + err.Error(), nil, true
	}
	ev["pushed"] = true
	return fmt.Sprintf("highlighted %s %s [%s] on the project's Highlights board on OpenBIN", what, in.Name, in.Tag), ev, false
}

func (s *server) agentTools() []llm.Tool {
	base := []llm.Tool{recordFindingTool(), writeArtifactTool(), highlightFunctionTool(s.reg() != nil)}
	if s.projectID() != "" {
		base = append(base, saveReportTool())
	}
	if x := s.sampleTools(); x != nil {
		base = append(base, x.Defs()...) // sandbox over the raw sample (sample.go)
	}
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
		if _, msg := s.checkFinding(input); msg != "" {
			return msg, true
		}
		var in struct{ Title, Severity string }
		_ = json.Unmarshal(input, &in)
		return "recorded [" + in.Severity + "] " + in.Title, false
	}
	if name == "highlight_function" {
		out, _, isErr := s.toolHighlight(input)
		return out, isErr
	}
	if name == "write_artifact" {
		var in struct{ Title, Content string }
		_ = json.Unmarshal(input, &in)
		if in.Title == "" || in.Content == "" {
			return "write_artifact needs at least title and content", true
		}
		return "created artifact: " + in.Title, false
	}
	if name == "save_report" {
		out, _, isErr := s.toolSaveReport(ctx, input)
		return out, isErr
	}
	if x := s.sampleTools(); x != nil && x.Has(name) {
		return x.Run(ctx, name, input)
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
//
// It returns the full transcript (text + tool_use + tool_result turns) so the
// caller can remember it and let the next request resume instead of replaying.
// On a mid-run error it returns what ran so far, so "continue" keeps that work.
func (s *server) runAgentLoop(ctx context.Context, provider llm.Provider, req llm.Request, send func(map[string]any)) []llm.Message {
	for iter := 0; iter < maxAgentIters; iter++ {
		resp, err := provider.Stream(ctx, req, func(delta string) {
			send(map[string]any{"type": "chunk", "text": delta})
		})
		if err != nil {
			send(map[string]any{"type": "error", "error": err.Error()})
			return req.Messages
		}
		// Token accounting for the counter + budget. context = the full prompt size
		// of THIS call (how big the conversation has grown); input/output are the
		// billed deltas this call adds to the session total.
		u := resp.Usage
		send(map[string]any{
			"type":    "usage",
			"input":   u.InputTokens + u.CacheCreationTokens,
			"output":  u.OutputTokens,
			"cached":  u.CacheReadTokens,
			"context": u.InputTokens + u.CacheReadTokens + u.CacheCreationTokens,
		})
		calls := resp.ToolCalls()
		if len(calls) == 0 {
			req.Messages = append(req.Messages, resp.AsMessage()) // remember the final answer
			send(map[string]any{"type": "done", "model": resp.Model})
			return req.Messages
		}
		// Record the assistant's tool_use turn, then answer each call.
		req.Messages = append(req.Messages, resp.AsMessage())
		results := make([]llm.Block, 0, len(calls))
		for _, c := range calls {
			send(map[string]any{"type": "tool_call", "name": c.Name, "input": json.RawMessage(c.Input)})
			var out string
			var isErr bool
			switch c.Name {
			case "save_report":
				// Pushed from chat: tell the UI so the Report panel reflects it.
				var n int
				out, n, isErr = s.toolSaveReport(ctx, c.Input)
				if !isErr {
					send(map[string]any{"type": "saved", "saved": n})
				}
			case "highlight_function":
				var ev map[string]any
				out, ev, isErr = s.toolHighlight(c.Input)
				if ev != nil {
					send(ev)
				}
			default:
				out, isErr = s.runTool(ctx, c.Name, c.Input)
			}
			// A successful finding / artifact becomes its own event for its drawer.
			if c.Name == "record_finding" && !isErr {
				var f map[string]any
				if json.Unmarshal(c.Input, &f) == nil {
					f["type"] = "finding"
					if fn, _ := s.checkFinding(c.Input); fn != "" {
						f["function"] = fn // normalized (binary: may have come in as `file`)
					}
					send(f)
				}
			}
			if c.Name == "write_artifact" && !isErr {
				var a map[string]any
				if json.Unmarshal(c.Input, &a) == nil {
					a["type"] = "artifact"
					send(a)
				}
			}
			send(map[string]any{"type": "tool_result", "name": c.Name, "ok": !isErr, "preview": preview(out)})
			results = append(results, llm.ToolResult(c.ID, out, isErr))
		}
		req.Messages = append(req.Messages, llm.Message{Role: llm.RoleUser, Blocks: results})
	}
	// Hit the tool-call cap without a final answer. Force a conclusion: one more
	// call with tools OFF so the model must respond in text instead of looping.
	req.Tools = nil
	req.Messages = append(req.Messages, llm.UserText("You've reached the investigation step limit. Stop using tools and give your conclusion now, based on what you've found so far."))
	resp, err := provider.Stream(ctx, req, func(delta string) {
		send(map[string]any{"type": "chunk", "text": delta})
	})
	if err != nil {
		send(map[string]any{"type": "error", "error": err.Error()})
		return req.Messages
	}
	req.Messages = append(req.Messages, resp.AsMessage())
	u := resp.Usage
	send(map[string]any{"type": "usage", "input": u.InputTokens + u.CacheCreationTokens, "output": u.OutputTokens, "cached": u.CacheReadTokens, "context": u.InputTokens + u.CacheReadTokens + u.CacheCreationTokens})
	send(map[string]any{"type": "done", "model": resp.Model, "note": "reached the tool-call limit — concluded from findings so far"})
	return req.Messages
}

func preview(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > toolPreviewSpan {
		return s[:toolPreviewSpan] + "…"
	}
	return s
}
