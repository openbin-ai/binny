package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/store"
)

// Output caps keep tool results from blowing the LLM context. A single result
// is a summary the model acts on, not a data dump — it can always narrow with
// a filter or fetch a specific function.
const (
	maxListItems   = 200
	maxSearchHits  = 60
	maxDecompChars = 12000
	maxFileChars   = 20000
)

// Toolbox holds the dependencies BINNY's tools operate over: the backend
// client and the attached project, plus a lazily-loaded, cached copy of the
// binary-analysis blob (fetched once, reused across every read tool).
//
// The blob is sourced local-first: a local project ("local:<sha12>") reads it
// straight from the on-disk store; a backend project checks the store's
// read-through cache before hitting the API/CloudFront (and populates the
// cache after a fetch), so repeat sessions on the same project cost nothing.
type Toolbox struct {
	API     *api.Client
	Project *api.Project

	mu             sync.Mutex
	sample         *api.Sample // active EXTRA sample; nil = the project's primary binary
	analysis       *api.Analysis
	analysisErr    error
	analysisLoaded bool

	// APK/script projects: the file tree and parsed manifest, fetched once.
	tree           *api.FileNode
	treeErr        error
	treeLoaded     bool
	manifestData   *api.Manifest
	manifestErr    error
	manifestLoaded bool
	src            sourceTree // resolved by source(): backend API or local JADX tree

	// Progress, when set, receives one-off status lines (e.g. the source
	// tree download) for the analyst to see.
	Progress func(format string, args ...any)
}

func (tb *Toolbox) progress() func(string, ...any) {
	if tb.Progress != nil {
		return tb.Progress
	}
	return func(string, ...any) {}
}

// NewToolbox builds a toolbox for a project.
func NewToolbox(client *api.Client, project *api.Project) *Toolbox {
	return &Toolbox{API: client, Project: project}
}

// ActiveSample returns the extra sample the read tools currently serve, or
// nil when they serve the project's primary binary.
func (tb *Toolbox) ActiveSample() *api.Sample {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.sample
}

// SwitchSample points every read tool at one of the project's extra samples
// (nil = back to the primary). The target blob is loaded eagerly so a bad
// switch fails here, not on the next get_function. The previously loaded blob
// is kept on failure.
func (tb *Toolbox) SwitchSample(s *api.Sample) (*api.Analysis, error) {
	if s != nil && !s.Ready() {
		return nil, fmt.Errorf("sample %q is %s — only READY samples have an analysis", s.DisplayName(), s.Status)
	}
	tb.mu.Lock()
	prev, prevA, prevErr, prevLoaded := tb.sample, tb.analysis, tb.analysisErr, tb.analysisLoaded
	tb.sample = s
	tb.analysisLoaded = false
	tb.mu.Unlock()
	a, err := tb.analysisBlob()
	if err != nil {
		tb.mu.Lock()
		tb.sample, tb.analysis, tb.analysisErr, tb.analysisLoaded = prev, prevA, prevErr, prevLoaded
		tb.mu.Unlock()
		return nil, err
	}
	return a, nil
}

// cacheKey is the on-disk read-through cache key for the active blob:
// the project id alone for the primary, "<project>:<sample>" for an extra
// sample — so switching samples never serves a stale sibling.
func (tb *Toolbox) cacheKey() string {
	if tb.sample != nil {
		return tb.Project.ID + ":" + tb.sample.ID
	}
	return tb.Project.ID
}

// analysisBlob lazily loads + caches the binary-analysis JSON. BIN-only; other
// kinds don't have one and the read tools that need it report that clearly.
func (tb *Toolbox) analysisBlob() (*api.Analysis, error) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.analysisLoaded {
		return tb.analysis, tb.analysisErr
	}
	tb.analysisLoaded = true
	if tb.Project.Kind != api.KindBIN {
		tb.analysisErr = fmt.Errorf("project kind %s has no binary analysis; use read_file / list_files instead", tb.Project.Kind)
		return nil, tb.analysisErr
	}
	if tb.Project.IsLocal() {
		raw, err := store.Blob(tb.Project.Sha256)
		if err != nil {
			tb.analysisErr = fmt.Errorf("local analysis missing for %s (was the store dir deleted?): %w — re-run /decompile", tb.Project.Sha256[:12], err)
			return nil, tb.analysisErr
		}
		tb.analysis, tb.analysisErr = api.ParseAnalysis(raw)
		return tb.analysis, tb.analysisErr
	}
	// Backend project: read-through disk cache keyed by project (+ sample) id.
	key := tb.cacheKey()
	if raw := store.RemoteBlob(key); raw != nil {
		if a, err := api.ParseAnalysis(raw); err == nil {
			tb.analysis = a
			return tb.analysis, nil
		}
		store.DropRemote(key) // corrupt/stale cache — refetch below
	}
	var raw []byte
	var err error
	if tb.sample != nil {
		raw, err = tb.API.SampleAnalysisRaw(tb.Project.ID, tb.sample)
	} else {
		raw, err = tb.API.BinaryAnalysisRaw(tb.Project)
	}
	if err != nil {
		tb.analysisErr = err
		return nil, err
	}
	tb.analysis, tb.analysisErr = api.ParseAnalysis(raw)
	if tb.analysisErr == nil {
		store.SaveRemote(key, raw)
	}
	return tb.analysis, tb.analysisErr
}

// ResolveSample picks a sample from a list by 1-based index, id, or
// case-insensitive label / filename (exact first, then unique prefix /
// substring). "primary" / "main" / "0" resolve to nil = the project's own
// binary. Shared by the switch_sample tool and the /switch command.
func ResolveSample(samples []api.Sample, query string) (*api.Sample, error) {
	q := strings.TrimSpace(query)
	switch strings.ToLower(q) {
	case "", "primary", "main", "0":
		return nil, nil
	}
	if n, err := strconv.Atoi(q); err == nil {
		if n < 1 || n > len(samples) {
			return nil, fmt.Errorf("sample #%d doesn't exist (project has %d extra sample(s))", n, len(samples))
		}
		return &samples[n-1], nil
	}
	lq := strings.ToLower(q)
	for i := range samples {
		s := &samples[i]
		if s.ID == q || strings.EqualFold(s.Label, q) || strings.EqualFold(s.OriginalFilename, q) || s.Sha256 == lq {
			return s, nil
		}
	}
	var hits []*api.Sample
	for i := range samples {
		s := &samples[i]
		if strings.Contains(strings.ToLower(s.Label), lq) || strings.Contains(strings.ToLower(s.OriginalFilename), lq) ||
			strings.HasPrefix(s.ID, lq) || strings.HasPrefix(s.Sha256, lq) {
			hits = append(hits, s)
		}
	}
	switch len(hits) {
	case 0:
		return nil, fmt.Errorf("no sample matches %q — use list_samples and pick by number or label", q)
	case 1:
		return hits[0], nil
	}
	names := make([]string, len(hits))
	for i, h := range hits {
		names[i] = h.DisplayName()
	}
	return nil, fmt.Errorf("%q is ambiguous (%s) — pick by number", q, strings.Join(names, ", "))
}

// Analysis exposes the currently-loaded analysis (nil if not loaded/errored) —
// used by decompile_sample to summarize a hot-swapped result.
func (tb *Toolbox) Analysis() (*api.Analysis, error) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.analysis, tb.analysisErr
}

// SetAnalysisRaw hot-swaps the toolbox's analysis with a freshly-produced blob
// (a local re-decompile via decompile_sample) so every read tool sees the new
// result immediately, mid-session.
func (tb *Toolbox) SetAnalysisRaw(raw []byte) error {
	a, err := api.ParseAnalysis(raw)
	if err != nil {
		return err
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.analysis, tb.analysisErr, tb.analysisLoaded = a, nil, true
	return nil
}

// RegisterRead adds the Navigate/Read toolset to a registry. The set depends
// on the project kind: a BIN project reads the Ghidra analysis blob; APK and
// script projects have no blob, so offering get_strings / get_imports / xrefs
// there only invites calls that fail — they get the source-tree tools instead.
func (tb *Toolbox) RegisterRead(reg *Registry) {
	reg.Add(tb.getMetadataTool())
	if tb.Project.Kind != api.KindBIN {
		reg.Add(tb.listFilesTool())
		reg.Add(tb.readFileTool())
		reg.Add(tb.codeSearchTool())
		if tb.Project.Kind == api.KindAPK {
			reg.Add(tb.getManifestTool())
			reg.Add(tb.findDefinitionTool())
			reg.Add(tb.findUsagesTool())
		}
		return
	}
	reg.Add(tb.listFunctionsTool())
	reg.Add(tb.getFunctionTool())
	reg.Add(tb.getStringsTool())
	reg.Add(tb.getImportsTool())
	reg.Add(tb.getExportsTool())
	reg.Add(tb.getDataSymbolsTool())
	reg.Add(tb.readDataTool())
	reg.Add(tb.xrefsTool())
	reg.Add(tb.reachabilityTool())
	reg.Add(tb.searchTool())
	reg.Add(tb.listFilesTool())
	reg.Add(tb.readFileTool())
}

func (tb *Toolbox) getMetadataTool() *Tool {
	return &Tool{
		Def: Def("get_metadata",
			"Get sample metadata: format, architecture/language, image base, section (memory block) layout, and counts of functions/strings/imports/exports. Call this first to orient.",
			Obj(map[string]any{})),
		Handler: func(_ context.Context, _ json.RawMessage) (string, error) {
			p := tb.Project
			var b strings.Builder
			fmt.Fprintf(&b, "Project: %s (kind=%s, status=%s)\n", p.Name, p.Kind, p.Status)
			if s := tb.ActiveSample(); s != nil {
				fmt.Fprintf(&b, "ACTIVE SAMPLE: %s (extra sample of this project; sha256 %s) — all read tools serve THIS binary. switch_sample to change.\n", s.DisplayName(), s.Sha256)
			} else if p.Sha256 != "" {
				fmt.Fprintf(&b, "sha256: %s\n", p.Sha256)
			}
			if p.Kind == api.KindAPK {
				b.WriteString("format: Android APK (decompiled to Java source)\n")
				tb.apkMetadata(&b)
				return b.String(), nil
			}
			if p.Kind != api.KindBIN {
				fmt.Fprintf(&b, "format: %s package\n", p.Kind)
				if p.PackageName != "" {
					fmt.Fprintf(&b, "package: %s\n", p.PackageName)
				}
				b.WriteString("(no binary-analysis blob for this kind — use list_files / read_file / search)\n")
				return b.String(), nil
			}
			a, err := tb.analysisBlob()
			if err != nil {
				return "", err
			}
			m := a.Metadata
			fmt.Fprintf(&b, "format: %s\narch/language: %s\ncompiler: %s\nimage base: %s\n",
				orNA(m.ExecutableFormat), orNA(m.Language), orNA(m.Compiler), orNA(m.ImageBase))
			fmt.Fprintf(&b, "counts: %d functions, %d strings, %d imports, %d exports, %d data symbols\n",
				m.FunctionCount, m.StringCount, m.ImportCount, m.ExportCount, m.DataSymbolCount)
			if len(a.MemoryBlocks) > 0 {
				b.WriteString("sections (memory blocks):\n")
				for _, mb := range a.MemoryBlocks {
					fmt.Fprintf(&b, "  %-16s %s-%s  perms=%s  size=%d%s\n",
						mb.Name, mb.Start, mb.End, mb.Permissions, mb.Size, execTag(mb.Executable))
				}
			}
			if len(a.EntryPoints) > 0 {
				b.WriteString("entry points: ")
				b.WriteString(joinSymbols(a.EntryPoints))
				b.WriteByte('\n')
			}
			return b.String(), nil
		},
	}
}

func (tb *Toolbox) listFunctionsTool() *Tool {
	return &Tool{
		Def: Def("list_functions",
			"List functions in the binary. Optional case-insensitive substring `filter` on the function name. Returns name, address, and size; external/thunk functions are marked.",
			Obj(map[string]any{"filter": StrProp("case-insensitive substring to match on the function name")})),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct{ Filter string }
			_ = json.Unmarshal(input, &args)
			a, err := tb.analysisBlob()
			if err != nil {
				return "", err
			}
			filter := strings.ToLower(args.Filter)
			var rows []string
			total := 0
			for _, f := range a.Functions {
				if filter != "" && !strings.Contains(strings.ToLower(f.Name), filter) {
					continue
				}
				total++
				if len(rows) >= maxListItems {
					continue
				}
				tag := ""
				switch {
				case f.External:
					tag = " [external]"
				case f.Thunk:
					tag = " [thunk]"
				case f.BodySkipped:
					tag = " [body-skipped]"
				}
				rows = append(rows, fmt.Sprintf("%-40s %s size=%d%s", f.Name, f.Address, f.Size, tag))
			}
			if total == 0 {
				return "no functions match", nil
			}
			out := strings.Join(rows, "\n")
			if total > len(rows) {
				out += fmt.Sprintf("\n… %d more (narrow with filter)", total-len(rows))
			}
			return out, nil
		},
	}
}

func (tb *Toolbox) getFunctionTool() *Tool {
	return &Tool{
		Def: Def("get_function",
			"Get a function's decompiled C pseudocode, signature, and call graph (callers/callees). Identify it by `name` or by `address` (e.g. 0x401000). Decompiled output is truncated if very long.",
			Obj(map[string]any{
				"name":    StrProp("exact function name"),
				"address": StrProp("function address, e.g. 0x401000"),
			})),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct{ Name, Address string }
			_ = json.Unmarshal(input, &args)
			if args.Name == "" && args.Address == "" {
				return "", fmt.Errorf("provide name or address")
			}
			a, err := tb.analysisBlob()
			if err != nil {
				return "", err
			}
			f := findFunction(a, args.Name, args.Address)
			if f == nil {
				return fmt.Sprintf("function not found (name=%q address=%q)", args.Name, args.Address), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "%s @ %s (size=%d)\n", f.Name, f.Address, f.Size)
			if f.Signature != "" {
				fmt.Fprintf(&b, "signature: %s\n", f.Signature)
			}
			if len(f.Xrefs.Callers) > 0 {
				fmt.Fprintf(&b, "callers: %s\n", strings.Join(capStrings(f.Xrefs.Callers, 30), ", "))
			}
			if len(f.Xrefs.Callees) > 0 {
				fmt.Fprintf(&b, "callees: %s\n", strings.Join(capStrings(f.Xrefs.Callees, 30), ", "))
			}
			switch {
			case f.External:
				b.WriteString("(external function — no body)\n")
			case f.Thunk:
				b.WriteString("(thunk — no body)\n")
			case f.BodySkipped:
				b.WriteString("(body skipped by the decompiler's budget — no pseudocode)\n")
			case f.Decompiled == "":
				b.WriteString("(no decompiled output)\n")
			default:
				b.WriteString("\n--- decompiled ---\n")
				b.WriteString(truncate(f.Decompiled, maxDecompChars))
			}
			return b.String(), nil
		},
	}
}

func (tb *Toolbox) getStringsTool() *Tool {
	return &Tool{
		Def: Def("get_strings",
			"List printable strings extracted from the binary. Optional case-insensitive substring `filter`. Useful for URLs, paths, ransom notes, commands, keys.",
			Obj(map[string]any{"filter": StrProp("case-insensitive substring to match")})),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct{ Filter string }
			_ = json.Unmarshal(input, &args)
			a, err := tb.analysisBlob()
			if err != nil {
				return "", err
			}
			return filterList(a.Strings, args.Filter, maxListItems), nil
		},
	}
}

func (tb *Toolbox) getImportsTool() *Tool {
	return &Tool{
		Def: Def("get_imports",
			"List imported symbols (external functions/APIs the binary calls). Optional substring `filter`.",
			Obj(map[string]any{"filter": StrProp("case-insensitive substring to match")})),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct{ Filter string }
			_ = json.Unmarshal(input, &args)
			a, err := tb.analysisBlob()
			if err != nil {
				return "", err
			}
			return filterList(a.Imports, args.Filter, maxListItems), nil
		},
	}
}

func (tb *Toolbox) getExportsTool() *Tool {
	return &Tool{
		Def: Def("get_exports",
			"List exported symbols (functions the binary exposes). Returns name + address.",
			Obj(map[string]any{})),
		Handler: func(_ context.Context, _ json.RawMessage) (string, error) {
			a, err := tb.analysisBlob()
			if err != nil {
				return "", err
			}
			if len(a.Exports) == 0 {
				return "no exports", nil
			}
			return joinSymbols(a.Exports), nil
		},
	}
}

func (tb *Toolbox) getDataSymbolsTool() *Tool {
	return &Tool{
		Def: Def("get_data_symbols",
			"List data-section symbols (globals, config blobs, tables). Returns name, address, type, size, and a short bytes preview. Optional substring `filter`. Use to locate embedded/encrypted config blobs — then read_data <name> to see one global's full captured bytes (small secrets are recoverable straight from analysis).",
			Obj(map[string]any{"filter": StrProp("case-insensitive substring to match on the symbol name")})),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct{ Filter string }
			_ = json.Unmarshal(input, &args)
			a, err := tb.analysisBlob()
			if err != nil {
				return "", err
			}
			filter := strings.ToLower(args.Filter)
			var rows []string
			total := 0
			for _, d := range a.DataSymbols {
				if filter != "" && !strings.Contains(strings.ToLower(d.Name), filter) {
					continue
				}
				total++
				if len(rows) >= maxListItems {
					continue
				}
				preview := d.BytesPreview
				if preview == "" {
					preview = d.Value
				}
				rows = append(rows, fmt.Sprintf("%-32s %s type=%s size=%d refs=%d  %s",
					d.Name, d.Address, orNA(d.Type), d.Size, d.RefCount, truncate(preview, 80)))
			}
			if total == 0 {
				return "no data symbols match", nil
			}
			out := strings.Join(rows, "\n")
			if total > len(rows) {
				out += fmt.Sprintf("\n… %d more (narrow with filter)", total-len(rows))
			}
			return out, nil
		},
	}
}

func (tb *Toolbox) readDataTool() *Tool {
	return &Tool{
		Def: Def("read_data",
			"Read one data-section global's captured bytes as full hex + an ASCII decode. Identify it by `name` (e.g. DAT_004c1234) or `address`. Use this to recover an embedded secret — a hardcoded C2 host/IP, a key, an XOR/RC4 table, a config struct — straight from the analysis, no raw sample needed. Analysis captures a bounded preview per global; if this reports the symbol is larger than what was captured, attach the raw binary with /sample to recover the rest.",
			Obj(map[string]any{
				"name":    StrProp("data symbol name, e.g. DAT_004c1234 or g_config"),
				"address": StrProp("data symbol address, e.g. 0x4c1234"),
			})),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct{ Name, Address string }
			if err := json.Unmarshal(input, &args); err != nil {
				return "", err
			}
			if args.Name == "" && args.Address == "" {
				return "", fmt.Errorf("provide name or address")
			}
			a, err := tb.analysisBlob()
			if err != nil {
				return "", err
			}
			d := findDataSymbol(a, args.Name, args.Address)
			if d == nil {
				return fmt.Sprintf("data symbol not found (name=%q address=%q) — list them with get_data_symbols", args.Name, args.Address), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "%s @ %s  type=%s size=%d refs=%d\n", d.Name, d.Address, orNA(d.Type), d.Size, d.RefCount)
			preview := d.BytesPreview
			if preview == "" {
				preview = d.Value
			}
			if strings.TrimSpace(preview) == "" {
				b.WriteString("(no bytes captured — likely uninitialized .bss; only exists at runtime)\n")
				return b.String(), nil
			}
			raw := decodeHexPreview(preview)
			if len(raw) > 0 {
				fmt.Fprintf(&b, "hex (%d bytes):\n%s\n", len(raw), hexDump(raw))
			} else {
				fmt.Fprintf(&b, "value: %s\n", preview)
			}
			// Truncation is judged from the DATA (captured vs declared size), not
			// a fixed cap — so this is correct whether the analysis came from the
			// old 64-byte worker or the new higher-cap one.
			if d.Size > len(raw) && len(raw) > 0 {
				fmt.Fprintf(&b, "NOTE: symbol is %d bytes but analysis captured only the first %d. To recover the rest (e.g. a full encrypted config), attach the raw binary with /sample and extract.\n", d.Size, len(raw))
			}
			return b.String(), nil
		},
	}
}

func findDataSymbol(a *api.Analysis, name, address string) *api.DataSymbol {
	for i := range a.DataSymbols {
		d := &a.DataSymbols[i]
		if name != "" && d.Name == name {
			return d
		}
		if address != "" && sameAddr(d.Address, address) {
			return d
		}
	}
	return nil
}

// decodeHexPreview parses the worker's "aa bb cc ..." hex-pair preview into raw
// bytes. A trailing "..." (more-bytes marker) is ignored.
func decodeHexPreview(s string) []byte {
	var out []byte
	for _, tok := range strings.Fields(s) {
		if len(tok) != 2 {
			continue // skip "..." and any stray token
		}
		v, err := strconv.ParseUint(tok, 16, 8)
		if err != nil {
			continue
		}
		out = append(out, byte(v))
	}
	return out
}

// hexDump renders bytes as a classic offset | hex | ASCII dump.
func hexDump(data []byte) string {
	var b strings.Builder
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprintf(&b, "%04x  ", i)
		for j := i; j < i+16; j++ {
			if j < end {
				fmt.Fprintf(&b, "%02x ", data[j])
			} else {
				b.WriteString("   ")
			}
		}
		b.WriteString(" ")
		for j := i; j < end; j++ {
			if data[j] >= 0x20 && data[j] <= 0x7e {
				b.WriteByte(data[j])
			} else {
				b.WriteByte('.')
			}
		}
		if end < len(data) {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func (tb *Toolbox) xrefsTool() *Tool {
	return &Tool{
		Def: Def("xrefs",
			"Show the callers and callees of a function (cross-references). Identify the function by `symbol` (its name).",
			Obj(map[string]any{"symbol": StrProp("function name")}, "symbol")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct{ Symbol string }
			_ = json.Unmarshal(input, &args)
			if args.Symbol == "" {
				return "", fmt.Errorf("provide symbol")
			}
			a, err := tb.analysisBlob()
			if err != nil {
				return "", err
			}
			f := findFunction(a, args.Symbol, "")
			if f == nil {
				return fmt.Sprintf("function %q not found", args.Symbol), nil
			}
			return fmt.Sprintf("%s\ncallers (%d): %s\ncallees (%d): %s",
				f.Name,
				len(f.Xrefs.Callers), strings.Join(capStrings(f.Xrefs.Callers, 50), ", "),
				len(f.Xrefs.Callees), strings.Join(capStrings(f.Xrefs.Callees, 50), ", ")), nil
		},
	}
}

// reachabilityTool answers the central exploitability question — is this sink
// reachable from an attacker-controllable source? — by reverse-walking the
// static call graph. It's the vuln-mode complement to xrefs (one hop) and
// get_function (one function).
func (tb *Toolbox) reachabilityTool() *Tool {
	return &Tool{
		Def: Def("reachability",
			"VULN RESEARCH: determine whether a SINK function is reachable from an attacker-controllable SOURCE via the call graph — the core of an exploitability assessment. Reverse-walks callers from `sink`. Sources default to the binary's exports + entry points (the externally-reachable surface); override with `sources`. Returns whether a path exists and the shortest source→sink call path. BIN projects only.",
			Obj(map[string]any{
				"sink":      StrProp("the dangerous/target function — name or address (e.g. a memcpy wrapper, a parser, a command exec)"),
				"sources":   ArrProp("optional source function names to test reachability from; default = all exports + entry points + TLS callbacks"),
				"max_depth": map[string]any{"type": "integer", "description": "max call-graph depth to search (default 15)"},
			}, "sink")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct {
				Sink     string   `json:"sink"`
				Sources  []string `json:"sources"`
				MaxDepth int      `json:"max_depth"`
			}
			_ = json.Unmarshal(input, &args)
			if strings.TrimSpace(args.Sink) == "" {
				return "", fmt.Errorf("provide sink")
			}
			a, err := tb.analysisBlob()
			if err != nil {
				return "", err
			}
			return traceReachability(a, args.Sink, args.Sources, args.MaxDepth), nil
		},
	}
}

// traceReachability reverse-BFSs the call graph from sink toward attacker
// sources, returning the shortest source→sink path if one exists. The BFS order
// guarantees the first source reached is via a shortest path.
func traceReachability(a *api.Analysis, sinkID string, sources []string, maxDepth int) string {
	if maxDepth <= 0 {
		maxDepth = 15
	}
	sink := findFunction(a, sinkID, sinkID) // resolve by name or address
	if sink == nil {
		return fmt.Sprintf("sink %q not found (try list_functions or search to find the exact name)", sinkID)
	}
	byName := make(map[string]*api.Function, len(a.Functions))
	for i := range a.Functions {
		byName[a.Functions[i].Name] = &a.Functions[i]
	}
	srcSet := map[string]bool{}
	if len(sources) > 0 {
		for _, s := range sources {
			srcSet[s] = true
		}
	} else {
		for _, e := range a.Exports {
			srcSet[e.Name] = true
		}
		for _, e := range a.EntryPoints {
			srcSet[e.Name] = true
		}
		for _, e := range a.TLSCallbacks {
			srcSet[e.Name] = true
		}
	}
	if srcSet[sink.Name] {
		return fmt.Sprintf("REACHABLE: %s is itself a source (exported / entry point) — directly attacker-reachable.", sink.Name)
	}

	visited := map[string]bool{sink.Name: true}
	parent := map[string]string{}
	type node struct {
		name  string
		depth int
	}
	queue := []node{{sink.Name, 0}}
	var reached []string
	rootSeen := map[string]bool{}
	var roots []string
	for len(queue) > 0 && len(reached) < 5 {
		cur := queue[0]
		queue = queue[1:]
		if cur.depth >= maxDepth {
			continue
		}
		f := byName[cur.name]
		if f == nil {
			continue // caller name with no resolved body (e.g. an import)
		}
		if len(f.Xrefs.Callers) == 0 && cur.name != sink.Name && !srcSet[cur.name] && !rootSeen[cur.name] {
			rootSeen[cur.name] = true
			roots = append(roots, cur.name)
		}
		for _, caller := range f.Xrefs.Callers {
			if visited[caller] {
				continue
			}
			visited[caller] = true
			parent[caller] = cur.name
			if srcSet[caller] {
				reached = append(reached, caller)
			}
			queue = append(queue, node{caller, cur.depth + 1})
		}
	}

	if len(reached) == 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "NOT reachable from any source within depth %d (searched %d functions).", maxDepth, len(visited))
		if len(roots) > 0 {
			fmt.Fprintf(&b, "\nNearest call-graph roots (no recorded callers, not sources): %s", strings.Join(capStrings(roots, 15), ", "))
		}
		b.WriteString("\nNote: indirect/virtual calls (vtables, function pointers, dlsym/GetProcAddress) are NOT in the static call graph, so this may UNDER-approximate — 'not reachable' is not proof of safety.")
		return b.String()
	}

	// Reconstruct the shortest path (source → … → sink) from the first source hit.
	var path []string
	for n := reached[0]; ; {
		path = append(path, n)
		p, ok := parent[n]
		if !ok {
			break
		}
		n = p
	}
	var b strings.Builder
	fmt.Fprintf(&b, "REACHABLE from %d source(s): %s\n", len(reached), strings.Join(capStrings(reached, 10), ", "))
	fmt.Fprintf(&b, "Shortest path: %s\n", strings.Join(path, " → "))
	b.WriteString("This establishes the sink is attacker-reachable. Before asserting exploitability, confirm the source actually passes untrusted, attacker-controlled data along this path (read the functions on it).")
	return b.String()
}

func (tb *Toolbox) searchTool() *Tool {
	return &Tool{
		Def: Def("search",
			"Search decompiled code and strings with a regular expression (Go/RE2 syntax). Returns matching functions (by name) and matching strings. Use for patterns like crypto constants, C2 URLs, suspicious API sequences.",
			Obj(map[string]any{"regex": StrProp("RE2 regular expression")}, "regex")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct{ Regex string }
			_ = json.Unmarshal(input, &args)
			if args.Regex == "" {
				return "", fmt.Errorf("provide regex")
			}
			re, err := regexp.Compile(args.Regex)
			if err != nil {
				return "", fmt.Errorf("bad regex: %v", err)
			}
			a, err := tb.analysisBlob()
			if err != nil {
				return "", err
			}
			var hits []string
			for _, f := range a.Functions {
				if len(hits) >= maxSearchHits {
					break
				}
				if re.MatchString(f.Name) || (f.Decompiled != "" && re.MatchString(f.Decompiled)) {
					hits = append(hits, "fn: "+f.Name+" @ "+f.Address)
				}
			}
			for _, s := range a.Strings {
				if len(hits) >= maxSearchHits {
					break
				}
				if re.MatchString(s) {
					hits = append(hits, "str: "+truncate(s, 120))
				}
			}
			if len(hits) == 0 {
				return "no matches", nil
			}
			out := strings.Join(hits, "\n")
			if len(hits) >= maxSearchHits {
				out += "\n… (more hits truncated; refine the regex)"
			}
			return out, nil
		},
	}
}

func (tb *Toolbox) listFilesTool() *Tool {
	return &Tool{
		Def: Def("list_files",
			"List the project's file tree (for APK / script projects). Returns relative paths under `dir` (default: the root) whose path contains `filter`. A large tree comes back as per-subdirectory file counts — drill in with dir. Library/SDK code (androidx/, kotlin/, com/google/, …) is hidden unless include_sdks.",
			Obj(map[string]any{
				"dir":    StrProp("optional: directory to list, e.g. sources/com/evil/app"),
				"filter": StrProp("optional: case-insensitive substring the path must contain, e.g. Crypto or .xml"),
				"include_sdks": map[string]any{"type": "boolean",
					"description": "also list library/SDK packages (default false)"},
			})),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct {
				Dir         string `json:"dir"`
				Filter      string `json:"filter"`
				IncludeSdks bool   `json:"include_sdks"`
			}
			_ = json.Unmarshal(input, &args)
			root, err := tb.fileTree()
			if err != nil {
				return "", err
			}
			return listTree(root, args.Dir, args.Filter, args.IncludeSdks), nil
		},
	}
}

func (tb *Toolbox) readFileTool() *Tool {
	return &Tool{
		Def: Def("read_file",
			"Read a file's text content by relative `path` (for APK / script projects). Applied renames are substituted in. Pass start_line (e.g. a search/find_usages hit's line minus a few) to read a numbered window from there; a long file returns its first page with the start_line to continue from.",
			Obj(map[string]any{
				"path": StrProp("relative file path within the project"),
				"start_line": map[string]any{"type": "integer",
					"description": "optional: 1-based line to start reading from (output is line-numbered)"},
			}, "path")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var args struct {
				Path      string `json:"path"`
				StartLine int    `json:"start_line"`
			}
			_ = json.Unmarshal(input, &args)
			if args.Path == "" {
				return "", fmt.Errorf("provide path")
			}
			src, err := tb.source()
			if err != nil {
				return "", err
			}
			fc, err := src.File(args.Path)
			if err != nil {
				return "", err
			}
			if fc.Encoding == "binary" {
				return fmt.Sprintf("(binary file, %d bytes — not text)", fc.Size), nil
			}
			if args.StartLine <= 0 && len(fc.Content) <= maxFileChars {
				body := fc.Content
				if fc.Truncated {
					body += "\n… (truncated by the server)"
				}
				return body, nil
			}
			body, next := sliceLines(fc.Content, args.StartLine, maxFileChars)
			if next > 0 {
				body += fmt.Sprintf("… (more — read_file again with start_line=%d)", next)
			} else if fc.Truncated {
				body += "… (rest of file truncated by the server)"
			}
			return body, nil
		},
	}
}

// --- helpers --------------------------------------------------------------

func findFunction(a *api.Analysis, name, address string) *api.Function {
	for i := range a.Functions {
		f := &a.Functions[i]
		if name != "" && f.Name == name {
			return f
		}
		if address != "" && sameAddr(f.Address, address) {
			return f
		}
	}
	return nil
}

// sameAddr compares two addresses tolerating format drift: the model tends to
// pass "0x00400a86" while the analysis stores "00400a86". Compare numerically
// when both parse as hex (handles the 0x prefix and leading zeros); fall back to
// a normalized string compare otherwise.
func sameAddr(a, b string) bool {
	na, oka := parseAddr(a)
	nb, okb := parseAddr(b)
	if oka && okb {
		return na == nb
	}
	return normAddr(a) == normAddr(b)
}

func parseAddr(s string) (uint64, bool) {
	n := normAddr(s)
	if n == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(n, 16, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// normAddr strips a 0x/0X prefix, surrounding whitespace, and leading zeros, and
// lowercases — so "0x00400A86", "00400a86", and "400a86" all normalize alike.
func normAddr(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "0x")
	if t := strings.TrimLeft(s, "0"); t != "" {
		return t
	}
	return s // all-zero address stays as-is (don't collapse to empty)
}

func filterList(items []string, filter string, cap int) string {
	f := strings.ToLower(filter)
	var out []string
	total := 0
	for _, s := range items {
		if f != "" && !strings.Contains(strings.ToLower(s), f) {
			continue
		}
		total++
		if len(out) >= cap {
			continue
		}
		out = append(out, s)
	}
	if total == 0 {
		return "no matches"
	}
	res := strings.Join(out, "\n")
	if total > len(out) {
		res += fmt.Sprintf("\n… %d more (narrow with filter)", total-len(out))
	}
	return res
}

func joinSymbols(syms []api.Symbol) string {
	var out []string
	for _, s := range syms {
		if len(out) >= maxListItems {
			out = append(out, "…")
			break
		}
		out = append(out, fmt.Sprintf("%s@%s", s.Name, s.Address))
	}
	return strings.Join(out, ", ")
}

func capStrings(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	return append(items[:n:n], fmt.Sprintf("…+%d", len(items)-n))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func orNA(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}

func execTag(x bool) string {
	if x {
		return " [exec]"
	}
	return ""
}
