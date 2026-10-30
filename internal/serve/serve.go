// Package serve is the HTTP backend for BINNY Desktop: the same engine the TUI
// drives (and, for now, a direct provider chat), exposed over localhost so a
// web/Electron frontend can talk to it. Started by `binny --serve`; the terminal
// TUI stays the default.
//
// Design (docs/DESKTOP.md): one Go binary is the ENTIRE local backend — file
// serving from a decompiled tree on disk, a streaming chat, local-model
// detection, and (later) the full staged engine. This file hosts the MVP:
//
//   - GET  /                     the embedded chat-first web UI
//   - GET  /api/health           liveness
//   - GET  /api/version          binny version
//   - GET  /api/config           configured providers (no keys) for the picker
//   - GET  /api/local-models     detected local inference servers + models
//   - GET  /api/files            the decompiled tree (from --serve-dir)
//   - GET  /api/file?path=       one file's content
//   - POST /api/chat             streaming chat (SSE), local or configured model
//
// The full staged investigation engine (triage→…→review, structured findings,
// CVE reports) is the next phase; see DESKTOP.md §6.
package serve

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/llm"
	"openbin.ai/binny/internal/tools"
)

//go:embed web
var webFS embed.FS

// Options configures the local server.
type Options struct {
	Addr      string            // listen address; defaults to 127.0.0.1:8899
	Version   string            // binny version, surfaced at /api/version
	Dir       string            // decompiled tree to serve (optional)
	Providers []config.Provider // configured providers, for chat with cloud models
	Endpoints config.Endpoints  // backend + Keycloak URLs for connected mode
}

// Run starts the HTTP server and blocks until the context is cancelled or the
// server fails. It binds to loopback only — a personal, on-machine backend.
func Run(ctx context.Context, opts Options) error {
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:8899"
	}
	if opts.Dir != "" {
		abs, err := filepath.Abs(opts.Dir)
		if err != nil {
			return fmt.Errorf("binny --serve: bad --serve-dir: %w", err)
		}
		opts.Dir = abs
	}

	s := &server{opts: opts, curDir: opts.Dir, ep: opts.Endpoints}
	srv := &http.Server{
		Addr:              opts.Addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return fmt.Errorf("binny --serve: cannot bind %s: %w", opts.Addr, err)
	}
	log.Printf("BINNY Desktop backend on http://%s", ln.Addr())
	if opts.Dir != "" {
		log.Printf("serving decompiled tree: %s", opts.Dir)
	} else {
		log.Printf("no --serve-dir set: Explorer/Code panes will be empty")
	}
	log.Printf("open the UI in a browser at http://%s", ln.Addr())

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

type server struct {
	opts Options
	ep   config.Endpoints // backend + Keycloak URLs (connected mode)

	mu     sync.RWMutex
	curDir string          // the tree currently served; swappable via /api/decompile
	curPID string          // backend project id backing curDir, if any ("" = local)
	curReg *tools.Registry // binary-analysis tools when a BIN project is open (no tree)
}

// dir returns the tree currently being served (initially --serve-dir, later
// whatever a GUI decompile produced).
func (s *server) dir() string {
	s.mu.RLock()
	d := s.curDir
	s.mu.RUnlock()
	if d == "" {
		return s.opts.Dir // not yet swapped: the configured --serve-dir
	}
	return d
}

func (s *server) setDir(d string) {
	s.mu.Lock()
	s.curDir = d
	s.curPID = "" // a local tree (dropped APK / --serve-dir), not a cloud project
	s.curReg = nil
	s.mu.Unlock()
}

// setDirProject swaps the served tree to a cloud project's cached source and
// records which backend project backs it.
func (s *server) setDirProject(d, projectID string) {
	s.mu.Lock()
	s.curDir = d
	s.curPID = projectID
	s.curReg = nil
	s.mu.Unlock()
}

// setBinaryProject enters binary mode: no file tree (binaries have none), just
// the Ghidra-backed analysis tools the chat agent uses to answer about it.
func (s *server) setBinaryProject(projectID string, reg *tools.Registry) {
	s.mu.Lock()
	s.curDir = ""
	s.curPID = projectID
	s.curReg = reg
	s.mu.Unlock()
}

// projectID returns the backend project id backing what's open, if any.
func (s *server) projectID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.curPID
}

// reg returns the binary-analysis tool registry when a BIN project is open.
func (s *server) reg() *tools.Registry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.curReg
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()

	// The embedded UI, served from the web/ subtree.
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/local-models", s.handleLocalModels)
	mux.HandleFunc("/api/files", s.handleFiles)
	mux.HandleFunc("/api/file", s.handleFile)
	mux.HandleFunc("/api/decompile", s.handleDecompile)
	mux.HandleFunc("/api/analyze", s.handleAnalyze)
	mux.HandleFunc("/api/chat", s.handleChat)

	// Connected mode: log in to the openbin backend and open a cloud project.
	mux.HandleFunc("/api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("/api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("/api/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("/api/projects", s.handleProjects)
	mux.HandleFunc("/api/project/open", s.handleOpenProject)
	return withLocalCORS(mux)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "hasDir": s.dir() != "", "projectId": s.projectID(), "binary": s.reg() != nil})
}

func (s *server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.opts.Version})
}

// handleConfig lists configured providers WITHOUT keys, so the picker can offer
// cloud models alongside detected local ones.
func (s *server) handleConfig(w http.ResponseWriter, r *http.Request) {
	type prov struct {
		ID     string   `json:"id"`
		Kind   string   `json:"kind"`
		Models []string `json:"models"`
		Ready  bool     `json:"ready"`
	}
	out := make([]prov, 0, len(s.opts.Providers))
	for _, p := range s.opts.Providers {
		out = append(out, prov{ID: p.ID, Kind: string(p.Kind), Models: p.Models, Ready: p.HasKey()})
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": out})
}

func (s *server) handleLocalModels(w http.ResponseWriter, r *http.Request) {
	runtimes := llm.DetectLocal(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"runtimes": runtimes})
}

// --- file serving ---------------------------------------------------------

type fileNode struct {
	Name     string     `json:"name"`
	Path     string     `json:"path"`
	Type     string     `json:"type"` // "dir" | "file"
	Size     int64      `json:"size,omitempty"`
	Children []fileNode `json:"children,omitempty"`
}

const maxTreeFiles = 40000

func (s *server) handleFiles(w http.ResponseWriter, r *http.Request) {
	dir := s.dir()
	if dir == "" {
		writeJSON(w, http.StatusOK, map[string]any{"root": nil})
		return
	}
	root, err := buildTree(dir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"root": root})
}

func buildTree(rootDir string) (*fileNode, error) {
	type item struct {
		rel   string
		isDir bool
		size  int64
	}
	var items []item
	count := 0
	err := filepath.WalkDir(rootDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == rootDir {
			return err
		}
		if count++; count > maxTreeFiles {
			return fs.SkipAll
		}
		rel, _ := filepath.Rel(rootDir, p)
		it := item{rel: filepath.ToSlash(rel), isDir: d.IsDir()}
		if !d.IsDir() {
			if info, e := d.Info(); e == nil {
				it.size = info.Size()
			}
		}
		items = append(items, it)
		return nil
	})
	if err != nil {
		return nil, err
	}
	children := map[string][]item{}
	for _, it := range items {
		parent := ""
		if i := strings.LastIndexByte(it.rel, '/'); i >= 0 {
			parent = it.rel[:i]
		}
		children[parent] = append(children[parent], it)
	}
	var build func(rel, name string) fileNode
	build = func(rel, name string) fileNode {
		n := fileNode{Name: name, Path: rel, Type: "dir"}
		kids := children[rel]
		sort.Slice(kids, func(i, j int) bool {
			if kids[i].isDir != kids[j].isDir {
				return kids[i].isDir // dirs first
			}
			return kids[i].rel < kids[j].rel
		})
		for _, k := range kids {
			base := k.rel[strings.LastIndexByte(k.rel, '/')+1:]
			if k.isDir {
				n.Children = append(n.Children, build(k.rel, base))
			} else {
				n.Children = append(n.Children, fileNode{Name: base, Path: k.rel, Type: "file", Size: k.size})
			}
		}
		return n
	}
	root := build("", filepath.Base(rootDir))
	return &root, nil
}

const maxFileBytes = 4 << 20

func (s *server) handleFile(w http.ResponseWriter, r *http.Request) {
	dir := s.dir()
	if dir == "" {
		writeErr(w, http.StatusNotFound, "no tree is being served")
		return
	}
	rel := r.URL.Query().Get("path")
	abs, ok := safeJoin(dir, rel)
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid path")
		return
	}
	info, err := os.Stat(abs)
	if err != nil || info.IsDir() {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	f, err := os.Open(abs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":      rel,
		"content":   string(data),
		"truncated": info.Size() > maxFileBytes,
	})
}

// safeJoin resolves rel under root, rejecting path traversal and absolute paths.
func safeJoin(root, rel string) (string, bool) {
	if rel == "" {
		return "", false
	}
	clean := filepath.Clean("/" + filepath.FromSlash(rel)) // force under /
	abs := filepath.Join(root, clean)
	if abs != root && !strings.HasPrefix(abs, root+string(os.PathSeparator)) {
		return "", false
	}
	return abs, true
}

// --- chat (SSE) -----------------------------------------------------------

type chatRequest struct {
	ProviderID string `json:"providerId"` // a configured provider id (cloud); or
	BaseURL    string `json:"baseURL"`    // a local server base (keyless, OpenAI-compatible)
	Model      string `json:"model"`
	System     string `json:"system"`
	Messages   []struct {
		Role string `json:"role"` // "user" | "assistant"
		Text string `json:"text"`
	} `json:"messages"`
}

func (s *server) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req chatRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	prov, err := s.resolveProvider(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	provider, err := llm.New(prov)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "provider: "+err.Error())
		return
	}

	msgs := make([]llm.Message, 0, len(req.Messages))
	for _, m := range req.Messages {
		if strings.EqualFold(m.Role, "assistant") {
			msgs = append(msgs, llm.Message{Role: llm.RoleAssistant, Blocks: []llm.Block{llm.TextBlock(m.Text)}})
		} else {
			msgs = append(msgs, llm.UserText(m.Text))
		}
	}
	model := req.Model
	if model == "" {
		model = prov.Models[0]
	}

	// SSE stream.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	send := func(ev map[string]any) {
		b, _ := json.Marshal(ev)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}

	// With a served tree the model gets read-only tools and investigates on its
	// own (agent.go); without one it's a plain single-turn chat.
	s.runAgentLoop(r.Context(), provider, llm.Request{
		System:    req.System,
		Messages:  msgs,
		Tools:     s.agentTools(),
		Model:     model,
		MaxTokens: 2048,
	}, send)
}

// resolveProvider turns a chat request into a provider config: a local keyless
// server when BaseURL is set, otherwise a configured provider by id.
func (s *server) resolveProvider(req chatRequest) (config.Provider, error) {
	if req.BaseURL != "" {
		return config.Provider{
			ID:      "local",
			Kind:    config.KindOpenAI,
			BaseURL: req.BaseURL,
			Local:   true,
			Models:  []string{req.Model},
		}, nil
	}
	for _, p := range s.opts.Providers {
		if p.ID == req.ProviderID {
			if !p.HasKey() {
				return config.Provider{}, fmt.Errorf("provider %q has no key configured", req.ProviderID)
			}
			return p, nil
		}
	}
	return config.Provider{}, fmt.Errorf("pick a model: no local baseURL and unknown provider %q", req.ProviderID)
}

// --- helpers --------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// withLocalCORS allows the Vite dev frontend (another localhost port) to call the
// backend. Loopback-only, so this opens nothing to the network.
func withLocalCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
