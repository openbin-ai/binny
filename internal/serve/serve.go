// Package serve is the HTTP backend for BINNY Desktop: the same engine the TUI
// drives, exposed over localhost so a web/Electron frontend can talk to it. It is
// started by `binny --serve`; the terminal TUI stays the default.
//
// Design (see docs/DESKTOP.md): one Go binary is the ENTIRE local backend — file
// serving from the local cache, the agent stream, local-model detection, and the
// Docker decompile workers. No cloud backend is required for a decompiled project
// that already lives on disk. This file is the scaffold: health, version, and
// live local-model detection. The file endpoints and the agent SSE stream land in
// later phases.
package serve

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"openbin.ai/binny/internal/llm"
)

// Options configures the local server.
type Options struct {
	Addr    string // listen address; defaults to 127.0.0.1:8899
	Version string // binny version, surfaced at /api/version
}

// Run starts the HTTP server and blocks until the context is cancelled or the
// server fails. It binds to loopback only — this is a personal, on-machine
// backend, never a shared service.
func Run(ctx context.Context, opts Options) error {
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:8899"
	}

	s := &server{version: opts.Version}
	srv := &http.Server{
		Addr:              opts.Addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Listen first so we can report the real address (and fail loudly on a busy
	// port) before announcing readiness.
	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return fmt.Errorf("binny --serve: cannot bind %s: %w", opts.Addr, err)
	}
	log.Printf("binny --serve listening on http://%s", ln.Addr())

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
	version string
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/version", s.handleVersion)
	mux.HandleFunc("/api/local-models", s.handleLocalModels)
	return withLocalCORS(mux)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": s.version})
}

// handleLocalModels probes the well-known local inference servers and returns the
// ones that are running, with their models. This is the "detect local LLMs like
// Open WebUI" feature — the picker populates from it, zero config.
func (s *server) handleLocalModels(w http.ResponseWriter, r *http.Request) {
	runtimes := llm.DetectLocal(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"runtimes": runtimes})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// withLocalCORS allows the dev frontend (Vite on another localhost port) to call
// the backend during development. Loopback-only, so this opens nothing to the
// network; the Electron build serves same-origin and won't need it.
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
