package serve

// Connected mode: the desktop isn't local-only. A user logs in to the openbin
// backend (browser device flow, no terminal needed) and opens one of their
// existing cloud projects — we download its decompiled source into the local
// cache and swap the served tree to it, so every existing file/chat/finding
// route works against a cloud project exactly as it does for a dropped APK.
//
//	GET  /api/auth/status   who's logged in (refreshes a stale session)
//	POST /api/auth/login    SSE device flow: {code …} then {done, account} | {error}
//	POST /api/auth/logout   forget stored credentials
//	GET  /api/projects      the user's backend projects (openable = APK + ready)
//	POST /api/project/open  SSE: fetch → download source → swap tree → {ready, root}

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/auth"
	"openbin.ai/binny/internal/store"
	"openbin.ai/binny/internal/tools"
)

// authClient builds an authed backend client from the stored credentials. The
// error (not logged in) is surfaced to the UI as a prompt to sign in. A fresh
// client per request keeps login state current without caching invalidation.
func (s *server) authClient() (*api.Client, error) {
	toks, err := auth.NewTokenSource(s.ep)
	if err != nil {
		return nil, err
	}
	return api.New(s.ep, toks), nil
}

func (s *server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	acct, err := auth.Status(s.ep)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, acct)
}

// handleAuthLogin runs the OAuth device flow over SSE: it emits a {code} event
// with the verification URL + user code for the UI to open, then blocks polling
// until the user confirms in the browser, emitting {done} or {error}.
func (s *server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	send, ok := sseSender(w)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	dl, err := auth.StartDeviceLogin(s.ep)
	if err != nil {
		send(map[string]any{"type": "error", "error": err.Error()})
		return
	}
	send(map[string]any{
		"type":                      "code",
		"user_code":                 dl.UserCode,
		"verification_uri":          dl.VerificationURI,
		"verification_uri_complete": dl.VerificationURIComplete,
		"expires_in":                dl.ExpiresIn,
	})
	acct, err := dl.Poll(r.Context(), s.ep)
	if err != nil {
		send(map[string]any{"type": "error", "error": err.Error()})
		return
	}
	send(map[string]any{"type": "done", "account": acct})
}

func (s *server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	if err := auth.Logout(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"loggedIn": false})
}

func (s *server) handleProjects(w http.ResponseWriter, r *http.Request) {
	client, err := s.authClient()
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error(), "loggedIn": false})
		return
	}
	projects, err := client.ListProjects()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	type proj struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Kind        string `json:"kind"`
		Status      string `json:"status"`
		Ready       bool   `json:"ready"`
		Openable    bool   `json:"openable"` // APK + ready + cloud: has a browsable source tree
		PackageName string `json:"packageName,omitempty"`
		Role        string `json:"role,omitempty"`
		CreatedAt   string `json:"createdAt,omitempty"`
	}
	out := make([]proj, 0, len(projects))
	for _, p := range projects {
		out = append(out, proj{
			ID: p.ID, Name: p.Name, Kind: string(p.Kind), Status: p.Status,
			Ready:       p.Ready(),
			Openable:    (p.Kind == api.KindAPK || p.Kind == api.KindBIN) && p.Ready() && !p.IsLocal(),
			PackageName: p.PackageName, Role: p.Role, CreatedAt: p.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": out})
}

// handleOpenProject downloads a cloud project's decompiled source into the local
// cache (the same cached-remote-source path the TUI uses) and swaps the served
// tree to it — mirroring handleDecompile, but sourced from the backend.
func (s *server) handleOpenProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing project id")
		return
	}
	client, err := s.authClient()
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	send, ok := sseSender(w)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	logf := func(format string, args ...any) {
		send(map[string]any{"type": "progress", "text": fmt.Sprintf(format, args...)})
	}

	send(map[string]any{"type": "progress", "text": "Fetching project…"})
	p, err := client.GetProject(id)
	if err != nil {
		send(map[string]any{"type": "error", "error": err.Error()})
		return
	}
	if !p.Ready() {
		send(map[string]any{"type": "error", "error": fmt.Sprintf("project isn't ready to open yet (status %s)", p.Status)})
		return
	}

	switch p.Kind {
	case api.KindAPK:
		// APK: download the decompiled source tree and serve it (browsable).
		send(map[string]any{"type": "progress", "text": "Downloading decompiled source…"})
		if err := tools.PrefetchSourceTree(client, id, logf); err != nil {
			send(map[string]any{"type": "error", "error": err.Error()})
			return
		}
		dir, err := store.RemoteTreeDir(id)
		if err != nil {
			send(map[string]any{"type": "error", "error": err.Error()})
			return
		}
		src := filepath.Join(dir, "src")
		s.setDirProject(src, id)
		root, err := buildTree(src)
		if err != nil {
			send(map[string]any{"type": "error", "error": err.Error()})
			return
		}
		send(map[string]any{"type": "ready", "kind": "APK", "root": root, "package": p.PackageName, "name": p.Name, "projectId": id})

	case api.KindBIN:
		// Binary: no source tree — give the chat agent the Ghidra-backed tools
		// over the analysis blob (fetched + cached by the toolbox on first use).
		send(map[string]any{"type": "progress", "text": "Loading binary analysis…"})
		reg := tools.NewRegistry()
		tb := tools.NewToolbox(client, p)
		tb.RegisterRead(reg)
		meta, isErr := reg.Run(r.Context(), "get_metadata", json.RawMessage(`{}`)) // forces the blob load
		if isErr {
			send(map[string]any{"type": "error", "error": meta})
			return
		}
		s.setBinaryProject(id, reg)
		send(map[string]any{"type": "ready", "kind": "BIN", "name": p.Name, "projectId": id, "summary": meta})

	default:
		send(map[string]any{"type": "error", "error": fmt.Sprintf("%s projects can't be opened in the desktop yet — only APK and binary projects", p.Kind)})
	}
}

// sseSender sets SSE headers and returns a JSON event writer, or ok=false when
// the ResponseWriter can't stream. Shared by the login + open-project flows.
func sseSender(w http.ResponseWriter) (func(map[string]any), bool) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, false
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	return func(ev map[string]any) {
		b, _ := json.Marshal(ev)
		fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}, true
}
