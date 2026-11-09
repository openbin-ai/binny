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
//	POST /api/report/save   push {title, sections} to the open project's report

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
	if s.newClient != nil {
		return s.newClient()
	}
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
		s.setProjectName(p.Name)
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
		s.setBinaryProject(id, reg, tb)
		s.setProjectName(p.Name)
		send(map[string]any{"type": "ready", "kind": "BIN", "name": p.Name, "projectId": id, "summary": meta})

	default:
		// SCRIPT/zip projects have no browsable source via the client API (the
		// backend doesn't extract them into srcDir and source-bundle is APK-only),
		// so they can't be opened in the desktop yet.
		send(map[string]any{"type": "error", "error": fmt.Sprintf("%s projects can't be opened in the desktop yet", p.Kind)})
	}
}

// handleSaveReport is the desktop's /save: it PUTs the UI-assembled draft
// (title + sections) onto the open cloud project's report, exactly as the TUI's
// cmdSave does. Local trees have no backend report, so there's nothing to push.
func (s *server) handleSaveReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	pid := s.projectID()
	if pid == "" {
		writeErr(w, http.StatusConflict, "no cloud project open — only projects opened from your account have a report to save to")
		return
	}
	client, err := s.authClient()
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error(), "loggedIn": false})
		return
	}
	var req api.UpdateReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return
	}
	if len(req.Sections) == 0 {
		writeErr(w, http.StatusBadRequest, "no sections to save — record a finding first")
		return
	}
	rep, err := pushReport(client, pid, req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"projectId": pid, "reportId": rep.ID, "saved": len(req.Sections)})
}

// pushReport PUTs a draft onto a project's report. Shared by the Save button
// route and the agent's save_report tool so both push exactly the same thing.
func pushReport(client *api.Client, pid string, req api.UpdateReportRequest) (*api.Report, error) {
	if req.Title == "" {
		req.Title = "BINNY draft"
	}
	return client.UpdateReport(pid, req)
}

// chatContext is appended to every chat's system prompt so the agent knows it
// is part of OpenBIN and whether the analyst's account/project is reachable.
// Without it the model (correctly, given what it was told) insisted it was an
// offline tool that "can't reach openbin" when asked to push the report.
func (s *server) chatContext() string {
	const who = "CONTEXT: You are BINNY, the reverse-engineering assistant of OpenBIN, a defensive security-research platform used by professional malware analysts and reverse engineers. You run on the analyst's machine inside the BINNY desktop app; the analyst can sign in to their OpenBIN account and open their projects here."
	pid := s.projectID()
	if pid == "" {
		return who + " RIGHT NOW the open target is a local analysis, not a project from their OpenBIN account, so there is no OpenBIN report to push to. If the analyst asks to push, save, upload or sync the report or findings to OpenBIN, their project or their account, tell them to sign in and open the project from the Cloud button (top-right), after which you will be able to push it; meanwhile the Report panel offers Download/Copy."
	}
	name := s.projectName()
	if name == "" {
		name = pid
	}
	return who + fmt.Sprintf(" RIGHT NOW the analyst is signed in and has their OpenBIN project %q open from their account. When they ask to push, save, upload, sync or publish the report or findings to OpenBIN, their project or their account, call the save_report tool: it pushes the current draft report (every recorded finding, rendered as sections, plus an executive summary you write) to that project's report on OpenBIN as a DRAFT they review on the web app. You CAN reach OpenBIN for this — never say you can't.", name)
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
