package serve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"openbin.ai/binny/internal/agent"
	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/experience"
	"openbin.ai/binny/internal/llm"
	"openbin.ai/binny/internal/mission"
	"openbin.ai/binny/internal/tools"
)

// Crew missions in BINNY Desktop. The chat stays a chat; a mission is a run
// the server drives: BINNY triages, each crew step runs the same agent loop
// as the chat with a role's prompt and tools in a fresh context, Parity
// verifies, BINNY writes the report. Go code picks who goes next — the model
// never does (unless the mission lets the captain add steps).
//
// The stream is the chat's SSE vocabulary plus:
//
//	{type:mission_start,runId,name,steps:[…]}   the track to draw
//	{type:step_start,step,agent,name,tasking}   a crew member goes out
//	{type:step_skip,step,agent,reason}          a step that couldn't run
//	{type:step_debrief,step,agent,text,…}       …and reports back
//	{type:verdict,id,verdict,severity,reason}   Parity ruled on a finding
//	{type:mission_plan,steps:[…]}               the captain added steps
//	{type:checkpoint,runId,after,next}          paused for the analyst
//	{type:mission_done,runId,verification,…}    report written
//
// and every tool_call / tool_result / chunk / status / finding / usage event
// a crew member causes carries `agent` and `step`, so the UI can file it
// under that member's card instead of interleaving agents line by line.

const (
	missionStepIters   = 12     // provider round-trips a crew step gets
	missionTriageIters = 8      // …and BINNY's triage
	missionMinShare    = 15_000 // a step's token share never drops below this
	missionMaxAdded    = 3      // steps the captain may add
	maxMissionRuns     = 8      // paused runs remembered
)

// --- crew / missions / experience (JSON) -----------------------------------

func (s *server) handleCrew(w http.ResponseWriter, r *http.Request) {
	type roleDTO struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Title   string   `json:"title"`
		Avatar  string   `json:"avatar"`
		Accent  string   `json:"accent"`
		Owns    []string `json:"owns,omitempty"`
		Task    string   `json:"defaultTask,omitempty"`
		Kinds   []string `json:"kinds,omitempty"`
		Sandbox bool     `json:"needsSample,omitempty"`
	}
	var out []roleDTO
	for _, ro := range agent.Lineup() {
		d := roleDTO{ID: ro.ID, Name: ro.Name, Title: ro.Title, Avatar: ro.Avatar, Accent: ro.Accent,
			Owns: ro.Owns, Task: ro.DefaultTask, Sandbox: ro.NeedsSandbox}
		for _, k := range ro.Kinds {
			d.Kinds = append(d.Kinds, string(k))
		}
		// A crew member whose art hasn't shipped falls back to an initial.
		if _, err := webFS.Open("web/" + ro.Avatar); err != nil {
			d.Avatar = ""
		}
		out = append(out, d)
	}
	kind := s.targetKind()
	objs, _ := agent.DefaultObjectives(app.ModeMalware, kind)
	vobjs, _ := agent.DefaultObjectives(app.ModeVuln, kind)
	writeJSON(w, http.StatusOK, map[string]any{"crew": out, "kind": string(kind),
		"objectives": map[string]any{"MALWARE": objs, "VULN_RESEARCH": vobjs}})
}

// missionDTO is a mission as the editor sees it.
type missionDTO struct {
	mission.Mission
	Starter  bool   `json:"starter"`
	Autonomy string `json:"autonomy"`
	Warning  string `json:"warning,omitempty"` // coverage check
}

func (s *server) missionDTO(m *mission.Mission, mode app.Mode) missionDTO {
	return missionDTO{Mission: *m, Starter: m.Starter, Autonomy: m.AutonomyPreset(),
		Warning: agent.CoverageWarning(m, mode, s.targetKind())}
}

func modeOf(v string) app.Mode {
	if strings.Contains(strings.ToUpper(v), "VULN") {
		return app.ModeVuln
	}
	return app.ModeMalware
}

func (s *server) handleMissions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		mode := modeOf(r.URL.Query().Get("mode"))
		var out []missionDTO
		for _, m := range mission.List() {
			out = append(out, s.missionDTO(m, mode))
		}
		writeJSON(w, http.StatusOK, map[string]any{"missions": out})
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "GET or POST")
		return
	}
	var req struct {
		Action  string           `json:"action"` // save | delete | check
		Name    string           `json:"name"`
		Mode    string           `json:"mode"`
		Mission *mission.Mission `json:"mission"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	switch req.Action {
	case "delete":
		if err := mission.Delete(req.Name); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "save", "check":
		if req.Mission == nil {
			writeErr(w, http.StatusBadRequest, "no mission in the request")
			return
		}
		if err := req.Mission.Validate(agent.KnownRole); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if req.Action == "save" {
			if err := mission.Save(req.Mission); err != nil {
				writeErr(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mission": s.missionDTO(req.Mission, modeOf(req.Mode))})
	default:
		writeErr(w, http.StatusBadRequest, "action must be save, delete or check")
	}
}

func (s *server) handleExperience(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		notes := experience.All()
		if notes == nil {
			notes = []experience.Note{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"notes": notes})
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "GET or POST")
		return
	}
	var req struct {
		Action string           `json:"action"` // keep | update | delete
		ID     string           `json:"id"`
		Lesson string           `json:"lesson"`
		Note   *experience.Note `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	var (
		n   experience.Note
		err error
	)
	switch req.Action {
	case "keep":
		if req.Note == nil {
			writeErr(w, http.StatusBadRequest, "no note in the request")
			return
		}
		n, err = experience.Add(*req.Note)
	case "update":
		n, err = experience.Update(req.ID, req.Lesson)
	case "delete":
		err = experience.Delete(req.ID)
	default:
		writeErr(w, http.StatusBadRequest, "action must be keep, update or delete")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "note": n})
}

// targetKind is the kind of whatever is open: the project's when known, BIN
// with the binary toolbox loaded, else a source tree — an APK when it has a
// manifest, a script package otherwise. "" = nothing open.
func (s *server) targetKind() api.ProjectKind {
	s.mu.RLock()
	p := s.curProj
	s.mu.RUnlock()
	if p != nil && p.Kind != "" {
		return p.Kind
	}
	if s.reg() != nil {
		return api.KindBIN
	}
	d := s.dir()
	if d == "" {
		return ""
	}
	for _, rel := range []string{"resources/AndroidManifest.xml", "AndroidManifest.xml"} {
		if _, err := os.Stat(filepath.Join(d, rel)); err == nil {
			return api.KindAPK
		}
	}
	return api.KindScript
}

// --- the run ---------------------------------------------------------------

// missionRun is one mission in flight (or paused at a checkpoint). The
// investigation mirrors what the crew pinned so findings get stable ids,
// provenance and verdicts, and holds the shared notebook.
type missionRun struct {
	id     string
	m      *mission.Mission
	mode   app.Mode
	kind   api.ProjectKind
	target string
	intel  string

	inv   *agent.Investigation
	crew  *tools.Registry // set_verdict + notebook, bound to inv
	accum *findingsAccum  // so a later save_report sees what the crew pinned

	mu       sync.Mutex
	emit     func(map[string]any) // the stream currently attached
	running  bool
	triaged  bool
	triage   string
	stepIdx  int
	log      []agent.StepRecord
	steer    string
	spent    int
	added    int
	reviewed bool
	lessons  []experience.Note
}

// send writes one event to whichever stream is attached. Crew members in a
// parallel group share the stream, so it is serialized here.
func (r *missionRun) send(ev map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.emit != nil {
		r.emit(ev)
	}
}

type missionRequest struct {
	chatRequest
	Mission     *mission.Mission `json:"mission"`     // the mission to run (as edited), or
	MissionName string           `json:"missionName"` // a saved/starter one by name
	Mode        string           `json:"mode"`
	Intel       string           `json:"intel"`
	Budget      int              `json:"budget"` // mission token total (0 = uncapped)
	RunID       string           `json:"runId"`  // resume a paused run
	Steer       string           `json:"steer"`  // analyst steering for the next step
	Action      string           `json:"action"` // resume only: "" continue | "report" wrap up now
}

// runEnv is what a request supplies for the provider calls of a run.
type runEnv struct {
	provider llm.Provider
	prov     config.Provider
	model    string
	system   string
	maxTok   int
	budget   int
	draft    *api.UpdateReportRequest
}

func (s *server) handleMissionRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req missionRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	prov, err := s.resolveProvider(req.chatRequest)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	provider, err := llm.New(prov)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "provider: "+err.Error())
		return
	}

	var run *missionRun
	if req.RunID != "" {
		if run = s.missionRun(req.RunID); run == nil {
			writeErr(w, http.StatusBadRequest, "that mission run is gone (BINNY was restarted) — start it again")
			return
		}
	} else {
		if run, err = s.newMissionRun(req); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	// A run the analyst just stopped takes a moment to unwind (the cancelled
	// provider call or tool has to return), so Continue right after Stop waits
	// for it instead of bouncing.
	for i := 0; ; i++ {
		run.mu.Lock()
		if !run.running {
			run.running = true
			if t := strings.TrimSpace(req.Steer); t != "" {
				run.steer = t
			}
			run.mu.Unlock()
			break
		}
		run.mu.Unlock()
		if i >= 50 {
			writeErr(w, http.StatusConflict, "this mission is still running (or still winding down a stopped step) — try again in a moment")
			return
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
	}

	send, ok := sseSender(w)
	if !ok {
		run.mu.Lock()
		run.running = false
		run.mu.Unlock()
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Connection", "keep-alive")
	run.mu.Lock()
	run.emit = send
	run.mu.Unlock()
	defer func() {
		run.mu.Lock()
		run.emit, run.running = nil, false
		run.mu.Unlock()
	}()

	env := runEnv{provider: provider, prov: prov, model: req.Model, system: strings.TrimSpace(req.System + "\n\n" + s.chatContext()),
		maxTok: req.MaxTokens, budget: req.Budget, draft: req.Report}
	if env.model == "" {
		env.model = prov.Models[0]
	}
	if env.maxTok <= 0 {
		env.maxTok = 8192
	}
	if env.maxTok > 32768 {
		env.maxTok = 32768
	}
	s.setProgress(func(line string) { run.send(map[string]any{"type": "status", "text": line}) })
	defer s.setProgress(nil)

	ctx := withFindings(withDraft(r.Context(), req.Report), run.accum)
	final, finished := s.runMission(ctx, run, env, req.Action == "report")
	if finished {
		// Follow-up chat continues from the report, with the run's record as context.
		// Any chat that came before the mission stays in the transcript.
		prior := append([]llm.Message(nil), s.loadConvo(req.ConversationID)...)
		if n := len(prior); n > 0 && prior[n-1].Role == llm.RoleUser {
			prior = prior[:n-1] // an unanswered turn can't precede another user turn
		}
		s.storeConvo(req.ConversationID, append(prior,
			llm.UserText(s.reportPrompt(run)),
			llm.Message{Role: llm.RoleAssistant, Blocks: []llm.Block{llm.TextBlock(final)}},
		))
		s.dropMissionRun(run.id)
	}
	run.send(map[string]any{"type": "done", "model": env.model})
}

func (s *server) newMissionRun(req missionRequest) (*missionRun, error) {
	kind := s.targetKind()
	if kind == "" {
		return nil, fmt.Errorf("open a target first — a mission needs something to investigate (Open, or Cloud for a project)")
	}
	m := req.Mission
	if m == nil {
		name := req.MissionName
		if name == "" {
			name = mission.Default().Name
		}
		loaded, err := mission.Load(name)
		if err != nil {
			return nil, err
		}
		m = loaded
	}
	m = m.Clone(m.Name) // a run may add steps; never edit the saved mission
	mode := modeOf(req.Mode)
	if m.Auto {
		objs, _ := agent.DefaultObjectives(mode, kind)
		m.Steps = agent.AutoSteps(objs, kind, mode, s.samplePath() != "")
	}
	if err := m.Validate(agent.KnownRole); err != nil {
		return nil, fmt.Errorf("mission %q can't run: %w", m.Name, err)
	}
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	run := &missionRun{
		id: "m" + hex.EncodeToString(buf), m: m, mode: mode, kind: kind,
		target: s.targetName(), intel: strings.TrimSpace(req.Intel),
		inv: agent.NewInvestigation(), accum: &findingsAccum{},
	}
	run.crew = agent.NewCrewTools(run.inv, func(f agent.Finding) {
		run.send(map[string]any{"type": "verdict", "id": f.ID, "verdict": f.Verdict, "severity": f.Severity,
			"was": f.WasSeverity, "reason": f.VerdictNote, "agent": f.VerifiedBy})
	})
	s.jobsMu.Lock()
	if s.missions == nil {
		s.missions = map[string]*missionRun{}
	}
	if len(s.missions) >= maxMissionRuns {
		for k, old := range s.missions {
			old.mu.Lock()
			idle := !old.running
			old.mu.Unlock()
			if idle {
				delete(s.missions, k)
				break
			}
		}
	}
	s.missions[run.id] = run
	s.jobsMu.Unlock()
	return run, nil
}

func (s *server) missionRun(id string) *missionRun {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	return s.missions[id]
}

func (s *server) dropMissionRun(id string) {
	s.jobsMu.Lock()
	delete(s.missions, id)
	s.jobsMu.Unlock()
}

// targetName is a display name for what's open.
func (s *server) targetName() string {
	if n := s.projectName(); n != "" {
		return n
	}
	if p := s.samplePath(); p != "" {
		return filepath.Base(p)
	}
	if d := s.dir(); d != "" {
		return filepath.Base(d)
	}
	return "the open binary"
}

// stepsDTO renders the mission's steps for the UI's track.
func stepsDTO(m *mission.Mission) []map[string]any {
	out := make([]map[string]any, 0, len(m.Steps))
	for i, st := range m.Steps {
		name := st.RoleID
		if ro, ok := agent.RoleByID(st.RoleID); ok {
			name = ro.Name
		}
		out = append(out, map[string]any{"step": i + 1, "role": strings.ToLower(st.RoleID), "name": name,
			"tasking": st.Tasking, "parallel": st.Parallel, "checkpoint": st.Checkpoint, "model": st.Model})
	}
	return out
}

// runMission advances a run until it finishes or pauses. It returns BINNY's
// report text and whether the run is over (false = paused: a checkpoint or an
// error the analyst can retry past).
func (s *server) runMission(ctx context.Context, run *missionRun, env runEnv, wrapUp bool) (string, bool) {
	m := run.m
	if !run.triaged {
		run.send(map[string]any{"type": "mission_start", "runId": run.id, "name": m.Name, "steps": stepsDTO(m),
			"verified": m.HasRole(agent.ParityID), "kind": string(run.kind)})
		run.send(map[string]any{"type": "step_start", "step": 0, "agent": agent.CaptainID, "name": "BINNY", "tasking": "Triage — what this is, and where the crew should look."})
		text, spent, errMsg := s.runStep(ctx, run, env, agent.Captain, 0, s.triagePrompt(run), s.captainTools(), env.system, missionTriageIters, 0)
		if errMsg != "" {
			run.send(map[string]any{"type": "mission_paused", "runId": run.id, "reason": errMsg})
			return "", false
		}
		run.triage, run.triaged = clipText(text, 3000), true
		run.send(map[string]any{"type": "step_debrief", "step": 0, "agent": agent.CaptainID, "name": "BINNY", "text": run.triage, "spent": spent, "findings": run.count(agent.CaptainID, 0)})
	} else {
		// A resumed stream redraws the track from where the run stands.
		run.send(map[string]any{"type": "mission_resume", "runId": run.id, "name": m.Name, "steps": stepsDTO(m), "log": run.log})
	}

	for !wrapUp && run.stepIdx < len(m.Steps) {
		first := run.stepIdx
		last := first
		for last+1 < len(m.Steps) && m.Steps[last+1].Parallel {
			last++
		}
		pause, errMsg := s.runGroup(ctx, run, env, first, last)
		if errMsg != "" {
			run.send(map[string]any{"type": "mission_paused", "runId": run.id, "reason": errMsg})
			return "", false
		}
		run.stepIdx = last + 1
		run.steer = ""
		if m.VerifyEachStep && m.HasRole(agent.ParityID) && len(run.inv.Unverified()) > 0 && !groupIsParity(m, first, last) {
			if errMsg := s.runParity(ctx, run, env, mission.Step{RoleID: agent.ParityID}, 0); errMsg != "" {
				run.send(map[string]any{"type": "mission_paused", "runId": run.id, "reason": errMsg})
				return "", false
			}
		}
		if run.stepIdx >= len(m.Steps) && m.AllowAdd && !run.reviewed {
			if errMsg := s.captainReview(ctx, run, env); errMsg != "" {
				run.send(map[string]any{"type": "mission_paused", "runId": run.id, "reason": errMsg})
				return "", false
			}
		}
		if pause && run.stepIdx < len(m.Steps) {
			run.send(map[string]any{"type": "checkpoint", "runId": run.id, "after": last + 1, "next": roleLabel(m.Steps[run.stepIdx].RoleID)})
			return "", false
		}
	}

	if run.inv.Snapshot().Verification != agent.VerificationDone {
		run.inv.SetVerification(agent.VerificationNone)
	}
	// The report is BINNY's own voice: plain chat events, no step card.
	run.send(map[string]any{"type": "report_start", "verification": run.inv.Snapshot().Verification})
	var final strings.Builder
	msgs := s.runAgentLoop(ctx, env.provider, llm.Request{
		System: env.system, Messages: []llm.Message{llm.UserText(s.reportPrompt(run))}, Model: env.model, MaxTokens: env.maxTok,
	}, func(ev map[string]any) {
		switch ev["type"] {
		case "done":
			return
		case "chunk":
			final.WriteString(fmt.Sprint(ev["text"]))
		case "usage":
			run.addSpend(ev)
		}
		run.send(ev)
	})
	if ctx.Err() != nil { // stopped mid-report: a partial report is not the report
		run.send(map[string]any{"type": "mission_paused", "runId": run.id, "reason": "stopped while BINNY was writing the report"})
		return "", false
	}
	text := lastAssistantText(msgs)
	if text == "" {
		text = final.String()
	}
	if strings.TrimSpace(text) == "" {
		run.send(map[string]any{"type": "mission_paused", "runId": run.id, "reason": "BINNY didn't get the report written — continue to try again"})
		return "", false
	}
	done := map[string]any{"type": "mission_done", "runId": run.id, "name": m.Name, "verification": run.inv.Snapshot().Verification,
		"log": run.log, "spent": run.spent, "mission": m, "target": experienceTarget(run).Label()}
	if len(run.lessons) > 0 {
		done["lessons"] = run.lessons
	}
	run.send(done)
	return text, true
}

func groupIsParity(m *mission.Mission, first, last int) bool {
	return first == last && strings.EqualFold(m.Steps[first].RoleID, agent.ParityID)
}

// runGroup runs one step, or a parallel group of them, to completion. It
// reports whether the mission should checkpoint afterwards.
func (s *server) runGroup(ctx context.Context, run *missionRun, env runEnv, first, last int) (pause bool, errMsg string) {
	m := run.m
	limit := env.prov.Concurrency()
	sem := make(chan struct{}, limit)
	errs := make([]string, last-first+1)
	var wg sync.WaitGroup
	for i := first; i <= last; i++ {
		st := m.Steps[i]
		pause = pause || st.Checkpoint
		wg.Add(1)
		go func(i int, st mission.Step) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if strings.EqualFold(st.RoleID, agent.ParityID) {
				errs[i-first] = s.runParity(ctx, run, env, st, i+1)
				return
			}
			errs[i-first] = s.runCrewStep(ctx, run, env, st, i+1, last > first)
		}(i, st)
	}
	wg.Wait()
	for _, e := range errs {
		if e != "" {
			return false, e
		}
	}
	return pause, ""
}

// skip records and announces a step that can't run. It never fails the run.
func (run *missionRun) skip(stepNo int, role agent.Role, id, reason string) {
	name := role.Name
	if name == "" {
		name = id
	}
	run.mu.Lock()
	run.log = append(run.log, agent.StepRecord{Step: stepNo, RoleID: strings.ToLower(id), Name: name, Status: "skipped", Reason: reason})
	run.mu.Unlock()
	run.send(map[string]any{"type": "step_skip", "step": stepNo, "agent": strings.ToLower(id), "name": name, "reason": reason})
}

// cantRun is why a role can't work the open target ("" = it can).
func (s *server) cantRun(role agent.Role, kind api.ProjectKind, toolCount int) string {
	if !role.WorksOn(kind) {
		if role.ID == "dex" {
			return fmt.Sprintf("this is a %s target, and Dex only works Android APKs", kind)
		}
		return fmt.Sprintf("%s doesn't work %s targets", role.Name, kind)
	}
	if role.NeedsSandbox && s.samplePath() == "" {
		return "no raw sample attached — use Attach sample, then try again"
	}
	if toolCount == 0 {
		return fmt.Sprintf("none of %s's tools exist for a %s target", role.Name, kind)
	}
	return ""
}

// captainTools is BINNY's own toolset on a mission: everything the chat has.
func (s *server) captainTools() []llm.Tool { return s.agentTools() }

// roleTools filters the chat's toolset down to a role's, and adds the
// crew-only tools the role may use. Desktop names its tree search
// search_code and pins code with write_artifact; both map onto the role data.
func (s *server) roleTools(run *missionRun, role agent.Role) (defs []llm.Tool, reads int) {
	if role.ID == agent.CaptainID {
		return append(s.captainTools(), run.crew.View([]string{"add_note", "read_notes"}).Defs()...), 1
	}
	defs, reads, want := s.roleToolDefs(role)
	names := make([]string, 0, len(want))
	for n := range want {
		names = append(names, n)
	}
	return append(defs, run.crew.View(names).Defs()...), reads
}

// roleToolDefs is the part of the chat's toolset a role may use (no crew-only
// tools — those belong to a mission run), how many of them read the target,
// and the role's full wanted set.
func (s *server) roleToolDefs(role agent.Role) (defs []llm.Tool, reads int, want map[string]bool) {
	want = map[string]bool{}
	for _, n := range role.ToolNames() {
		want[n] = true
	}
	if want["search"] {
		want["search_code"] = true
	}
	if role.ID != agent.ParityID {
		want["write_artifact"] = true
	}
	delete(want, agent.AskUserToolName) // a stream can't suspend on a question
	delete(want, "mark_objective")      // Desktop tracks no objective list
	delete(want, "suggest_renames")
	for _, t := range s.agentTools() {
		if !want[t.Name] {
			continue
		}
		defs = append(defs, t)
		switch t.Name {
		case "record_finding", "highlight_function", "write_artifact", "write_file", "run", "read_artifact", "decompile_sample", "switch_sample", "list_samples":
		default:
			reads++
		}
	}
	return defs, reads, want
}

// runCrewStep runs one crew member (or a Captain task card) for one step.
func (s *server) runCrewStep(ctx context.Context, run *missionRun, env runEnv, st mission.Step, stepNo int, parallel bool) string {
	role, ok := agent.RoleByID(st.RoleID)
	if !ok {
		run.skip(stepNo, agent.Role{}, st.RoleID, "no such crew member")
		return ""
	}
	defs, reads := s.roleTools(run, role)
	if parallel {
		// Members of a group must not re-point the shared read tools under each other.
		kept := defs[:0]
		for _, d := range defs {
			if d.Name != "switch_sample" && d.Name != "decompile_sample" {
				kept = append(kept, d)
			}
		}
		defs = kept
	}
	if why := s.cantRun(role, run.kind, reads); why != "" {
		run.skip(stepNo, role, role.ID, why)
		return ""
	}
	provider, model, err := s.stepProvider(env, st.Model)
	if err != nil {
		run.skip(stepNo, role, role.ID, "can't use model "+st.Model+": "+err.Error())
		return ""
	}
	objs, bias := agent.DefaultObjectives(run.mode, run.kind)
	mine := agent.StepObjectives(st, role, objs, run.kind)
	tasking := strings.TrimSpace(run.expand(st.Tasking))
	if tasking == "" {
		if len(mine) > 0 {
			tasking = "Work the objectives assigned to you below."
		} else {
			tasking = role.DefaultTask
		}
	}
	share := run.shareFor(st, env.budget)
	rec := agent.StepRecord{Step: stepNo, RoleID: role.ID, Name: role.Name, Tasking: tasking, Status: "running", Model: model, Budget: share}
	for _, o := range mine {
		rec.Objectives = append(rec.Objectives, o.ID)
	}
	run.send(map[string]any{"type": "step_start", "step": stepNo, "agent": role.ID, "name": role.Name, "title": role.Title,
		"tasking": tasking, "objectives": rec.Objectives, "budget": share, "model": model})

	kick := s.crewKickoff(run, role, tasking, mine, bias, stepNo)
	system := agent.CrewSystem(env.system, role)
	stepEnv := env
	stepEnv.provider, stepEnv.model = provider, model
	debrief, spent, errMsg := s.runStep(ctx, run, stepEnv, role, stepNo, kick, defs, system, missionStepIters, share)
	if errMsg != "" {
		return fmt.Sprintf("%s hit an error: %s", role.Name, errMsg)
	}
	debrief, lessons := agent.LessonsFrom(debrief, role.ID, experienceTarget(run), run.target)
	debrief, rec.Handoffs = agent.HandoffsFrom(debrief, role.ID)
	rec.Findings = run.count(role.ID, stepNo)
	if debrief == "" {
		debrief = fmt.Sprintf("(no debrief written) pinned %d finding(s)", rec.Findings)
	}
	rec.Status, rec.Debrief, rec.Spent = "done", clipText(debrief, 1500), spent
	run.mu.Lock()
	run.log = append(run.log, rec)
	run.lessons = append(run.lessons, lessons...)
	run.mu.Unlock()
	ev := map[string]any{"type": "step_debrief", "step": stepNo, "agent": role.ID, "name": role.Name,
		"text": rec.Debrief + agent.HandoffLines(rec.Handoffs), "findings": rec.Findings, "spent": spent}
	if len(lessons) > 0 {
		ev["lessons"] = lessons
	}
	run.send(ev)
	return ""
}

// runParity runs the verification pass over the findings not yet ruled on.
func (s *server) runParity(ctx context.Context, run *missionRun, env runEnv, st mission.Step, stepNo int) string {
	role, _ := agent.RoleByID(agent.ParityID)
	scope := run.inv.Unverified()
	if len(scope) == 0 {
		run.inv.SetVerification(agent.VerificationDone)
		run.skip(stepNo, role, role.ID, "there are no unverified findings to check")
		return ""
	}
	defs, reads := s.roleTools(run, role)
	if why := s.cantRun(role, run.kind, reads); why != "" {
		run.skip(stepNo, role, role.ID, why)
		return ""
	}
	provider, model, err := s.stepProvider(env, st.Model)
	if err != nil {
		run.skip(stepNo, role, role.ID, "can't use model "+st.Model+": "+err.Error())
		return ""
	}
	tasking := fmt.Sprintf("Verify %d finding(s): %s", len(scope), strings.Join(scope, ", "))
	share := run.shareFor(st, env.budget)
	run.send(map[string]any{"type": "step_start", "step": stepNo, "agent": role.ID, "name": role.Name, "title": role.Title,
		"tasking": tasking, "budget": share, "model": model})
	kick := fmt.Sprintf("Target: %q (kind=%s).\n", run.target, run.kind) + agent.ParityBrief(run.m.Name, run.inv.Snapshot(), scope) + run.handoffsFor(agent.ParityID)
	stepEnv := env
	stepEnv.provider, stepEnv.model = provider, model
	debrief, spent, errMsg := s.runStep(ctx, run, stepEnv, role, stepNo, kick, defs, agent.CrewSystem(env.system, role), missionStepIters, share)
	if errMsg != "" {
		return "Parity hit an error: " + errMsg
	}
	run.inv.SetVerification(agent.VerificationDone)
	c, d, rj, u := 0, 0, 0, 0
	for _, f := range run.inv.Snapshot().Findings {
		in := false
		for _, id := range scope {
			in = in || id == f.ID
		}
		if !in {
			continue
		}
		switch f.Verdict {
		case agent.VerdictConfirmed:
			c++
		case agent.VerdictDowngraded:
			d++
		case agent.VerdictRejected:
			rj++
		default:
			u++
		}
	}
	tally := fmt.Sprintf("%d confirmed, %d downgraded, %d rejected", c, d, rj)
	if u > 0 {
		tally += fmt.Sprintf(", %d not reached (unverified)", u)
	}
	if debrief != "" {
		tally += ". " + debrief
	}
	rec := agent.StepRecord{Step: stepNo, RoleID: role.ID, Name: role.Name, Tasking: tasking, Status: "done",
		Debrief: clipText(tally, 1500), Spent: spent, Model: model, Budget: share}
	run.mu.Lock()
	run.log = append(run.log, rec)
	run.mu.Unlock()
	run.send(map[string]any{"type": "step_debrief", "step": stepNo, "agent": role.ID, "name": role.Name, "text": rec.Debrief,
		"spent": spent, "confirmed": c, "downgraded": d, "rejected": rj, "unverified": u})
	return ""
}

// runStep runs the agent loop for one crew member and returns its debrief
// (the final text), what it spent, and an error message if the loop failed.
// Every event it causes is stamped with the member and step.
func (s *server) runStep(ctx context.Context, run *missionRun, env runEnv, role agent.Role, stepNo int, kickoff string, defs []llm.Tool, system string, iters, share int) (debrief string, spent int, errMsg string) {
	allowed := map[string]bool{}
	for _, d := range defs {
		allowed[d.Name] = true
	}
	var mu sync.Mutex
	wrap := func(ev map[string]any) {
		switch ev["type"] {
		case "done":
			return // one step ending isn't the stream ending
		case "error":
			mu.Lock()
			errMsg = fmt.Sprint(ev["error"])
			mu.Unlock()
		case "usage":
			n := run.addSpend(ev)
			mu.Lock()
			spent += n
			mu.Unlock()
		case "finding":
			ev["id"] = run.mirrorFinding(ev, role.ID, stepNo)
		}
		ev["agent"], ev["step"] = role.ID, stepNo
		run.send(ev)
	}
	cfg := loopCfg{
		maxIters: iters,
		stop: func() string {
			mu.Lock()
			defer mu.Unlock()
			if share > 0 && spent >= share {
				return fmt.Sprintf("%s has used its share of the mission budget (~%dk tokens).", role.Name, spent/1000)
			}
			return ""
		},
		tool: func(ctx context.Context, name string, input json.RawMessage) (string, bool, bool) {
			if !allowed[name] {
				return fmt.Sprintf("%s isn't one of your tools on this mission. If the task needs it, say so in your debrief.", name), true, true
			}
			if run.crew.Has(name) {
				out, isErr := run.crew.Run(ctx, name, input)
				return out, isErr, true
			}
			return "", false, false
		},
	}
	lctx := withLoopCfg(agent.WithActor(ctx, role.ID, stepNo), cfg)
	msgs := s.runAgentLoop(lctx, env.provider, llm.Request{
		System: system, Messages: []llm.Message{llm.UserText(kickoff)}, Tools: defs, Model: env.model, MaxTokens: env.maxTok,
	}, wrap)
	return lastAssistantText(msgs), spent, errMsg
}

// captainReview lets the captain add steps after the planned ones
// (Mission.AllowAdd). One provider call, one tool.
func (s *server) captainReview(ctx context.Context, run *missionRun, env runEnv) string {
	run.reviewed = true
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %q (kind=%s).\n\nMISSION REVIEW. Your crew has finished the planned steps. Their debriefs:\n%s", run.target, run.kind, run.debriefs())
	fmt.Fprintf(&b, "\nRecorded evidence:\n%s\nCrew you can dispatch:\n", run.inv.Snapshot().EvidenceSummary())
	for _, ro := range agent.Roles() {
		_, reads := s.roleTools(run, ro)
		if ro.ID == agent.ParityID || s.cantRun(ro, run.kind, reads) != "" {
			continue
		}
		fmt.Fprintf(&b, "- %s — %s\n", ro.ID, ro.Title)
	}
	fmt.Fprintf(&b, "\nIf a specific gap is worth more work, call dispatch_crew (at most %d times) with the crew member and a precise tasking. If the crew's work is enough for the report, reply without calling it.\n", missionMaxAdded)
	resp, err := env.provider.Stream(ctx, llm.Request{
		System: env.system, Messages: []llm.Message{llm.UserText(b.String())}, Model: env.model, MaxTokens: env.maxTok,
		Tools: []llm.Tool{tools.Def("dispatch_crew", "Add one more step to the mission: send a crew member back out with a precise tasking.",
			tools.Obj(map[string]any{
				"role":    tools.StrProp("crew member id, e.g. trace, hex, twine"),
				"tasking": tools.StrProp("exactly what to establish, and where to start"),
			}, "role", "tasking"))},
	}, nil)
	if err != nil {
		run.reviewed = false
		return err.Error()
	}
	run.addSpend(map[string]any{"input": resp.Usage.InputTokens + resp.Usage.CacheCreationTokens, "output": resp.Usage.OutputTokens})
	parityRan := run.inv.Snapshot().Verification == agent.VerificationDone
	for _, c := range resp.ToolCalls() {
		var a struct{ Role, Tasking string }
		if c.Name != "dispatch_crew" || run.added >= missionMaxAdded || json.Unmarshal(c.Input, &a) != nil || strings.TrimSpace(a.Tasking) == "" {
			continue
		}
		role, ok := agent.RoleByID(a.Role)
		if !ok || role.ID == agent.ParityID {
			continue
		}
		run.m.Steps = append(run.m.Steps, mission.Step{RoleID: role.ID, Tasking: strings.TrimSpace(a.Tasking)})
		run.added++
	}
	if run.added > 0 {
		if parityRan && run.m.HasRole(agent.ParityID) {
			run.m.Steps = append(run.m.Steps, mission.Step{RoleID: agent.ParityID})
		}
		run.send(map[string]any{"type": "mission_plan", "steps": stepsDTO(run.m), "added": run.added})
	}
	return ""
}

// stepProvider resolves a step's model: "" is the request's; "provider/model"
// crosses to another configured provider; anything else is a model id on the
// request's provider.
func (s *server) stepProvider(env runEnv, model string) (llm.Provider, string, error) {
	model = strings.TrimSpace(model)
	if model == "" {
		return env.provider, env.model, nil
	}
	if i := strings.IndexByte(model, '/'); i > 0 {
		s.mu.RLock()
		var found *config.Provider
		for k := range s.opts.Providers {
			if s.opts.Providers[k].ID == model[:i] {
				p := s.opts.Providers[k]
				found = &p
			}
		}
		s.mu.RUnlock()
		if found != nil {
			if !found.HasKey() {
				return nil, "", fmt.Errorf("provider %q has no key configured", found.ID)
			}
			c, err := llm.New(*found)
			return c, model[i+1:], err
		}
	}
	return env.provider, model, nil
}

// --- run bookkeeping -------------------------------------------------------

// addSpend folds a usage event into the run total and returns its size.
func (run *missionRun) addSpend(ev map[string]any) int {
	n := toInt(ev["input"]) + toInt(ev["output"])
	run.mu.Lock()
	run.spent += n
	run.mu.Unlock()
	return n
}

func toInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	}
	return 0
}

// shareFor splits what is left of the mission budget across the steps still
// to run (0 = the mission is uncapped).
func (run *missionRun) shareFor(st mission.Step, budget int) int {
	if st.TokenBudget > 0 {
		return st.TokenBudget
	}
	if budget <= 0 {
		return 0
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	remaining := len(run.m.Steps) - run.stepIdx
	if remaining < 1 {
		remaining = 1
	}
	share := (budget - run.spent) / remaining
	if share < missionMinShare {
		share = missionMinShare
	}
	return share
}

// mirrorFinding records a pinned finding in the run's investigation, which
// gives it a stable id, provenance, and a place for Parity's verdict.
func (run *missionRun) mirrorFinding(ev map[string]any, roleID string, stepNo int) string {
	str := func(k string) string {
		v, _ := ev[k].(string)
		return strings.TrimSpace(v)
	}
	ref := str("function")
	if f := str("file"); f != "" {
		if n := toInt(ev["line"]); n > 0 {
			f = fmt.Sprintf("%s:%d", f, n)
		}
		if ref == "" {
			ref = f
		} else if f != ref {
			ref += ", " + f
		}
	}
	if ref == "" {
		ref = str("title")
	}
	cat := str("cwe")
	if cat == "" {
		cat = "finding"
	}
	note := str("title")
	if n := str("note"); n != "" {
		note += " — " + n
	}
	sev := strings.ToLower(str("severity"))
	if sev == "" {
		sev = "info"
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	_ = run.inv.AddFinding(agent.Finding{Category: cat, Severity: sev, Note: note, CWE: str("cwe"),
		EvidenceRefs: []string{ref}, FoundBy: roleID, Step: stepNo})
	return fmt.Sprintf("F%d", len(run.inv.Snapshot().Findings))
}

// count is how many findings a crew member pinned in a step.
func (run *missionRun) count(roleID string, stepNo int) int {
	n := 0
	for _, f := range run.inv.Snapshot().Findings {
		if f.FoundBy == roleID && f.Step == stepNo {
			n++
		}
	}
	return n
}

func (run *missionRun) debriefs() string {
	run.mu.Lock()
	defer run.mu.Unlock()
	var b strings.Builder
	for _, r := range run.log {
		if r.Status == "skipped" {
			fmt.Fprintf(&b, "- %s: SKIPPED — %s\n", r.Name, r.Reason)
		} else {
			fmt.Fprintf(&b, "- %s: %s%s\n", r.Name, r.Debrief, agent.HandoffLines(r.Handoffs))
		}
	}
	return b.String()
}

// handoffsFor is what crewmates left for a role in the steps before it.
func (run *missionRun) handoffsFor(roleID string) string {
	run.mu.Lock()
	defer run.mu.Unlock()
	return agent.HandoffsFor(roleID, run.log)
}

// expand fills the run-time placeholders in a tasking prompt.
func (run *missionRun) expand(t string) string {
	if !strings.Contains(t, "{") {
		return t
	}
	findings := strings.TrimSpace(run.inv.Snapshot().EvidenceSummary())
	if findings == "" {
		findings = "(nothing recorded yet)"
	}
	class := clipText(run.triage, 400)
	if class == "" {
		class = "not triaged yet"
	}
	return strings.NewReplacer("{sample}", run.target, "{classification}", class, "{findings}", findings).Replace(t)
}

func experienceTarget(run *missionRun) experience.Target {
	return experience.Target{Kind: string(run.kind), Mode: string(run.mode)}
}

// --- prompts ---------------------------------------------------------------

func (s *server) triagePrompt(run *missionRun) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %q (kind=%s).\n", run.target, run.kind)
	if run.intel != "" {
		fmt.Fprintf(&b, "\nAnalyst intel: %s\n", run.intel)
	}
	fmt.Fprintf(&b, "\nMISSION %q — TRIAGE. You are the captain. Your crew goes out after you: ", run.m.Name)
	var names []string
	for _, st := range run.m.Steps {
		names = append(names, roleLabel(st.RoleID))
	}
	b.WriteString(strings.Join(names, ", ") + ".\n")
	if run.mode == app.ModeVuln {
		b.WriteString("\nDo a BOUNDED first pass — a handful of tool calls: what the target is and where attacker-controlled input enters it (the attack surface). Do not audit yet; that is the crew's job.\n")
	} else {
		b.WriteString("\nDo a BOUNDED first pass — a handful of tool calls: what the target is, your best classification (STIX malware type, or benign/unknown) with the evidence for it, and anything that looks packed or encrypted. Do not investigate in depth; that is the crew's job.\n")
	}
	b.WriteString("\nThen stop calling tools and write a short TRIAGE BRIEF for the crew: what it is, what you saw that says so, and the two or three places they should look first. Do not write the report yet.\n")
	return b.String()
}

func (s *server) crewKickoff(run *missionRun, role agent.Role, tasking string, objs []agent.Objective, bias string, stepNo int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %q (kind=%s).\n", run.target, run.kind)
	if run.intel != "" {
		fmt.Fprintf(&b, "\nAnalyst intel: %s\n", run.intel)
	}
	if run.triage != "" {
		fmt.Fprintf(&b, "\nBINNY's triage brief:\n%s\n", run.triage)
	}
	who := role.Name
	if role.ID == agent.CaptainID {
		who = "BINNY, on a Captain task card"
	}
	fmt.Fprintf(&b, "\nMISSION %q — step %d. You are %s.\n", run.m.Name, stepNo, who)
	b.WriteString(agent.MissionCrewLine(run.m.Steps, stepNo, role.ID))
	if t := strings.TrimSpace(run.expand(run.m.Tasking)); t != "" {
		fmt.Fprintf(&b, "\nMission tasking (the whole crew has this):\n%s\n", t)
	}
	fmt.Fprintf(&b, "\nYOUR TASKING:\n%s\n", tasking)
	if len(objs) > 0 {
		b.WriteString("\nObjectives assigned to you:\n")
		for _, o := range objs {
			fmt.Fprintf(&b, "- [%s] %s\n", o.ID, o.Desc)
		}
		if bias != "" {
			fmt.Fprintf(&b, "\nWhere to look (a hint — use the tools you actually have): %s\n", bias)
		}
	}
	snap := run.inv.Snapshot()
	if len(snap.Findings) > 0 {
		fmt.Fprintf(&b, "\nPINNED SO FAR by the crew before you — build on it, don't redo it:\n%s\n", strings.TrimSpace(snap.EvidenceSummary()))
	}
	if nb := snap.NotebookSummary(); nb != "" {
		fmt.Fprintf(&b, "\nSHARED NOTEBOOK — what the crew already worked out (read_notes for the current list):\n%s", nb)
	}
	if d := run.debriefs(); d != "" {
		fmt.Fprintf(&b, "\nCREW DEBRIEFS so far:\n%s", d)
	}
	b.WriteString(run.handoffsFor(role.ID))
	if hints := experience.Match(experience.All(), experienceTarget(run), role.ID); len(hints) > 0 {
		b.WriteString("\nEXPERIENCE — method hints from past runs on this kind of target. They say WHERE TO LOOK and nothing about this sample: verify everything here, and a hint is never evidence.\n")
		for _, h := range hints {
			fmt.Fprintf(&b, "- %s\n", h.Lesson)
		}
	}
	if run.steer != "" {
		fmt.Fprintf(&b, "\nANALYST STEERING (given at the last checkpoint):\n%s\n", run.steer)
	}
	b.WriteString("\nPin every distinct issue with record_finding as you establish it — anchored to the function (binary) or file and line (source) it lives in. An unanchored claim is not a finding.\n")
	b.WriteString("\nBegin. When you are done, stop calling tools and give your DEBRIEF. If this run taught you a reusable METHOD for this kind of target — where to look, how to approach it, never a conclusion about this sample — you may end the debrief with one line starting `LESSON:`.\n")
	return b.String()
}

// reportPrompt hands BINNY everything the crew recorded and asks for the
// report. It is also what a follow-up chat is seeded with.
func (s *server) reportPrompt(run *missionRun) string {
	var b strings.Builder
	snap := run.inv.Snapshot()
	fmt.Fprintf(&b, "Target: %q (kind=%s).\n", run.target, run.kind)
	if run.intel != "" {
		fmt.Fprintf(&b, "\nAnalyst intel: %s\n", run.intel)
	}
	fmt.Fprintf(&b, "\nMISSION %q is complete — your crew ran the investigation, and you now write the report for the analyst.\n", run.m.Name)
	if run.triage != "" {
		fmt.Fprintf(&b, "\nYour triage brief:\n%s\n", run.triage)
	}
	if d := run.debriefs(); d != "" {
		fmt.Fprintf(&b, "\nCrew debriefs:\n%s", d)
	}
	if ev := strings.TrimSpace(snap.EvidenceSummary()); ev != "" {
		fmt.Fprintf(&b, "\nPinned findings (each is already in the Findings panel):\n%s\n", ev)
	} else {
		b.WriteString("\nThe crew pinned no findings.\n")
	}
	if nb := snap.NotebookSummary(); nb != "" {
		b.WriteString("\nShared notebook (what functions and symbols are):\n" + nb)
	}
	b.WriteString(agent.VerificationBrief(snap))
	b.WriteString("\nWrite the report in Markdown: what the target is; what the crew established, each claim with the function or file:line that shows it; what was checked and cleared; what is still open. Write only from what is recorded above — do not add a finding nobody pinned. If the crew pinned nothing, say plainly what was examined and that nothing was established.\n")
	return b.String()
}

// --- small helpers ---------------------------------------------------------

func roleLabel(id string) string {
	if ro, ok := agent.RoleByID(id); ok {
		return ro.Name
	}
	return id
}

func clipText(t string, n int) string {
	t = strings.TrimSpace(t)
	if len(t) <= n {
		return t
	}
	return t[:n] + "…"
}

// lastAssistantText is the text of the final assistant message of a
// transcript — a crew member's debrief.
func lastAssistantText(msgs []llm.Message) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role != llm.RoleAssistant {
			continue
		}
		var b strings.Builder
		for _, blk := range msgs[i].Blocks {
			if blk.Kind == llm.BlockText {
				b.WriteString(blk.Text)
			}
		}
		return strings.TrimSpace(b.String())
	}
	return ""
}
