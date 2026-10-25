package agent

import (
	"fmt"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/llm"
	"openbin.ai/binny/internal/playbook"
	"openbin.ai/binny/internal/tools"
)

// EngineState is the serializable snapshot of an engine + its investigation —
// everything needed to resume the loop after an interrupt/crash. Playbooks are
// NOT stored: they're re-derived from the mode + classification on restore (the
// same way Start/advanceStage load them), so the persisted state stays small.
type EngineState struct {
	Messages         []llm.Message  `json:"messages"`
	Stage            int            `json:"stage"`
	Rounds           int            `json:"rounds"`
	SpentTokens      int            `json:"spentTokens"`
	CacheReadTokens  int            `json:"cacheReadTokens,omitempty"`
	MaxTokens        int            `json:"maxTokens"`
	Briefed          []int          `json:"briefed"` // stages already briefed
	ReportPrefs      string         `json:"reportPrefs,omitempty"`
	ReportPrefsAsked bool           `json:"reportPrefsAsked,omitempty"`
	TriageNudges     int            `json:"triageNudges,omitempty"`
	SynthDeadline    int            `json:"synthDeadline,omitempty"`
	CapReason        string         `json:"capReason,omitempty"`
	Investigation    *Investigation `json:"investigation"`
	Pending          *PendingState  `json:"pending,omitempty"`
	Sample           *api.Sample    `json:"sample,omitempty"` // active extra sample at snapshot time
}

// PendingState mirrors a suspended ask (ask_user or the Collaborative report
// interview) so a resumed session lands back on the same question.
type PendingState struct {
	Kind         int         `json:"kind"`
	Question     string      `json:"question"`
	AskToolID    string      `json:"askToolID,omitempty"`
	OtherResults []llm.Block `json:"otherResults,omitempty"`
}

// State captures the engine for persistence.
func (e *Engine) State() EngineState {
	briefed := make([]int, 0, len(e.briefed))
	for s, ok := range e.briefed {
		if ok {
			briefed = append(briefed, int(s))
		}
	}
	st := EngineState{
		Messages:         e.messages,
		Stage:            int(e.stage),
		Rounds:           e.rounds,
		SpentTokens:      e.spentTokens,
		CacheReadTokens:  e.cacheReadTokens,
		MaxTokens:        e.maxTokens,
		Briefed:          briefed,
		ReportPrefs:      e.reportPrefs,
		ReportPrefsAsked: e.reportPrefsAsked,
		TriageNudges:     e.triageNudges,
		SynthDeadline:    e.synthDeadline,
		CapReason:        e.capReason,
		Investigation:    e.inv,
	}
	if e.tb != nil {
		st.Sample = e.tb.ActiveSample()
	}
	if e.pending != nil {
		st.Pending = &PendingState{
			Kind:         int(e.pending.kind),
			Question:     e.pending.question,
			AskToolID:    e.pending.askToolID,
			OtherResults: e.pending.otherResults,
		}
	}
	return st
}

// RestoreEngine rebuilds an engine + investigation from a persisted state. It
// reconstructs the tool registry and provider exactly like Build, then rehydrates
// the loop's internal state so stepping continues where it left off.
func RestoreEngine(sess *app.Session, client *api.Client, st EngineState) (*Engine, *Investigation, error) {
	provider, err := llm.New(*sess.Provider)
	if err != nil {
		return nil, nil, err
	}
	inv := st.Investigation
	if inv == nil {
		inv = NewInvestigation()
	}
	reg := tools.NewRegistry()
	tb := tools.NewToolbox(client, sess.Project)
	tb.RegisterRead(reg)
	registerOutputTools(reg, inv, client, sess.Project, sess.Mode)
	registerExtractionTools(reg, inv, sess)
	registerSampleTools(reg, sess, tb)
	if st.Sample != nil {
		// The interrupted session was looking at an extra sample — re-point
		// the read tools at it so BINNY resumes on the same binary. The signed
		// URL in the snapshot is stale by now; the inline endpoint fallback
		// (empty URL) still works.
		s := *st.Sample
		s.AnalysisDownloadURL = ""
		if _, err := tb.SwitchSample(&s); err == nil {
			sess.Sample = &s
		} else {
			sess.Sample = nil
		}
	}

	e := NewEngine(sess, inv, reg, provider)
	e.tb = tb
	tb.Progress = func(format string, args ...any) { e.StreamLine(fmt.Sprintf(format, args...)) }
	e.messages = st.Messages
	e.stage = stage(st.Stage)
	e.rounds = st.Rounds
	e.spentTokens = st.SpentTokens
	e.cacheReadTokens = st.CacheReadTokens
	if st.MaxTokens > 0 {
		e.maxTokens = st.MaxTokens
	}
	e.reportPrefs = st.ReportPrefs
	e.reportPrefsAsked = st.ReportPrefsAsked
	e.triageNudges = st.TriageNudges
	e.synthDeadline = st.SynthDeadline
	e.capReason = st.CapReason
	e.briefed = map[stage]bool{}
	for _, s := range st.Briefed {
		e.briefed[stage(s)] = true
	}
	// Re-derive playbooks (never serialized) — objectives + coverage already live
	// in the restored investigation, so do NOT reload them.
	if sess.Mode == app.ModeVuln {
		e.pbs = []playbook.Playbook{vulnPlaybookForSession(sess)}
	} else if len(inv.MalwareTypes) > 0 {
		e.pbs = playbook.SelectByTypes(inv.MalwareTypes)
	}
	if st.Pending != nil {
		e.pending = &pendingAsk{
			kind:         askKind(st.Pending.Kind),
			question:     st.Pending.Question,
			askToolID:    st.Pending.AskToolID,
			otherResults: st.Pending.OtherResults,
		}
	}
	return e, inv, nil
}
