// Package app holds BINNY's mutable session state — the single source of
// truth the TUI renders and the agent loop steers. Kept separate from both so
// slash commands, the phase machine, and the view all read/write one struct.
package app

import (
	"fmt"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/config"
)

// Mode is the analysis lens, mirroring the backend AnalysisMode enum.
type Mode string

const (
	ModeMalware Mode = "MALWARE"       // MAR — malware analysis report
	ModeVuln    Mode = "VULN_RESEARCH" // VRR — vulnerability research report
)

// Autonomy is how much the analyst stays in the loop — orthogonal to the
// analysis lens (Mode). It controls whether the engine runs straight through or
// pauses for review/steering, and whether the report is co-shaped.
type Autonomy string

const (
	// Autonomous runs every round to a finished draft with no scheduled stops.
	Autonomous Autonomy = "AUTONOMOUS"
	// Supervised pauses at phase boundaries (triage→investigate→synthesize) and
	// asks when it hits ambiguity a tool can't resolve.
	Supervised Autonomy = "SUPERVISED"
	// Collaborative is Supervised plus a report-shaping interview (audience,
	// depth, tone) before synthesis.
	Collaborative Autonomy = "COLLABORATIVE"
)

// AutonomyLabel renders a short human label for a mode.
func AutonomyLabel(a Autonomy) string {
	switch a {
	case Autonomous:
		return "Autonomous"
	case Collaborative:
		return "Collaborative"
	default:
		return "Supervised"
	}
}

// Phase is the position in BINNY's state machine (SELECT→…→REVIEW).
type Phase string

const (
	PhaseSelect      Phase = "SELECT"
	PhaseMode        Phase = "MODE"
	PhaseDecomp      Phase = "DECOMP"
	PhaseIntel       Phase = "INTEL"
	PhaseTriage      Phase = "TRIAGE"
	PhasePlaybook    Phase = "PLAYBOOK"
	PhaseInvestigate Phase = "INVESTIGATE"
	PhaseSynthesize  Phase = "SYNTHESIZE"
	PhaseReview      Phase = "REVIEW"
)

// Session is the live BINNY session.
type Session struct {
	Endpoints config.Endpoints
	Config    *config.Config
	API       *api.Client

	Provider *config.Provider // currently selected LLM provider
	Model    string           // currently selected model id
	Mode     Mode
	Autonomy Autonomy // how much the analyst stays in the loop
	Phase    Phase

	Project    *api.Project // selected sample under analysis
	Sample     *api.Sample  // active EXTRA sample of a multi-sample project; nil = the primary binary
	Intel      string       // analyst-supplied intel (phase INTEL)
	SamplePath string       // local path to the raw sample (for extraction)

	// VulnFocus scopes a vuln-mode session to specific vulnerability classes
	// (resolved playbook.VulnClass keys). Empty = survey every class. Ignored
	// in malware mode.
	VulnFocus []string

	// WorkspacePath is the persistent host dir mounted rw at /work in the
	// extraction sandbox. Empty = per-sample default under
	// ~/.local/share/binny/workspaces/ (resolved lazily; see /workspace).
	WorkspacePath string
}

// NewSession builds a session with provider/model resolved from config
// defaults (falling back to the first configured provider).
func NewSession(ep config.Endpoints, cfg *config.Config, client *api.Client) *Session {
	s := &Session{
		Endpoints: ep,
		Config:    cfg,
		API:       client,
		Mode:      ModeMalware,
		Autonomy:  Supervised, // balanced default; analyst picks per project
		Phase:     PhaseSelect,
	}
	if p := cfg.Find(cfg.DefaultProvider); p != nil {
		s.Provider = p
	} else if len(cfg.Providers) > 0 {
		s.Provider = &cfg.Providers[0]
	}
	s.Model = cfg.DefaultModel
	if s.Provider != nil && !s.providerHasModel(s.Model) && len(s.Provider.Models) > 0 {
		s.Model = s.Provider.Models[0]
	}
	return s
}

func (s *Session) providerHasModel(model string) bool {
	if s.Provider == nil {
		return false
	}
	for _, m := range s.Provider.Models {
		if m == model {
			return true
		}
	}
	return false
}

// SetProvider switches the active provider by id, defaulting the model to that
// provider's first model. Returns an error if the id is unknown.
func (s *Session) SetProvider(id string) error {
	p := s.Config.Find(id)
	if p == nil {
		return fmt.Errorf("unknown provider %q — see /models", id)
	}
	s.Provider = p
	if len(p.Models) > 0 {
		s.Model = p.Models[0]
	}
	s.persistDefaults()
	return nil
}

// SetModel switches the active model. If the model belongs to a different
// configured provider, the provider switches too; otherwise it's accepted
// as-is on the current provider (custom model ids are allowed).
func (s *Session) SetModel(model string) error {
	for i := range s.Config.Providers {
		for _, m := range s.Config.Providers[i].Models {
			if m == model {
				s.Provider = &s.Config.Providers[i]
				s.Model = model
				s.persistDefaults()
				return nil
			}
		}
	}
	if s.Provider == nil {
		return fmt.Errorf("no provider selected — pick one with /model <providerId> first")
	}
	s.Model = model // custom/unlisted model id on the current provider
	s.persistDefaults()
	return nil
}

func (s *Session) persistDefaults() {
	if s.Provider != nil {
		s.Config.DefaultProvider = s.Provider.ID
	}
	s.Config.DefaultModel = s.Model
	_ = s.Config.Save() // best-effort; a failed remember shouldn't break the session
}

// ProviderReady reports whether the active provider has a usable key.
func (s *Session) ProviderReady() bool {
	return s.Provider != nil && s.Provider.HasKey()
}

// TokenBudget returns the per-run token cap for the active project (or the
// global default when there's no project / no override).
func (s *Session) TokenBudget() int {
	if s.Project == nil {
		return config.DefaultTokenBudget
	}
	return s.Config.ProjectBudget(s.Project.ID)
}

// SetTokenBudget stores a per-project token budget (Settings → token budget).
func (s *Session) SetTokenBudget(budget int) error {
	if s.Project == nil {
		return fmt.Errorf("no project selected")
	}
	return s.Config.SetProjectBudget(s.Project.ID, budget)
}
