// Package mission holds BINNY's saved crew pipelines. A mission is data, the
// same way a playbook is: an ordered list of crew steps, where the analyst
// placed checkpoints, and the tasking each step runs with. BINNY's triage is
// implicitly first and the report implicitly last; neither is a step.
//
// The package knows nothing about models or tools. Roles are referred to by
// id, and the engine resolves them when the mission runs.
package mission

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"openbin.ai/binny/internal/config"
)

// Role ids a mission treats specially.
const (
	CaptainID = "binny"  // a standalone Captain task card
	ParityID  = "parity" // the verification pass
)

// Autonomy presets: where the checkpoints go.
const (
	Autonomous = "autonomous" // no checkpoints
	Supervised = "supervised" // a checkpoint after every step
	Custom     = "custom"     // as the analyst placed them
)

// Mission is a saved pipeline.
type Mission struct {
	Name string `json:"name"`
	Desc string `json:"desc,omitempty"`
	// Steps run in order. A step with Parallel set runs alongside the step
	// before it.
	Steps []Step `json:"steps"`
	// Auto missions carry no steps: the crew is assembled after triage from
	// whichever roles own the loaded objectives.
	Auto bool `json:"auto,omitempty"`
	// AllowAdd lets the captain dispatch extra steps after the planned ones
	// ("Captain may add steps"). Off by default: Go code drives dispatch.
	AllowAdd bool `json:"allowAdd,omitempty"`
	// Tasking is mission-level direction every crew member sees.
	Tasking string `json:"tasking,omitempty"`
	// VerifyEachStep runs Parity after every step instead of once where it
	// is placed. Only meaningful when the mission includes Parity.
	VerifyEachStep bool `json:"verifyEachStep,omitempty"`

	// Starter marks a shipped, read-only mission (clone it to edit).
	Starter bool `json:"-"`
}

// Step is one card on the mission track.
type Step struct {
	RoleID      string   `json:"role"`                  // crew role id, or "binny" for a Captain task card
	Tasking     string   `json:"tasking,omitempty"`     // "" = the role's default from the objectives it owns
	Model       string   `json:"model,omitempty"`       // "" = session model; "provider/model" to cross providers
	TokenBudget int      `json:"tokenBudget,omitempty"` // 0 = an even share of what is left of the mission budget
	Focus       []string `json:"focus,omitempty"`       // objective ids, overriding the role's defaults
	Checkpoint  bool     `json:"checkpoint,omitempty"`  // pause AFTER this step
	Parallel    bool     `json:"parallel,omitempty"`    // run alongside the previous step
}

// HasRole reports whether any step uses the role.
func (m *Mission) HasRole(id string) bool {
	for _, s := range m.Steps {
		if strings.EqualFold(s.RoleID, id) {
			return true
		}
	}
	return false
}

// Clone returns a deep, editable copy under a new name.
func (m *Mission) Clone(name string) *Mission {
	c := *m
	c.Name = name
	c.Starter = false
	c.Steps = make([]Step, len(m.Steps))
	for i, s := range m.Steps {
		s.Focus = append([]string(nil), s.Focus...)
		c.Steps[i] = s
	}
	return &c
}

// ApplyAutonomy places checkpoints for a preset. Custom leaves them alone.
func (m *Mission) ApplyAutonomy(preset string) {
	switch strings.ToLower(preset) {
	case Autonomous:
		for i := range m.Steps {
			m.Steps[i].Checkpoint = false
		}
	case Supervised:
		for i := range m.Steps {
			m.Steps[i].Checkpoint = true
		}
	}
}

// AutonomyPreset reports which preset the checkpoint placement matches.
func (m *Mission) AutonomyPreset() string {
	n := 0
	for _, s := range m.Steps {
		if s.Checkpoint {
			n++
		}
	}
	switch {
	case n == 0:
		return Autonomous
	case n == len(m.Steps):
		return Supervised
	}
	return Custom
}

// Validate checks a mission is runnable: a name, known roles, and a first
// step that isn't marked parallel. knownRole is the engine's role lookup.
func (m *Mission) Validate(knownRole func(id string) bool) error {
	if strings.TrimSpace(m.Name) == "" {
		return errors.New("a mission needs a name")
	}
	if !m.Auto && len(m.Steps) == 0 {
		return errors.New("a mission needs at least one crew step")
	}
	for i, s := range m.Steps {
		id := strings.ToLower(strings.TrimSpace(s.RoleID))
		if id == "" {
			return fmt.Errorf("step %d has no crew member", i+1)
		}
		if id != CaptainID && knownRole != nil && !knownRole(id) {
			return fmt.Errorf("step %d: unknown crew member %q", i+1, s.RoleID)
		}
		if id == CaptainID && strings.TrimSpace(s.Tasking) == "" {
			return fmt.Errorf("step %d: a Captain task card needs tasking", i+1)
		}
		if s.Parallel && i == 0 {
			return errors.New("the first step can't run in parallel with a step before it")
		}
		if s.Parallel && (id == ParityID || strings.EqualFold(m.Steps[i-1].RoleID, ParityID)) {
			return fmt.Errorf("step %d: Parity verifies what the others found, so it can't run in parallel with them", i+1)
		}
		if s.TokenBudget < 0 {
			return fmt.Errorf("step %d: token budget can't be negative", i+1)
		}
	}
	return nil
}

// Default is what /investigate runs: the crew assembled from the loaded
// objectives, then Parity.
func Default() *Mission {
	return &Mission{
		Name:    "Default",
		Desc:    "Crew assembled from the objectives triage loads, then Parity verifies.",
		Auto:    true,
		Starter: true,
	}
}

// Starters are the shipped missions. They are read-only; Clone one to edit.
func Starters() []*Mission {
	return []*Mission{
		Default(),
		{
			Name: "Quick Triage", Starter: true,
			Desc:  "A fast first look: what it is and what it talks to. No verification pass.",
			Steps: []Step{{RoleID: "siggy"}, {RoleID: "twine"}},
		},
		{
			Name: "Full Malware", Starter: true,
			Desc:  "The whole crew, in order, with Parity before the report.",
			Steps: []Step{{RoleID: "siggy"}, {RoleID: "twine"}, {RoleID: "trace"}, {RoleID: "hex"}, {RoleID: ParityID}},
		},
		{
			Name: "Android", Starter: true,
			Desc:  "Dex leads on an APK; Hex recovers what the decoder hides.",
			Steps: []Step{{RoleID: "dex"}, {RoleID: "hex"}, {RoleID: ParityID}},
		},
		{
			Name: "Vuln Hunt", Starter: true,
			Desc: "Trace maps the surface, hunts memory and other sinks side by side, then proves the paths.",
			Steps: []Step{
				{RoleID: "trace", Focus: []string{"attack-surface", "input-surface"}},
				{RoleID: "trace", Focus: []string{"memory-sinks", "injection"}},
				{RoleID: "trace", Focus: []string{"other-sinks", "deserialization-traversal"}, Parallel: true},
				{RoleID: "trace", Focus: []string{"reachability", "exploitability"}},
				{RoleID: ParityID},
			},
		},
		{
			Name: "Config Extractor", Starter: true,
			Desc:  "Hex goes straight for the encrypted config; Parity checks what came out.",
			Steps: []Step{{RoleID: "hex"}, {RoleID: ParityID}},
		},
		{
			Name: "IOC Sweep", Starter: true,
			Desc:  "Twine pulls every indicator the strings and data give up; Parity checks them.",
			Steps: []Step{{RoleID: "twine"}, {RoleID: ParityID}},
		},
	}
}

func starter(name string) *Mission {
	for _, m := range Starters() {
		if strings.EqualFold(m.Name, name) || slug(m.Name) == slug(name) {
			return m
		}
	}
	return nil
}

// IsStarter reports whether a name belongs to a shipped mission.
func IsStarter(name string) bool { return starter(name) != nil }

// slug turns a mission name into a filename stem.
func slug(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	return strings.TrimRight(b.String(), "-")
}

func pathFor(name string) (string, error) {
	s := slug(name)
	if s == "" {
		return "", errors.New("a mission name needs at least one letter or digit")
	}
	dir, err := config.MissionsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, s+".json"), nil
}

// Save writes a mission to ~/.config/binny/missions/<name>.json. Starters are
// read-only: saving under a starter's name is refused.
func Save(m *Mission) error {
	if IsStarter(m.Name) {
		return fmt.Errorf("%q is a shipped mission and is read-only — save your version under another name", m.Name)
	}
	path, err := pathFor(m.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load returns a mission by name: a saved one first, else a starter.
func Load(name string) (*Mission, error) {
	if s := starter(name); s != nil {
		return s, nil
	}
	path, err := pathFor(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no mission named %q", name)
		}
		return nil, err
	}
	var m Mission
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("mission %q is not valid JSON: %w", name, err)
	}
	if strings.TrimSpace(m.Name) == "" {
		m.Name = name
	}
	return &m, nil
}

// Delete removes a saved mission. Starters can't be deleted.
func Delete(name string) error {
	if IsStarter(name) {
		return fmt.Errorf("%q is a shipped mission and can't be deleted", name)
	}
	path, err := pathFor(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no mission named %q", name)
		}
		return err
	}
	return nil
}

// List returns the starters followed by the saved missions, by name. A saved
// file that doesn't parse is skipped rather than failing the listing.
func List() []*Mission {
	out := Starters()
	dir, err := config.MissionsDir()
	if err != nil {
		return out
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	var saved []*Mission
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var m Mission
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		if strings.TrimSpace(m.Name) == "" {
			m.Name = strings.TrimSuffix(e.Name(), ".json")
		}
		if IsStarter(m.Name) {
			continue
		}
		saved = append(saved, &m)
	}
	sort.Slice(saved, func(i, j int) bool { return strings.ToLower(saved[i].Name) < strings.ToLower(saved[j].Name) })
	return append(out, saved...)
}
