package mission

import (
	"strings"
	"testing"
)

func known(id string) bool {
	switch id {
	case "siggy", "twine", "trace", "hex", "dex", "parity":
		return true
	}
	return false
}

func TestSaveLoadListDelete(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	m := &Mission{
		Name: "My Recon!", Tasking: "Stay on {sample}.", AllowAdd: true,
		Steps: []Step{
			{RoleID: "siggy", Checkpoint: true},
			{RoleID: "binny", Tasking: "Summarize what {findings} mean."},
			{RoleID: "trace", Focus: []string{"persistence"}, Model: "openai/gpt-x", TokenBudget: 30000, Parallel: true},
		},
	}
	if err := m.Validate(known); err != nil {
		t.Fatal(err)
	}
	if err := Save(m); err != nil {
		t.Fatal(err)
	}
	got, err := Load("my recon")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "My Recon!" || len(got.Steps) != 3 || !got.Steps[0].Checkpoint || got.Steps[2].Focus[0] != "persistence" ||
		got.Steps[2].Model != "openai/gpt-x" || !got.Steps[2].Parallel || !got.AllowAdd || got.Tasking != m.Tasking {
		t.Errorf("round trip lost something: %+v", got)
	}
	all := List()
	if last := all[len(all)-1]; last.Name != "My Recon!" || last.Starter {
		t.Errorf("saved mission should list after the starters: %+v", last)
	}
	if err := Delete("My Recon!"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("My Recon!"); err == nil {
		t.Error("deleted mission still loads")
	}
}

func TestStartersAreReadOnlyAndValid(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	want := []string{"Default", "Quick Triage", "Full Malware", "Android", "Vuln Hunt", "Config Extractor", "IOC Sweep"}
	ss := Starters()
	if len(ss) != len(want) {
		t.Fatalf("starters = %d", len(ss))
	}
	for i, s := range ss {
		if s.Name != want[i] || !s.Starter {
			t.Errorf("starter %d = %q", i, s.Name)
		}
		if err := s.Validate(known); err != nil {
			t.Errorf("%s: %v", s.Name, err)
		}
	}
	if err := Save(&Mission{Name: "full malware", Steps: []Step{{RoleID: "hex"}}}); err == nil {
		t.Error("saving over a starter must be refused")
	}
	if err := Delete("IOC Sweep"); err == nil {
		t.Error("deleting a starter must be refused")
	}
	// A clone is editable and saves under its own name.
	c, _ := Load("Quick Triage")
	mine := c.Clone("Quick Triage (mine)")
	mine.Steps = append(mine.Steps, Step{RoleID: "parity"})
	if err := Save(mine); err != nil {
		t.Fatal(err)
	}
	if again, _ := Load("Quick Triage"); len(again.Steps) != 2 {
		t.Error("editing a clone changed the starter")
	}
}

func TestValidateAndAutonomy(t *testing.T) {
	bad := map[string]*Mission{
		"name":          {Steps: []Step{{RoleID: "hex"}}},
		"at least one":  {Name: "x"},
		"unknown crew":  {Name: "x", Steps: []Step{{RoleID: "bob"}}},
		"needs tasking": {Name: "x", Steps: []Step{{RoleID: "binny"}}},
		"first step":    {Name: "x", Steps: []Step{{RoleID: "hex", Parallel: true}}},
		"Parity":        {Name: "x", Steps: []Step{{RoleID: "hex"}, {RoleID: "parity", Parallel: true}}},
	}
	for want, m := range bad {
		if err := m.Validate(known); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v", want, err)
		}
	}
	m := &Mission{Name: "x", Steps: []Step{{RoleID: "siggy"}, {RoleID: "twine", Checkpoint: true}}}
	if m.AutonomyPreset() != Custom {
		t.Errorf("preset = %s", m.AutonomyPreset())
	}
	m.ApplyAutonomy(Supervised)
	if !m.Steps[0].Checkpoint || m.AutonomyPreset() != Supervised {
		t.Error("supervised = a checkpoint after every step")
	}
	m.ApplyAutonomy(Autonomous)
	if m.Steps[1].Checkpoint || m.AutonomyPreset() != Autonomous {
		t.Error("autonomous = no checkpoints")
	}
}
