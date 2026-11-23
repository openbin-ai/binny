package tui

import (
	"strings"
	"testing"

	"openbin.ai/binny/internal/mission"
)

func text(ls []line) string {
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.text + "\n")
	}
	return b.String()
}

func TestCrewLinesCarryANameTag(t *testing.T) {
	out := toolLine("get_function main").by("hex").render(80)
	if !strings.Contains(out, "[hex]") || !strings.Contains(out, "get_function main") {
		t.Errorf("crew line should lead with its tag: %q", out)
	}
	if plain := toolLine("get_function main").render(80); strings.Contains(plain, "[") {
		t.Errorf("BINNY's own lines carry no tag: %q", plain)
	}
}

func TestMissionSketchAndPick(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	m := newTestModel()

	if out := text(m.newMission([]string{"Recon", "siggy", "twine+", "|trace", "parity"})); !strings.Contains(out, "Siggy → Twine ⏸ ‖ Trace → Parity") {
		t.Errorf("sketch: %s", out)
	}
	ms, err := mission.Load("Recon")
	if err != nil || !ms.Steps[1].Checkpoint || !ms.Steps[2].Parallel {
		t.Fatalf("saved sketch: %+v %v", ms, err)
	}
	if out := text(m.newMission([]string{"Bad", "siggy", "bob"})); !strings.Contains(out, "unknown crew member") {
		t.Errorf("unknown crew should be refused: %s", out)
	}
	if out := text(m.newMission([]string{"NoCheck", "siggy"})); !strings.Contains(out, "unverified") {
		t.Errorf("a mission without Parity should warn: %s", out)
	}

	// Default until one is picked; solo opts out of the crew.
	if m.missionChoice().Name != "Default" {
		t.Errorf("default mission = %q", m.missionChoice().Name)
	}
	m.cmdMission([]string{"solo"})
	if !m.soloRun {
		t.Error("/mission solo should select a crew-less run")
	}
	if out := text(m.cmdMissions()); !strings.Contains(out, "Full Malware") || !strings.Contains(out, "Recon") {
		t.Errorf("/missions should list starters and saved: %s", out)
	}
	if out := text(m.cmdCrew()); !strings.Contains(out, "Parity") || !strings.Contains(out, "Skeptic") {
		t.Errorf("/crew before a run shows the lineup: %s", out)
	}
}

func TestPickIndexes(t *testing.T) {
	if got := pickIndexes([]string{"2,1", "9", "x", "2"}, 3); len(got) != 2 || got[0] != 1 || got[1] != 0 {
		t.Errorf("got %v", got)
	}
	if got := pickIndexes([]string{"all"}, 3); len(got) != 3 {
		t.Errorf("all → %v", got)
	}
}
