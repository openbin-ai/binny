package agent

import (
	"strings"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/mission"
)

// The captain must know its crew in every prompt it runs under, so a crew
// name in a question is read as the crew member.
func TestCaptainKnowsTheCrew(t *testing.T) {
	for _, kind := range []api.ProjectKind{api.KindBIN, api.KindAPK} {
		for _, mode := range []app.Mode{app.ModeMalware, app.ModeVuln} {
			sys := systemPrompt(mode, app.Supervised, true, kind)
			for _, r := range Roles() {
				if !strings.Contains(sys, "- "+r.Name+" — ") {
					t.Errorf("%s/%s captain prompt doesn't list %s", kind, mode, r.Name)
				}
			}
			if !strings.Contains(sys, "not the DEX file format") || !strings.Contains(sys, "never invent what a crewmate said") {
				t.Errorf("%s/%s captain prompt is missing the crew-name / no-invention rules", kind, mode)
			}
		}
	}
}

// Every crew member has a voice and a blurb, knows its crewmates (not itself
// as a crewmate), and is told the voice stays out of what it records.
func TestCrewKnowEachOther(t *testing.T) {
	if Captain.Voice == "" || Captain.Blurb == "" {
		t.Error("the captain has no voice or blurb")
	}
	for _, r := range Roles() {
		if r.Voice == "" || r.Blurb == "" {
			t.Errorf("%s has no voice or blurb", r.Name)
		}
		sys := crewSystem("BASE", r)
		if !strings.Contains(sys, r.Voice) || !strings.Contains(sys, voiceRule) {
			t.Errorf("%s's prompt is missing its voice or the voice rule", r.Name)
		}
		for _, mate := range Lineup() {
			listed := strings.Contains(sys, "- "+mate.Name+" — "+mate.Blurb)
			if mate.ID == r.ID && listed {
				t.Errorf("%s is listed as its own crewmate", r.Name)
			}
			if mate.ID != r.ID && !listed {
				t.Errorf("%s's prompt doesn't list %s", r.Name, mate.Name)
			}
		}
	}
	// A Captain task card adds nothing: the base prompt already has the brief.
	if got := crewSystem("BASE", Captain); strings.Contains(got, "YOUR CREWMATES") {
		t.Error("captain task card repeats the roster")
	}
}

func TestHandoffs(t *testing.T) {
	debrief := "Pulled 4 hosts from the strings.\n" +
		"- HANDOFF: Hex — 0x40-byte blob at DAT_00412a00, XOR-decoded in FUN_00401a30\n" +
		"handoff: trace: who calls FUN_00401a30?\n" +
		"HANDOFF: Twine — talking to myself\n" +
		"HANDOFF: Nobody — not on the crew\n" +
		"HANDOFF: captain - packed section .upx0 means the classification may be off\n"
	rest, hs := HandoffsFrom(debrief, "twine")
	want := []Handoff{
		{"hex", "0x40-byte blob at DAT_00412a00, XOR-decoded in FUN_00401a30"},
		{"trace", "who calls FUN_00401a30?"},
		{CaptainID, "packed section .upx0 means the classification may be off"},
	}
	if len(hs) != len(want) {
		t.Fatalf("handoffs = %+v", hs)
	}
	for i := range want {
		if hs[i] != want[i] {
			t.Errorf("handoff %d = %+v, want %+v", i, hs[i], want[i])
		}
	}
	// Lines that name nobody on the crew, or the writer, stay in the debrief.
	if !strings.Contains(rest, "Pulled 4 hosts") || !strings.Contains(rest, "talking to myself") || !strings.Contains(rest, "not on the crew") || strings.Contains(rest, "DAT_00412a00") {
		t.Errorf("debrief after handoffs = %q", rest)
	}
	if same, none := HandoffsFrom("nothing to pass on", "twine"); same != "nothing to pass on" || none != nil {
		t.Errorf("no-handoff debrief changed: %q %+v", same, none)
	}

	log := []StepRecord{{RoleID: "twine", Name: "Twine", Status: "done", Handoffs: hs}}
	if got := HandoffsFor("hex", log); !strings.Contains(got, "from Twine: 0x40-byte blob") || strings.Contains(got, "who calls") {
		t.Errorf("Hex's handoffs = %q", got)
	}
	if got := HandoffsFor("siggy", log); got != "" {
		t.Errorf("Siggy was left nothing, got %q", got)
	}
	if got := HandoffLines(hs); !strings.Contains(got, "handoff for Hex: ") || !strings.Contains(got, "handoff for BINNY: ") {
		t.Errorf("rendered handoffs = %q", got)
	}
}

func TestMissionCrewLine(t *testing.T) {
	steps := []mission.Step{{RoleID: "siggy"}, {RoleID: "twine"}, {RoleID: "hex"}, {RoleID: "parity"}}
	got := MissionCrewLine(steps, 2, "twine")
	if !strings.Contains(got, "Ahead of you on this mission: Siggy.") || !strings.Contains(got, "you: Hex, Parity") || strings.Contains(got, "Twine") {
		t.Errorf("step 2 = %q", got)
	}
	if got := MissionCrewLine(steps, 4, "parity"); !strings.Contains(got, "last one out") {
		t.Errorf("last step = %q", got)
	}
	if got := MissionCrewLine(steps, 0, "parity"); got != "" {
		t.Errorf("interim pass = %q", got)
	}
}
