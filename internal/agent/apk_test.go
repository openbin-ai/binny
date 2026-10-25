package agent

import (
	"strings"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/playbook"
)

func apkSession(mode app.Mode) *app.Session {
	return &app.Session{
		Mode: mode, Autonomy: app.Supervised, Model: "test", Config: &config.Config{},
		Project: &api.Project{ID: "p1", Name: "evil.apk", Kind: api.KindAPK, Status: "READY"},
	}
}

// An APK session must not be told to orient with native-only tools it
// doesn't have — that's what sent APK triage into a wall of tool errors.
func TestAPKPromptsAvoidNativeTools(t *testing.T) {
	sys := systemPrompt(app.ModeMalware, app.Supervised, true, api.KindAPK)
	for _, native := range []string{"prefer get_metadata, get_imports, and get_strings", "readelf -S", "read_data <symbol>", "decompile_sample", "MULTI-SAMPLE"} {
		if strings.Contains(sys, native) {
			t.Errorf("APK system prompt mentions native-only guidance %q", native)
		}
	}
	for _, want := range []string{"ANDROID (APK) PROJECTS", "get_manifest", "unzip -o /sample"} {
		if !strings.Contains(sys, want) {
			t.Errorf("APK system prompt missing %q", want)
		}
	}

	triage := triageKickoff(apkSession(app.ModeMalware), nil)
	if strings.Contains(triage, "get_imports") || strings.Contains(triage, "get_strings") {
		t.Errorf("APK triage kickoff points at native tools:\n%s", triage)
	}
	if !strings.Contains(triage, "get_manifest") || !strings.Contains(triage, "set_classification") {
		t.Errorf("APK triage kickoff missing manifest orientation / classification:\n%s", triage)
	}

	vuln := triageKickoff(apkSession(app.ModeVuln), nil)
	if !strings.Contains(vuln, "get_manifest exported_only=true") {
		t.Errorf("APK vuln kickoff should start from exported components:\n%s", vuln)
	}
}

func TestBINPromptUnchanged(t *testing.T) {
	mal := systemPrompt(app.ModeMalware, app.Supervised, true, api.KindBIN)
	for _, want := range []string{"prefer get_metadata, get_imports, and get_strings", "readelf -S", "MULTI-SAMPLE"} {
		if !strings.Contains(mal, want) {
			t.Errorf("BIN malware prompt lost %q", want)
		}
	}
	sys := systemPrompt(app.ModeVuln, app.Supervised, true, api.KindBIN)
	for _, want := range []string{"prefer get_metadata, get_imports, and get_strings", "MULTI-SAMPLE", "`reachability` tool"} {
		if !strings.Contains(sys, want) {
			t.Errorf("BIN system prompt lost %q", want)
		}
	}
	if strings.Contains(sys, "ANDROID (APK) PROJECTS") {
		t.Error("BIN system prompt carries the Android block")
	}
}

func TestInvestigateBriefUsesAndroidBias(t *testing.T) {
	pbs := playbook.SelectByTypes([]string{"spyware"})
	apk := investigateBrief(pbs, nil, api.KindAPK, app.ModeMalware, nil)
	if !strings.Contains(apk, "READ_SMS") || strings.Contains(apk, "Login Data") {
		t.Errorf("APK brief should carry the Android bias, not the Windows one:\n%s", apk)
	}
	if !strings.Contains(apk, "Application class's onCreate") {
		t.Errorf("APK brief should start the narrative at manifest entry points:\n%s", apk)
	}
	bin := investigateBrief(pbs, nil, api.KindBIN, app.ModeMalware, nil)
	if !strings.Contains(bin, "Login Data") || !strings.Contains(bin, "get_function on main") {
		t.Errorf("BIN brief changed:\n%s", bin)
	}
}

func TestSplitFileLine(t *testing.T) {
	cases := []struct{ in, path, line string }{
		{"sources/a/B.java:42", "sources/a/B.java", "42"},
		{"sources/a/B.java", "sources/a/B.java", ""},
		{"C:/x/B.java", "C:/x/B.java", ""},
		{"sources/a/B.java:", "sources/a/B.java:", ""},
	}
	for _, c := range cases {
		p, l := splitFileLine(c.in)
		if p != c.path || l != c.line {
			t.Errorf("splitFileLine(%q) = (%q, %q), want (%q, %q)", c.in, p, l, c.path, c.line)
		}
	}
}

func TestInvestigateBriefScopedVsSurvey(t *testing.T) {
	pb, classes := playbook.VulnPlaybookForFocus("BIN", []string{"memory"})
	if len(classes) != 1 || classes[0].Key != "memory" {
		t.Fatalf("focus resolution = %+v", classes)
	}
	scoped := investigateBrief([]playbook.Playbook{pb}, nil, api.KindBIN, app.ModeVuln, []string{"memory"})
	if !strings.Contains(scoped, "SCOPED HUNT") || !strings.Contains(scoped, "memory") {
		t.Errorf("scoped brief missing scope notice:\n%s", scoped)
	}
	if !strings.Contains(scoped, "input-bounded loop") || !strings.Contains(scoped, "SOURCE→SINK") {
		t.Errorf("scoped brief should carry the memory recipe + audit method:\n%s", scoped)
	}
	survey := investigateBrief([]playbook.Playbook{playbook.VulnPlaybookFor("BIN")}, nil, api.KindBIN, app.ModeVuln, nil)
	if !strings.Contains(survey, "SURVEY") {
		t.Errorf("unfocused brief should say survey:\n%s", survey)
	}
}
