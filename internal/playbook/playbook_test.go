package playbook

import "testing"

func TestVulnPlaybookForKind(t *testing.T) {
	cases := map[string]string{
		"BIN":    "Vuln — Native Binary",
		"SCRIPT": "Vuln — Script / Package",
		"APK":    "Vuln — Android (APK)",
		"":       "Vuln — Native Binary", // unknown kind → native fallback
		"WeIrD":  "Vuln — Native Binary",
	}
	for kind, want := range cases {
		if got := VulnPlaybookFor(kind).Name; got != want {
			t.Errorf("VulnPlaybookFor(%q) = %q, want %q", kind, got, want)
		}
	}
}

// SelectByTypes drives MALWARE analysis; it must never return a vuln playbook,
// even if a caller passes a stray type that happens to collide.
func TestSelectByTypesExcludesVulnPlaybooks(t *testing.T) {
	for _, types := range [][]string{
		{"ransomware"}, {"spyware"}, {"backdoor"}, {"unknown"}, {"trojan", "dropper"},
	} {
		for _, pb := range SelectByTypes(types) {
			if pb.vuln {
				t.Errorf("SelectByTypes(%v) returned vuln playbook %q", types, pb.Name)
			}
		}
	}
}

// Every vuln playbook must be flagged vuln (so SelectByTypes skips it) and carry
// a report template — a bare playbook would produce an empty VRR.
func TestVulnPlaybooksWellFormed(t *testing.T) {
	for _, kind := range []string{"BIN", "SCRIPT", "APK"} {
		pb := VulnPlaybookFor(kind)
		if !pb.vuln {
			t.Errorf("%s playbook not flagged vuln", pb.Name)
		}
		if len(pb.Objectives) == 0 || len(pb.Sections) == 0 {
			t.Errorf("%s playbook missing objectives or sections", pb.Name)
		}
	}
}

func TestBiasForAPK(t *testing.T) {
	for _, pb := range SelectByTypes([]string{"ransomware", "spyware", "backdoor", "trojan"}) {
		if pb.AndroidBias == "" {
			t.Errorf("%s has no AndroidBias", pb.Name)
		}
		if pb.BiasFor("APK") != pb.AndroidBias || pb.BiasFor("BIN") != pb.ToolBias {
			t.Errorf("%s: BiasFor picks the wrong hint", pb.Name)
		}
	}
	// A playbook without an Android variant falls back to its ToolBias.
	if got := VulnPlaybookFor("APK").BiasFor("APK"); got != VulnPlaybookFor("APK").ToolBias {
		t.Errorf("fallback BiasFor = %q", got)
	}
}
