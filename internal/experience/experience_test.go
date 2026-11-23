package experience

import (
	"strings"
	"testing"
)

func TestOnlyMethodIsKept(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, bad := range []string{
		"The C2 is 10.2.3.4 on port 443.",
		"It beacons to http://evil.example/gate.php",
		"This sample is malicious and drops a miner.",
		"Config is decrypted in FUN_00401a20.",
		"Payload hash d41d8cd98f00b204e9800998ecf8427e matches the dropper.",
		"Contacts update.badhost.ru for commands.",
	} {
		if _, err := Add(Note{TargetType: "t", Lesson: bad}); err == nil {
			t.Errorf("a conclusion was accepted as experience: %q", bad)
		}
	}
	n, err := Add(Note{TargetType: "WiFi driver", Kind: "BIN", Mode: "VULN_RESEARCH", Role: "trace",
		Lesson: "In WiFi drivers, the ioctl handler is the attacker-reachable entry — trace from there."})
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := Add(n); again.ID != n.ID || len(All()) != 1 {
		t.Error("the same lesson should not be saved twice")
	}
	if _, err := Update(n.ID[:4], "The C2 is 1.2.3.4"); err == nil {
		t.Error("an edit can't turn a lesson into a conclusion")
	}
	if up, err := Update(n.ID[:4], "In WiFi drivers start at the ioctl dispatch table."); err != nil || !strings.Contains(All()[0].Lesson, "dispatch table") {
		t.Errorf("edit: %+v %v", up, err)
	}
	if err := Delete(n.ID); err != nil || len(All()) != 0 {
		t.Errorf("prune failed: %v", err)
	}
}

func TestScoping(t *testing.T) {
	wifi := Note{Kind: "BIN", Mode: "VULN_RESEARCH", Role: "trace", Lesson: "x"}
	if wifi.Applies(Target{Kind: "APK", Mode: "VULN_RESEARCH"}, "trace") {
		t.Error("a driver lesson must never fire on an APK")
	}
	if wifi.Applies(Target{Kind: "BIN", Mode: "MALWARE"}, "trace") {
		t.Error("a vuln-research lesson must not fire on a malware run")
	}
	if wifi.Applies(Target{Kind: "BIN", Mode: "VULN_RESEARCH"}, "hex") {
		t.Error("a lesson for Trace is not for Hex")
	}
	if !wifi.Applies(Target{Kind: "BIN", Mode: "VULN_RESEARCH"}, "trace") {
		t.Error("in-scope lesson should apply")
	}
	rw := Note{Kind: "BIN", Mode: "MALWARE", Types: []string{"ransomware"}, Lesson: "x"}
	if rw.Applies(Target{Kind: "BIN", Mode: "MALWARE", Types: []string{"spyware"}}, "hex") {
		t.Error("a ransomware lesson must not fire on spyware")
	}
	if !rw.Applies(Target{Kind: "BIN", Mode: "MALWARE", Types: []string{"trojan", "Ransomware"}}, "hex") {
		t.Error("multi-label classification should match")
	}
	if got := (Target{Kind: "BIN", Mode: "MALWARE", Types: []string{"wiper", "ransomware"}}).Label(); got != "ransomware+wiper · BIN" {
		t.Errorf("label = %q", got)
	}
}
