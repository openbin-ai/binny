package playbook

import "testing"

func TestLookupVulnClass(t *testing.T) {
	cases := map[string]string{
		"memory": "memory", "buffer-overflow": "memory", "BOF": "memory",
		"use after free": "memory", "memory safety": "memory",
		"sqli": "injection-data", "command": "command-injection", "rce": "command-injection",
		"weak crypto": "crypto", "encryption": "crypto", "hardcoded": "secrets",
		"authz": "auth", "toctou": "race", "webview": "android-components",
	}
	for in, want := range cases {
		c, ok := LookupVulnClass(in)
		if !ok || c.Key != want {
			t.Errorf("LookupVulnClass(%q) = (%q,%v), want %q", in, c.Key, ok, want)
		}
	}
	if _, ok := LookupVulnClass("not-a-bug-class"); ok {
		t.Error("unknown token should not resolve")
	}
	if _, ok := LookupVulnClass(""); ok {
		t.Error("empty token should not resolve")
	}
}

func TestVulnClassesWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range VulnClasses() {
		if c.Key == "" || c.Name == "" || len(c.CWEs) == 0 || len(c.Objectives) == 0 {
			t.Errorf("class %q is missing required fields", c.Key)
		}
		if c.Hunt == "" && c.HuntAPK == "" {
			t.Errorf("class %q has no recipe", c.Key)
		}
		if seen[c.Key] {
			t.Errorf("duplicate class key %q", c.Key)
		}
		seen[c.Key] = true
		if c.HuntFor("APK") == "" || c.HuntFor("BIN") == "" || c.HuntFor("SCRIPT") == "" {
			t.Errorf("class %q resolves to an empty recipe for some kind", c.Key)
		}
	}
}

func TestDetectVulnIntent(t *testing.T) {
	yes := []string{
		"this is a vulnerability research engagement, find memory bugs",
		"look for buffer overflows in the parser",
		"security audit of the exported components",
		"hunt for sql injection and hardcoded secrets",
	}
	for _, s := range yes {
		if ok, _ := DetectVulnIntent(s); !ok {
			t.Errorf("DetectVulnIntent(%q) = false, want true", s)
		}
	}
	no := []string{
		"this is ransomware, classify it and pull IOCs",
		"analyze the C2 protocol and recover the config",
		"",
	}
	for _, s := range no {
		if ok, _ := DetectVulnIntent(s); ok {
			t.Errorf("DetectVulnIntent(%q) = true, want false", s)
		}
	}
}

func TestDetectVulnClasses(t *testing.T) {
	got := DetectVulnClasses("look for buffer overflows and weak crypto, also any hardcoded secrets")
	want := map[string]bool{"memory": true, "crypto": true, "secrets": true}
	if len(got) != 3 {
		t.Fatalf("got %v, want 3 classes", got)
	}
	for _, k := range got {
		if !want[k] {
			t.Errorf("unexpected class %q", k)
		}
	}
	if len(DetectVulnClasses("just have a look around")) != 0 {
		t.Error("no class words should detect none")
	}
}
