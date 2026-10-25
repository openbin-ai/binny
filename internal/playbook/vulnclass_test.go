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
