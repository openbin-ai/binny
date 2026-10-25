package agent

import (
	"strings"
	"testing"
)

func TestValidateVulnFinding(t *testing.T) {
	base := func() Finding {
		return Finding{
			Category: "stack-overflow", CWE: "cwe-121", Severity: "medium", Reachability: "likely",
			Source: "recv() in handle_conn", Sink: "memcpy in parse_hdr:88",
			Remediation: "bound the copy to sizeof(dst)", Note: "len from header, unchecked",
			EvidenceRefs: []string{"parse_hdr"},
		}
	}
	// Happy path normalizes CWE and keeps severity.
	if f, err := validateVulnFinding(base()); err != nil || f.CWE != "CWE-121" {
		t.Fatalf("valid finding rejected: %v (cwe=%q)", err, f.CWE)
	}
	// high/critical without proven+path is refused.
	f := base()
	f.Severity = "critical"
	if _, err := validateVulnFinding(f); err == nil || !strings.Contains(err.Error(), "reachability=proven") {
		t.Errorf("critical without proof should be refused, got %v", err)
	}
	// proven requires a path.
	f = base()
	f.Severity, f.Reachability = "high", "proven"
	if _, err := validateVulnFinding(f); err == nil || !strings.Contains(err.Error(), "needs the path") {
		t.Errorf("proven without path should be refused, got %v", err)
	}
	// proven+path+high is allowed.
	f = base()
	f.Severity, f.Reachability, f.Path = "high", "proven", []string{"handle_conn", "parse_hdr:88"}
	if _, err := validateVulnFinding(f); err != nil {
		t.Errorf("proven high with path should pass: %v", err)
	}
	// ruled_out is forced to info.
	f = base()
	f.Reachability, f.Severity = "ruled_out", "high"
	if got, err := validateVulnFinding(f); err != nil || got.Severity != "info" {
		t.Errorf("ruled_out should drop to info: sev=%q err=%v", got.Severity, err)
	}
	// Missing required fields and bad CWE are reported.
	f = base()
	f.CWE, f.Source, f.Remediation = "oops", "", ""
	_, err := validateVulnFinding(f)
	if err == nil {
		t.Fatal("expected refusal")
	}
	for _, want := range []string{"cwe", "source is required", "remediation is required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
	// Bad CVSS is rejected; empty CVSS is fine.
	f = base()
	f.CVSS = "not-a-vector"
	if _, err := validateVulnFinding(f); err == nil || !strings.Contains(err.Error(), "cvss") {
		t.Errorf("bad cvss should be refused, got %v", err)
	}
}
