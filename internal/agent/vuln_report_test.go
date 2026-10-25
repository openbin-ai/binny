package agent

import (
	"strings"
	"testing"
)

func vulnFinding(cat, cwe, sev, reach, sink string, cvss string, path ...string) Finding {
	return Finding{
		Category: cat, CWE: cwe, Severity: sev, Reachability: reach,
		Source: "recv", Sink: sink, Path: path, CVSS: cvss,
		Remediation: "bound it", Note: "mechanism here", EvidenceRefs: []string{"fn"},
	}
}

func TestVulnReportScaffold(t *testing.T) {
	inv := NewInvestigation()
	// Intentionally out of severity order to test ranking.
	_ = inv.AddFinding(vulnFinding("path-traversal", "CWE-22", "medium", "likely", "openFile:40", ""))
	_ = inv.AddFinding(vulnFinding("stack-overflow", "CWE-121", "critical", "proven", "memcpy:88", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "a", "b"))
	ruled := vulnFinding("format-string", "CWE-134", "info", "ruled_out", "printf:12", "")
	_ = inv.AddFinding(ruled)
	out := vulnReportScaffold(inv.Snapshot())

	// Critical ranks first → BINNY-VR-001; medium second.
	i1 := strings.Index(out, "BINNY-VR-001")
	i2 := strings.Index(out, "BINNY-VR-002")
	if i1 < 0 || i2 < 0 || i1 > i2 {
		t.Fatalf("advisory IDs missing or misordered:\n%s", out)
	}
	if !strings.Contains(out, "BINNY-VR-001 | stack overflow in memcpy:88 | CWE-121 | critical | CVSS:3.1") {
		t.Errorf("table row for the critical finding wrong:\n%s", out)
	}
	for _, want := range []string{"### BINNY-VR-001", "**CWE:** CWE-121", "**Remediation:** bound it", "path: a → b", "INVESTIGATED AND RULED OUT", "CWE-134"} {
		if !strings.Contains(out, want) {
			t.Errorf("scaffold missing %q", want)
		}
	}
	// Ruled-out must NOT get an advisory ID.
	if strings.Contains(out, "BINNY-VR-003") {
		t.Errorf("ruled-out finding should not get an advisory block:\n%s", out)
	}
	// A finding with no CVSS gets the compute-it hint.
	if !strings.Contains(out, "compute a CVSS vector") {
		t.Errorf("missing CVSS prompt for the finding without one")
	}
}

func TestVulnReportScaffoldEmpty(t *testing.T) {
	if vulnReportScaffold(NewInvestigation().Snapshot()) != "" {
		t.Error("no findings should scaffold to empty")
	}
	// Malware-schema findings don't produce a vuln scaffold.
	inv := NewInvestigation()
	_ = inv.AddFinding(Finding{Category: "c2", Severity: "high", Note: "x", EvidenceRefs: []string{"fn"}})
	if vulnReportScaffold(inv.Snapshot()) != "" {
		t.Error("malware findings should not scaffold a vuln report")
	}
}
