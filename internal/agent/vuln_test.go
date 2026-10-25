package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"openbin.ai/binny/internal/app"
)

// TestRecordFindingCWE covers the vuln-finding path: a CWE flows through the
// tool into the investigation and surfaces in the evidence summary.
func TestRecordFindingCWE(t *testing.T) {
	inv := NewInvestigation()
	tool := recordFindingTool(inv)
	out, err := tool.Handler(context.Background(), json.RawMessage(
		`{"category":"stack-overflow","severity":"high","cwe":"CWE-787","note":"unchecked memcpy reachable from handle_request","evidence_refs":["copy_field"]}`))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "CWE-787") {
		t.Errorf("tool ack should mention the CWE, got %q", out)
	}
	if len(inv.Findings) != 1 || inv.Findings[0].CWE != "CWE-787" {
		t.Fatalf("CWE not stored on finding: %+v", inv.Findings)
	}
	if !strings.Contains(inv.Snapshot().EvidenceSummary(), "CWE-787") {
		t.Error("evidence summary should surface the CWE")
	}
}

// TestVulnSynthesizeBriefIsVRR confirms vuln mode gets the VRR brief (CWE /
// source→sink framing), not the malware execution-narrative brief.
func TestVulnSynthesizeBriefIsVRR(t *testing.T) {
	snap := (&Investigation{}).Snapshot()
	vuln := synthesizeBrief(app.ModeVuln, nil, snap)
	for _, want := range []string{"Vulnerability Research Report", "CVE-style advisories", "[advisories]", "CVSS 3.1"} {
		if !strings.Contains(vuln, want) {
			t.Errorf("vuln synthesize brief missing %q:\n%s", want, vuln)
		}
	}
	mal := synthesizeBrief(app.ModeMalware, nil, snap)
	if strings.Contains(mal, "Vulnerability Research Report") {
		t.Error("malware synthesize brief should not be the VRR brief")
	}
}
