package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"openbin.ai/binny/internal/tools"
)

// The vuln-mode record_finding. A vulnerability claim is only worth something
// if it says what the bug is (CWE), where attacker input comes from, what it
// reaches, how sure we are that it gets there, and how to fix it — so all of
// that is required, and severity is held to the evidence: high/critical needs
// a PROVEN source→sink path. Ruled-out candidates are recorded too; "we looked
// at this sink and it is not reachable" is a result, not a gap.

var (
	vulnSeverities  = []string{"info", "low", "medium", "high", "critical"}
	reachabilities  = []string{"proven", "likely", "unproven", "ruled_out"}
	reCWE           = regexp.MustCompile(`^(?i:cwe)?[-\s]?(\d{1,4})$`)
	reCVSS          = regexp.MustCompile(`^CVSS:(3\.[01]|4\.0)/[A-Z]{1,3}:[A-Z](/[A-Z]{1,3}:[A-Z])*$`)
	severityAtLeast = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
)

func recordVulnFindingTool(inv *Investigation) *tools.Tool {
	return &tools.Tool{
		Def: tools.Def("record_finding",
			"Record a vulnerability (or a candidate you investigated). Every field below is required except cvss and mitigations, and is checked: "+
				"cwe (e.g. CWE-787), severity, reachability, source, sink, path, remediation, and evidence_refs you actually observed. "+
				"Reachability is your honest verdict: `proven` = you traced attacker input to the sink hop by hop; `likely` = most of the path is established but a hop is inferred (indirect call, reflection, config-dependent); "+
				"`unproven` = a dangerous sink with no source→sink path found yet; `ruled_out` = you checked and it is NOT exploitable (record why — e.g. bounds-checked, not reachable, constant input). "+
				"high/critical severity requires reachability=proven and a non-empty path. Ruled-out candidates are recorded at severity info.",
			tools.Obj(map[string]any{
				"category":        tools.StrProp("the bug class, e.g. stack-overflow, heap-overflow, oob-read, integer-overflow, use-after-free, format-string, command-injection, sql-injection, path-traversal, insecure-deserialization, exported-component, intent-redirection, webview-js-bridge, hardcoded-secret, weak-crypto"),
				"cwe":             tools.StrProp("CWE id, e.g. CWE-787"),
				"severity":        tools.StrProp("info | low | medium | high | critical — held to the evidence, see reachability"),
				"reachability":    tools.StrProp("proven | likely | unproven | ruled_out"),
				"source":          tools.StrProp("where attacker-controlled input enters: an export / entry point / parser / exported component + the specific parameter, extra or field"),
				"sink":            tools.StrProp("the dangerous operation, with its location (function / file:line)"),
				"path":            tools.ArrProp("the source→sink hops in order, each a function or file:line (from reachability / find_usages / your trace). Empty only for unproven."),
				"controllability": tools.StrProp("what the attacker controls at the sink: length, content, index, a format string, a command fragment…"),
				"mitigations":     tools.StrProp("what stands in the way: stack canary, NX, PIE/ASLR, RELRO, FORTIFY, bounds check, input validation, permission guard, non-exported component…"),
				"remediation":     tools.StrProp("the concrete fix (e.g. bound the copy to sizeof(dst); mark the activity exported=false; use parameterized queries)"),
				"note":            tools.StrProp("the bug mechanism in plain language — for ruled_out, why it is not exploitable"),
				"cvss":            tools.StrProp("optional CVSS vector, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
				"evidence_refs":   tools.ArrProp("function names / addresses / file:line you observed that ground this"),
			}, "category", "cwe", "severity", "reachability", "source", "sink", "remediation", "note", "evidence_refs")),
		Handler: func(_ context.Context, input json.RawMessage) (string, error) {
			var a struct {
				Category        string   `json:"category"`
				CWE             string   `json:"cwe"`
				Severity        string   `json:"severity"`
				Reachability    string   `json:"reachability"`
				Source          string   `json:"source"`
				Sink            string   `json:"sink"`
				Path            []string `json:"path"`
				Controllability string   `json:"controllability"`
				Mitigations     string   `json:"mitigations"`
				Remediation     string   `json:"remediation"`
				Note            string   `json:"note"`
				CVSS            string   `json:"cvss"`
				EvidenceRefs    []string `json:"evidence_refs"`
			}
			if err := json.Unmarshal(input, &a); err != nil {
				return "", err
			}
			f, err := validateVulnFinding(Finding{
				Category: strings.TrimSpace(a.Category), CWE: a.CWE, Severity: a.Severity, Reachability: a.Reachability,
				Source: strings.TrimSpace(a.Source), Sink: strings.TrimSpace(a.Sink), Path: trimAll(a.Path),
				Controllability: strings.TrimSpace(a.Controllability), Mitigations: strings.TrimSpace(a.Mitigations),
				Remediation: strings.TrimSpace(a.Remediation), Note: strings.TrimSpace(a.Note),
				CVSS: strings.TrimSpace(a.CVSS), EvidenceRefs: trimAll(a.EvidenceRefs),
			})
			if err != nil {
				return "", err
			}
			if err := inv.AddFinding(f); err != nil {
				return "", err
			}
			return fmt.Sprintf("recorded %s %s [%s, reachability %s]", f.CWE, f.Category, f.Severity, f.Reachability), nil
		},
	}
}

// validateVulnFinding normalizes and checks a vuln finding. Errors are written
// for the model to act on: they say what to fix.
func validateVulnFinding(f Finding) (Finding, error) {
	var problems []string
	m := reCWE.FindStringSubmatch(strings.TrimSpace(f.CWE))
	if m == nil {
		problems = append(problems, fmt.Sprintf("cwe %q is not a CWE id (use e.g. CWE-787)", f.CWE))
	} else {
		f.CWE = "CWE-" + m[1]
	}
	f.Severity = strings.ToLower(strings.TrimSpace(f.Severity))
	if !contains(vulnSeverities, f.Severity) {
		problems = append(problems, fmt.Sprintf("severity %q must be one of %s", f.Severity, strings.Join(vulnSeverities, ", ")))
	}
	f.Reachability = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(f.Reachability), "-", "_"))
	if !contains(reachabilities, f.Reachability) {
		problems = append(problems, fmt.Sprintf("reachability %q must be one of %s", f.Reachability, strings.Join(reachabilities, ", ")))
	}
	for _, req := range []struct{ name, val string }{
		{"category", f.Category}, {"source", f.Source}, {"sink", f.Sink}, {"remediation", f.Remediation}, {"note", f.Note},
	} {
		if req.val == "" {
			problems = append(problems, req.name+" is required")
		}
	}
	if f.CVSS != "" && !reCVSS.MatchString(f.CVSS) {
		problems = append(problems, fmt.Sprintf("cvss %q is not a CVSS 3.x/4.0 vector (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — omit it rather than guess", f.CVSS))
	}
	if len(problems) > 0 {
		return f, fmt.Errorf("finding refused: %s", strings.Join(problems, "; "))
	}

	// Severity held to the evidence.
	switch {
	case f.Reachability == "ruled_out":
		f.Severity = "info"
	case severityAtLeast[f.Severity] >= severityAtLeast["high"] && f.Reachability != "proven":
		return f, fmt.Errorf("finding refused: severity %s needs reachability=proven — trace the source→sink path first (reachability / find_usages), or record it as %s at medium or below",
			f.Severity, f.Reachability)
	case f.Reachability == "proven" && len(f.Path) == 0:
		return f, fmt.Errorf("finding refused: reachability=proven needs the path — list the source→sink hops (function or file:line each)")
	}
	return f, nil
}

func trimAll(ss []string) []string {
	var out []string
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}
