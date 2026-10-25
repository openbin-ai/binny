package agent

import (
	"fmt"
	"sort"
	"strings"
)

// Vuln reporting helpers: rank the recorded vuln findings, assign stable
// advisory IDs, and pre-render the findings table + a CVE-style scaffold per
// finding so SYNTHESIZE fills prose into a deterministic structure instead of
// inventing its own layout (and its own IDs) each run.

var severityRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "": 0}

// rankedVulnFindings returns the vuln-schema findings worth advisories
// (everything except ruled_out), most-severe first; within a severity, proven
// before likely before unproven. Ruled-out findings are returned separately.
func rankedVulnFindings(findings []Finding) (advisories, ruledOut []Finding) {
	reachRank := map[string]int{"proven": 3, "likely": 2, "unproven": 1}
	for _, f := range findings {
		if !f.IsVuln() {
			continue
		}
		if f.Reachability == "ruled_out" {
			ruledOut = append(ruledOut, f)
		} else {
			advisories = append(advisories, f)
		}
	}
	sort.SliceStable(advisories, func(i, j int) bool {
		if si, sj := severityRank[advisories[i].Severity], severityRank[advisories[j].Severity]; si != sj {
			return si > sj
		}
		return reachRank[advisories[i].Reachability] > reachRank[advisories[j].Reachability]
	})
	return advisories, ruledOut
}

// advisoryID is the stable local id for the Nth-ranked finding (1-based).
func advisoryID(n int) string { return fmt.Sprintf("BINNY-VR-%03d", n) }

// vulnReportScaffold renders the findings table and a CVE-style skeleton for
// each advisory, from the recorded findings. IDs are assigned here so they're
// stable across the report. Returns "" when there are no vuln findings.
func vulnReportScaffold(snap InvestigationSnapshot) string {
	adv, ruled := rankedVulnFindings(snap.Findings)
	if len(adv) == 0 && len(ruled) == 0 {
		return ""
	}
	var b strings.Builder

	b.WriteString("FINDINGS TABLE — render exactly these rows (same IDs, severity order) as a Markdown table with columns | ID | Title | CWE | Severity | CVSS | Component | Reachability |:\n")
	for i, f := range adv {
		fmt.Fprintf(&b, "  %s | %s | %s | %s | %s | %s | %s\n",
			advisoryID(i+1), titleFor(f), f.CWE, f.Severity, orTBD(f.CVSS), orTBD(f.Sink), f.Reachability)
	}
	if len(adv) == 0 {
		b.WriteString("  (no exploitable findings — say so plainly)\n")
	}

	b.WriteString("\nPER-FINDING ADVISORIES — one CVE-style block per row above, in this exact shape (fill every field from the recorded evidence; keep the ID):\n")
	for i, f := range adv {
		id := advisoryID(i + 1)
		fmt.Fprintf(&b, "\n### %s — %s\n", id, titleFor(f))
		fmt.Fprintf(&b, "- **CWE:** %s\n", f.CWE)
		fmt.Fprintf(&b, "- **Severity:** %s%s\n", f.Severity, cvssSuffix(f))
		fmt.Fprintf(&b, "- **Reachability:** %s\n", f.Reachability)
		fmt.Fprintf(&b, "- **Affected component:** %s  (name the file/function + version/package if known)\n", orTBD(f.Sink))
		fmt.Fprintf(&b, "- **Source → sink:** %s → %s%s\n", orTBD(f.Source), orTBD(f.Sink), pathSuffix(f))
		if f.Controllability != "" {
			fmt.Fprintf(&b, "- **Attacker control:** %s\n", f.Controllability)
		}
		if f.Mitigations != "" {
			fmt.Fprintf(&b, "- **Mitigations present:** %s\n", f.Mitigations)
		}
		fmt.Fprintf(&b, "- **Description:** %s — EXPAND into a paragraph: the mechanism, the exact code (quote the decompiled lines), and why the input reaches it. Evidence: %s\n", f.Note, strings.Join(f.EvidenceRefs, ", "))
		fmt.Fprintf(&b, "- **Impact:** what an attacker gains if it fires.\n")
		fmt.Fprintf(&b, "- **Trigger conditions:** the preconditions/input shape that reaches the bug (describe it — do NOT write a weaponized exploit or payload).\n")
		fmt.Fprintf(&b, "- **Remediation:** %s\n", f.Remediation)
	}

	if len(ruled) > 0 {
		b.WriteString("\nINVESTIGATED AND RULED OUT — render as a section (a short table or list). These are negative results; keep them, they show coverage:\n")
		for _, f := range ruled {
			fmt.Fprintf(&b, "  - %s at %s — %s (why not exploitable: %s)\n", f.CWE, orTBD(f.Sink), titleFor(f), f.Note)
		}
	}
	return b.String()
}

func titleFor(f Finding) string {
	loc := f.Sink
	if i := strings.IndexAny(loc, " ("); i > 0 {
		loc = loc[:i]
	}
	cat := strings.ReplaceAll(f.Category, "-", " ")
	if loc != "" {
		return fmt.Sprintf("%s in %s", cat, loc)
	}
	return cat
}

func cvssSuffix(f Finding) string {
	if f.CVSS != "" {
		return " (" + f.CVSS + ")"
	}
	return " (compute a CVSS vector + base score and add it)"
}

func pathSuffix(f Finding) string {
	if len(f.Path) == 0 {
		return ""
	}
	return "  [path: " + strings.Join(f.Path, " → ") + "]"
}

func orTBD(s string) string {
	if strings.TrimSpace(s) == "" {
		return "TBD"
	}
	return s
}
