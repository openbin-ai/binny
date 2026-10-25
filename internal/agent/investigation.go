package agent

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Investigation is the mutable, evidence-grounded state BINNY accumulates while
// working a sample: findings, IOCs, a classification, per-objective coverage,
// and draft report sections. The output tools write here; SYNTHESIZE reads
// here. It is guarded by a mutex because tool handlers run from the agent
// goroutine while the TUI may read it to render status.
//
// EVIDENCE-GROUNDING is enforced at write time: record_finding and add_ioc
// REQUIRE at least one evidence ref (a function name, string, or address).
// Uncited findings/IOCs are refused, so SYNTHESIZE can never emit a
// hallucinated C2 / IOC.
type Investigation struct {
	mu sync.Mutex

	Findings       []Finding
	IOCs           []IOC
	MalwareTypes   []string // STIX types (multi-label)
	Confidence     string
	Sections       []ReportSection
	Objectives     []Objective
	Artifacts      []Artifact // extraction outputs (scripts, decrypted blobs)
	RenameProposal []RenameSuggestion
}

// Finding is one evidence-grounded observation.
type Finding struct {
	Category     string   // e.g. "persistence", "c2", "crypto" (malware) or a bug class (vuln)
	Severity     string   // info|low|medium|high|critical
	Note         string   // human-readable description
	CWE          string   // CWE id for vuln findings, e.g. "CWE-787"
	EvidenceRefs []string // fn names / strings / addresses that ground it

	// Vulnerability-research fields (set by the vuln-mode record_finding, which
	// requires them; empty on malware findings).
	Reachability    string   // proven | likely | unproven | ruled_out
	Source          string   // where attacker-controlled input enters
	Sink            string   // the dangerous operation it reaches
	Path            []string // source→sink hops, each a function / file:line
	Controllability string   // what the attacker controls at the sink (size, content, index…)
	Mitigations     string   // what stands in the way (canary, NX, validation, permission…)
	Remediation     string   // how to fix it
	CVSS            string   // optional CVSS vector, e.g. CVSS:3.1/AV:N/…
}

// IsVuln reports whether a finding came through the vuln-mode schema.
func (f Finding) IsVuln() bool { return f.Reachability != "" }

// IOC is an indicator of compromise, each tied to one evidence ref.
type IOC struct {
	Type        string // ip|domain|url|hash|path|mutex|registry|email|…
	Value       string
	EvidenceRef string
}

// ReportSection is a draft report section (id/title/content), matching the
// backend ProjectReport shape.
type ReportSection struct {
	ID      string
	Title   string
	Content string
}

// Objective is one item of the loaded playbook's work list, with coverage.
type Objective struct {
	ID        string
	Desc      string
	Covered   bool
	ToolCalls int // tool calls spent on this objective
}

// Artifact is a file produced during extraction (a script or a decrypted blob).
type Artifact struct {
	Path        string
	Kind        string // "script" | "decrypted" | "other"
	Description string
	Bytes       []byte
}

// RenameSuggestion is a proposed function rename (applied via the backend).
type RenameSuggestion struct {
	Original  string
	Suggested string
	Rationale string
}

// NewInvestigation returns an empty investigation.
func NewInvestigation() *Investigation { return &Investigation{} }

// AddFinding records an evidence-grounded finding. Returns an error (surfaced
// to the LLM) if no evidence ref is supplied — the grounding guarantee.
func (inv *Investigation) AddFinding(f Finding) error {
	if len(f.EvidenceRefs) == 0 {
		return fmt.Errorf("finding refused: at least one evidence_ref (function, string, address, or file:line) is required — every finding must be grounded")
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.Findings = append(inv.Findings, f)
	return nil
}

// AddIOC records an indicator. Returns an error if no evidence ref is supplied.
func (inv *Investigation) AddIOC(i IOC) error {
	if strings.TrimSpace(i.EvidenceRef) == "" {
		return fmt.Errorf("IOC refused: an evidence_ref is required — every IOC must cite where it was found")
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.IOCs = append(inv.IOCs, i)
	return nil
}

// SetClassification records the multi-label STIX classification + confidence.
func (inv *Investigation) SetClassification(types []string, confidence string) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.MalwareTypes = types
	inv.Confidence = confidence
}

// WriteSection upserts a report section by id.
func (inv *Investigation) WriteSection(s ReportSection) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	for i := range inv.Sections {
		if inv.Sections[i].ID == s.ID {
			inv.Sections[i] = s
			return
		}
	}
	inv.Sections = append(inv.Sections, s)
}

// SetObjectives replaces the objective list (called when a playbook loads).
func (inv *Investigation) SetObjectives(objs []Objective) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.Objectives = objs
}

// MarkObjective marks an objective covered by id (case-insensitive).
func (inv *Investigation) MarkObjective(id string) bool {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	for i := range inv.Objectives {
		if strings.EqualFold(inv.Objectives[i].ID, id) {
			inv.Objectives[i].Covered = true
			return true
		}
	}
	return false
}

// Coverage returns (covered, total) objectives.
func (inv *Investigation) Coverage() (int, int) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	covered := 0
	for _, o := range inv.Objectives {
		if o.Covered {
			covered++
		}
	}
	return covered, len(inv.Objectives)
}

// AddArtifact records an extraction artifact.
func (inv *Investigation) AddArtifact(a Artifact) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.Artifacts = append(inv.Artifacts, a)
}

// AddRename records a proposed rename.
func (inv *Investigation) AddRename(r RenameSuggestion) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.RenameProposal = append(inv.RenameProposal, r)
}

// Snapshot returns a copy-safe summary for rendering (avoids holding the lock
// while the caller formats). Slices are shallow-copied.
func (inv *Investigation) Snapshot() InvestigationSnapshot {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	return InvestigationSnapshot{
		Findings:     append([]Finding(nil), inv.Findings...),
		IOCs:         append([]IOC(nil), inv.IOCs...),
		MalwareTypes: append([]string(nil), inv.MalwareTypes...),
		Confidence:   inv.Confidence,
		Sections:     append([]ReportSection(nil), inv.Sections...),
		Objectives:   append([]Objective(nil), inv.Objectives...),
		Artifacts:    append([]Artifact(nil), inv.Artifacts...),
	}
}

// InvestigationSnapshot is an immutable view for rendering / synthesis.
type InvestigationSnapshot struct {
	Findings     []Finding
	IOCs         []IOC
	MalwareTypes []string
	Confidence   string
	Sections     []ReportSection
	Objectives   []Objective
	Artifacts    []Artifact
}

// EvidenceSummary renders findings + IOCs + classification compactly, for
// feeding into the SYNTHESIZE prompt and status displays.
func (s InvestigationSnapshot) EvidenceSummary() string {
	var b strings.Builder
	if len(s.MalwareTypes) > 0 {
		fmt.Fprintf(&b, "Classification: %s (confidence: %s)\n", strings.Join(s.MalwareTypes, ", "), orUnknown(s.Confidence))
	}
	if !vulnSummary(&b, s.Findings) && len(s.Findings) > 0 {
		b.WriteString("\nFindings:\n")
		for _, f := range s.Findings {
			cwe := ""
			if f.CWE != "" {
				cwe = " " + f.CWE
			}
			fmt.Fprintf(&b, "- [%s/%s%s] %s (evidence: %s)\n",
				f.Category, f.Severity, cwe, f.Note, strings.Join(f.EvidenceRefs, ", "))
		}
	}
	if len(s.IOCs) > 0 {
		b.WriteString("\nIOCs:\n")
		for _, i := range s.IOCs {
			fmt.Fprintf(&b, "- %s: %s (evidence: %s)\n", i.Type, i.Value, i.EvidenceRef)
		}
	}
	if len(s.Artifacts) > 0 {
		b.WriteString("\nArtifacts:\n")
		for _, a := range s.Artifacts {
			fmt.Fprintf(&b, "- %s [%s]: %s\n", a.Path, a.Kind, a.Description)
		}
	}
	return b.String()
}

// CoverageLine renders "N/M objectives" with the uncovered ones listed.
func (s InvestigationSnapshot) CoverageLine() string {
	if len(s.Objectives) == 0 {
		return "no objectives loaded"
	}
	covered := 0
	var pending []string
	for _, o := range s.Objectives {
		if o.Covered {
			covered++
		} else {
			pending = append(pending, o.ID)
		}
	}
	line := fmt.Sprintf("%d/%d objectives", covered, len(s.Objectives))
	if len(pending) > 0 {
		sort.Strings(pending)
		line += " — pending: " + strings.Join(pending, ", ")
	}
	return line
}

func orUnknown(s string) string {
	if s == "" {
		return "unstated"
	}
	return s
}

// vulnSummary renders vuln-schema findings grouped by reachability verdict —
// confirmed bugs first, ruled-out candidates last — with every structured
// field, so synthesis writes from the facts BINNY actually established.
// Returns false when there are no vuln findings.
func vulnSummary(b *strings.Builder, findings []Finding) bool {
	groups := []struct{ key, title string }{
		{"proven", "Vulnerabilities — reachability PROVEN"},
		{"likely", "Vulnerabilities — reachability LIKELY (path partly established)"},
		{"unproven", "Candidates — reachability NOT established"},
		{"ruled_out", "Investigated and RULED OUT (keep these: negative results are part of the research)"},
	}
	any := false
	for _, f := range findings {
		any = any || f.IsVuln()
	}
	if !any {
		return false
	}
	for _, g := range groups {
		var fs []Finding
		for _, f := range findings {
			if f.Reachability == g.key {
				fs = append(fs, f)
			}
		}
		if len(fs) == 0 {
			continue
		}
		fmt.Fprintf(b, "\n%s:\n", g.title)
		for _, f := range fs {
			fmt.Fprintf(b, "- [%s %s/%s] %s\n", f.CWE, f.Category, f.Severity, f.Note)
			fmt.Fprintf(b, "    source: %s\n    sink: %s\n", f.Source, f.Sink)
			if len(f.Path) > 0 {
				fmt.Fprintf(b, "    path: %s\n", strings.Join(f.Path, " → "))
			}
			if f.Controllability != "" {
				fmt.Fprintf(b, "    attacker controls: %s\n", f.Controllability)
			}
			if f.Mitigations != "" {
				fmt.Fprintf(b, "    mitigations: %s\n", f.Mitigations)
			}
			if f.CVSS != "" {
				fmt.Fprintf(b, "    cvss: %s\n", f.CVSS)
			}
			if f.Remediation != "" {
				fmt.Fprintf(b, "    fix: %s\n", f.Remediation)
			}
			fmt.Fprintf(b, "    evidence: %s\n", strings.Join(f.EvidenceRefs, ", "))
		}
	}
	// Malware-schema findings recorded alongside (rare in vuln mode).
	var other []Finding
	for _, f := range findings {
		if !f.IsVuln() {
			other = append(other, f)
		}
	}
	if len(other) > 0 {
		b.WriteString("\nOther observations:\n")
		for _, f := range other {
			fmt.Fprintf(b, "- [%s/%s] %s (evidence: %s)\n", f.Category, f.Severity, f.Note, strings.Join(f.EvidenceRefs, ", "))
		}
	}
	return true
}
