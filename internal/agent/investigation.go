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

	// Notes is the crew's shared notebook: what a function / symbol / address
	// means, so the next crew member doesn't re-read it.
	Notes []Note
	// Verification says whether the findings went through a Parity pass:
	// "" (a single-agent run, no crew), VerificationDone, or
	// VerificationNone (a mission without Parity — the draft is unverified).
	Verification string
}

// Verification states.
const (
	VerificationDone = "verified"
	VerificationNone = "unverified"
)

// Parity's verdicts on a finding. An unset verdict means "not verified yet".
const (
	VerdictConfirmed  = "confirmed"
	VerdictDowngraded = "downgraded"
	VerdictRejected   = "rejected"
)

// Note is one shared-notebook entry, keyed by symbol.
type Note struct {
	Symbol  string // function name, symbol, address, or file:line
	Meaning string // what it is / does
	By      string // role id of the crew member who wrote it
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

	// Crew provenance + verification. ID is assigned when the finding is
	// recorded; FoundBy/Step say who recorded it and in which mission step;
	// the verdict fields are Parity's.
	ID          string // "F1", "F2", … stable handle for set_verdict
	FoundBy     string // role id ("" on a single-agent run)
	Step        int    // 1-based mission step that recorded it (0 = outside a step)
	Verdict     string // "" | confirmed | downgraded | rejected
	VerifiedBy  string // role id that set the verdict
	VerdictNote string // why
	WasSeverity string // the severity before a downgrade
}

// IsVuln reports whether a finding came through the vuln-mode schema.
func (f Finding) IsVuln() bool { return f.Reachability != "" }

// IOC is an indicator of compromise, each tied to one evidence ref.
type IOC struct {
	Type        string // ip|domain|url|hash|path|mutex|registry|email|…
	Value       string
	EvidenceRef string
	FoundBy     string // role id ("" on a single-agent run)
	Step        int    // 1-based mission step that recorded it
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
	f.ID = fmt.Sprintf("F%d", len(inv.Findings)+1)
	inv.Findings = append(inv.Findings, f)
	return nil
}

// SetVerdict records Parity's verdict on a finding. A downgrade carries the
// new (lower) severity. The reason is required: a verdict is a claim too.
func (inv *Investigation) SetVerdict(id, verdict, severity, reason, by string) (Finding, error) {
	verdict = strings.ToLower(strings.TrimSpace(verdict))
	if verdict != VerdictConfirmed && verdict != VerdictDowngraded && verdict != VerdictRejected {
		return Finding{}, fmt.Errorf("verdict %q must be confirmed, downgraded or rejected", verdict)
	}
	if strings.TrimSpace(reason) == "" {
		return Finding{}, fmt.Errorf("a verdict needs a reason: say what you re-read and what it showed")
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	for i := range inv.Findings {
		f := &inv.Findings[i]
		if !strings.EqualFold(f.ID, strings.TrimSpace(id)) {
			continue
		}
		if verdict == VerdictDowngraded {
			severity = strings.ToLower(strings.TrimSpace(severity))
			was := f.Severity
			if f.WasSeverity != "" {
				was = f.WasSeverity
			}
			to, ok := severityAtLeast[severity]
			if !ok {
				return Finding{}, fmt.Errorf("a downgrade needs the new severity (info | low | medium | high)")
			}
			if from, known := severityAtLeast[strings.ToLower(was)]; known && to >= from {
				return Finding{}, fmt.Errorf("%s is %s — a downgrade must set a LOWER severity (use confirmed if it stands)", f.ID, was)
			}
			f.WasSeverity, f.Severity = was, severity
		} else if f.WasSeverity != "" {
			// A later confirm/reject undoes an earlier downgrade.
			f.Severity, f.WasSeverity = f.WasSeverity, ""
		}
		f.Verdict, f.VerifiedBy, f.VerdictNote = verdict, by, strings.TrimSpace(reason)
		return *f, nil
	}
	return Finding{}, fmt.Errorf("no finding %q (ids are F1, F2, … as listed)", id)
}

// Unverified returns the ids of findings that carry no verdict yet.
func (inv *Investigation) Unverified() []string {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	var ids []string
	for _, f := range inv.Findings {
		if f.Verdict == "" {
			ids = append(ids, f.ID)
		}
	}
	return ids
}

// SetVerification records whether a Parity pass covered this investigation.
func (inv *Investigation) SetVerification(v string) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.Verification = v
}

// AddNote upserts a shared-notebook entry by symbol (case-insensitive).
func (inv *Investigation) AddNote(n Note) error {
	n.Symbol, n.Meaning = strings.TrimSpace(n.Symbol), strings.TrimSpace(n.Meaning)
	if n.Symbol == "" || n.Meaning == "" {
		return fmt.Errorf("a note needs both a symbol and what it means")
	}
	inv.mu.Lock()
	defer inv.mu.Unlock()
	for i := range inv.Notes {
		if strings.EqualFold(inv.Notes[i].Symbol, n.Symbol) {
			inv.Notes[i] = n
			return nil
		}
	}
	inv.Notes = append(inv.Notes, n)
	return nil
}

// NotesMatching returns notebook entries whose symbol or meaning contains the
// filter (case-insensitive); an empty filter returns them all.
func (inv *Investigation) NotesMatching(filter string) []Note {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	filter = strings.ToLower(strings.TrimSpace(filter))
	var out []Note
	for _, n := range inv.Notes {
		if filter == "" || strings.Contains(strings.ToLower(n.Symbol), filter) || strings.Contains(strings.ToLower(n.Meaning), filter) {
			out = append(out, n)
		}
	}
	return out
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
		Notes:        append([]Note(nil), inv.Notes...),
		Renames:      append([]RenameSuggestion(nil), inv.RenameProposal...),
		Verification: inv.Verification,
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
	Notes        []Note
	Renames      []RenameSuggestion
	Verification string
}

// verified reports whether verdicts should shape the summary: a Parity pass
// ran, or some finding already carries a verdict.
func (s InvestigationSnapshot) verified() bool {
	if s.Verification == VerificationDone {
		return true
	}
	for _, f := range s.Findings {
		if f.Verdict != "" {
			return true
		}
	}
	return false
}

// forDraft is the snapshot the report scaffold is built from: a vuln finding
// Parity rejected becomes a ruled-out candidate (a negative result with its
// reason) instead of an advisory.
func (s InvestigationSnapshot) forDraft() InvestigationSnapshot {
	out := s
	out.Findings = append([]Finding(nil), s.Findings...)
	for i := range out.Findings {
		f := &out.Findings[i]
		if f.Verdict == VerdictRejected && f.IsVuln() {
			f.Reachability, f.Severity = "ruled_out", "info"
			f.Note = strings.TrimSpace(f.Note + " — rejected on verification: " + f.VerdictNote)
		}
	}
	return out
}

// verdictTag annotates a finding line with Parity's verdict.
func verdictTag(f Finding) string {
	switch f.Verdict {
	case VerdictConfirmed:
		return " ✔confirmed"
	case VerdictDowngraded:
		if f.WasSeverity != "" {
			return " ▼downgraded from " + f.WasSeverity
		}
		return " ▼downgraded"
	case VerdictRejected:
		return " ✘rejected"
	}
	return " ?unverified"
}

// NotebookSummary renders the shared notebook, one entry per line.
func (s InvestigationSnapshot) NotebookSummary() string {
	if len(s.Notes) == 0 {
		return ""
	}
	var b strings.Builder
	for _, n := range s.Notes {
		fmt.Fprintf(&b, "- %s — %s", n.Symbol, n.Meaning)
		if n.By != "" {
			fmt.Fprintf(&b, " (%s)", n.By)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// EvidenceSummary renders findings + IOCs + classification compactly, for
// feeding into the SYNTHESIZE prompt and status displays.
func (s InvestigationSnapshot) EvidenceSummary() string {
	var b strings.Builder
	if len(s.MalwareTypes) > 0 {
		fmt.Fprintf(&b, "Classification: %s (confidence: %s)\n", strings.Join(s.MalwareTypes, ", "), orUnknown(s.Confidence))
	}
	// Once Parity has weighed in, rejected findings leave the body of evidence
	// (they are kept below as negative results) and the rest carry their verdict.
	verified := s.verified()
	live, rejected := s.Findings, []Finding(nil)
	if verified {
		live = nil
		for _, f := range s.Findings {
			if f.Verdict == VerdictRejected {
				rejected = append(rejected, f)
			} else {
				live = append(live, f)
			}
		}
	}
	if !vulnSummary(&b, live, verified) && len(live) > 0 {
		b.WriteString("\nFindings:\n")
		for _, f := range live {
			cwe := ""
			if f.CWE != "" {
				cwe = " " + f.CWE
			}
			tag := ""
			if verified {
				tag = verdictTag(f)
			}
			fmt.Fprintf(&b, "- [%s/%s%s%s] %s (evidence: %s)\n",
				f.Category, f.Severity, cwe, tag, f.Note, strings.Join(f.EvidenceRefs, ", "))
		}
	}
	if len(rejected) > 0 {
		b.WriteString("\nRejected by verification (negative results — do NOT present these as findings; you may list them as checked-and-cleared):\n")
		for _, f := range rejected {
			fmt.Fprintf(&b, "- [%s] %s — rejected: %s\n", f.Category, f.Note, f.VerdictNote)
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
func vulnSummary(b *strings.Builder, findings []Finding, verified bool) bool {
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
			tag := ""
			if verified {
				tag = verdictTag(f)
			}
			fmt.Fprintf(b, "- [%s %s/%s%s] %s\n", f.CWE, f.Category, f.Severity, tag, f.Note)
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
