package agent

import (
	"strings"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/llm"
	"openbin.ai/binny/internal/tools"
)

func qaSession() *app.Session {
	return &app.Session{
		Mode: app.ModeMalware, Autonomy: app.Supervised, Model: "test", Config: &config.Config{},
		Project: &api.Project{ID: "p1", Name: "sample.bin", Kind: api.KindBIN, Status: "READY"},
	}
}

func qaEngine(sess *app.Session) (*Engine, *Investigation) {
	inv := NewInvestigation()
	reg := tools.NewRegistry()
	registerOutputTools(reg, inv, nil, sess.Project, sess.Mode)
	return NewEngine(sess, inv, reg, &scriptedProvider{}), inv
}

// TestStartQAWithReport: a report is loaded as CLAIMS to check (not as trusted
// work), the engine lands in REVIEW, the kickoff frames the skeptical posture,
// and nothing is spent until the analyst asks.
func TestStartQAWithReport(t *testing.T) {
	sess := qaSession()
	eng, inv := qaEngine(sess)

	report := &api.Report{
		Title:       "sample.bin — MAR",
		MalwareType: "trojan",
		Sections: []api.ReportSection{
			{ID: "summary", Title: "Summary", Content: "A 64-bit Delphi infostealer."},
			{ID: "exfil", Title: "Exfil channel", Content: "FTP via Indi."},
			{ID: "empty", Title: "Empty", Content: "   "}, // skipped — no content
		},
	}
	lines := eng.StartQA(report)

	if eng.stage != stageReview {
		t.Errorf("stage = %d, want stageReview(%d)", eng.stage, stageReview)
	}
	if got := len(inv.Sections); got != 2 {
		t.Fatalf("loaded %d sections, want 2 (empty skipped)", got)
	}
	if eng.spentTokens != 0 {
		t.Errorf("StartQA spent %d tokens, want 0 (no provider call)", eng.spentTokens)
	}
	if len(eng.messages) != 1 || eng.messages[0].Role != llm.RoleUser {
		t.Fatalf("want exactly 1 seeded user message, got %d", len(eng.messages))
	}
	body := renderMessageText(eng.messages[0])
	// Skeptical posture + report content embedded, and NOT the trusting
	// "established" language that continue-mode uses.
	for _, want := range []string{"Q&A", "CLAIMS", "FTP via Indi", "REPORT UNDER QUESTION"} {
		if !strings.Contains(body, want) {
			t.Errorf("kickoff missing %q", want)
		}
	}
	if strings.Contains(body, "TRUSTS it as established") {
		t.Error("Q&A kickoff must NOT tell BINNY to trust the report as established")
	}
	if len(lines) == 0 {
		t.Error("expected an opening status line")
	}
}

// TestStartQANoReport: with no report, Q&A still seeds a REVIEW session oriented
// on the sample, and mentions attaching a local binary via /sample.
func TestStartQANoReport(t *testing.T) {
	sess := qaSession()
	eng, inv := qaEngine(sess)

	lines := eng.StartQA(nil)

	if eng.stage != stageReview {
		t.Errorf("stage = %d, want stageReview(%d)", eng.stage, stageReview)
	}
	if len(inv.Sections) != 0 {
		t.Errorf("no report → want 0 sections, got %d", len(inv.Sections))
	}
	body := renderMessageText(eng.messages[0])
	for _, want := range []string{"Q&A", "/sample", "sample.bin"} {
		if !strings.Contains(body, want) {
			t.Errorf("kickoff missing %q", want)
		}
	}
	if strings.Contains(body, "REPORT UNDER QUESTION") {
		t.Error("no-report Q&A kickoff should not embed a report block")
	}
	if len(lines) == 0 {
		t.Error("expected an opening status line")
	}

	// First question merges into the seeded turn (Messages API: no two
	// consecutive user turns).
	eng.Ask("what does main do?")
	if len(eng.messages) != 1 {
		t.Errorf("after Ask, %d messages — first question should merge into the kickoff", len(eng.messages))
	}
}
