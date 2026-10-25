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

// TestStartFromReport verifies the "continue existing report" seed: the report
// loads into the investigation as established, the engine lands in REVIEW, and
// the conversation is seeded (but nothing is sent) — ready for the analyst's
// first message without re-running triage.
func TestStartFromReport(t *testing.T) {
	sess := &app.Session{
		Mode: app.ModeMalware, Autonomy: app.Supervised, Model: "test", Config: &config.Config{},
		Project: &api.Project{ID: "p1", Name: "sample.bin", Kind: api.KindBIN, Status: "READY"},
	}
	inv := NewInvestigation()
	reg := tools.NewRegistry()
	registerOutputTools(reg, inv, nil, sess.Project, sess.Mode)
	eng := NewEngine(sess, inv, reg, &scriptedProvider{})

	report := &api.Report{
		Title:       "sample.bin — MAR",
		MalwareType: "trojan",
		Sections: []api.ReportSection{
			{ID: "summary", Title: "Summary", Content: "A 64-bit Delphi infostealer."},
			{ID: "exfil", Title: "Exfil channel", Content: "FTP via Indi."},
			{ID: "empty", Title: "Empty", Content: "   "}, // skipped — no content
		},
	}
	lines := eng.StartFromReport(report)

	if eng.stage != stageReview {
		t.Errorf("stage = %d, want stageReview(%d)", eng.stage, stageReview)
	}
	if got := len(inv.Sections); got != 2 {
		t.Fatalf("loaded %d sections, want 2 (empty one skipped)", got)
	}
	if len(inv.MalwareTypes) != 1 || inv.MalwareTypes[0] != "trojan" {
		t.Errorf("classification = %v, want [trojan]", inv.MalwareTypes)
	}
	if !eng.Started() {
		t.Error("engine should report Started after seeding")
	}
	if len(eng.messages) != 1 {
		t.Fatalf("seeded %d messages, want exactly 1 (the kickoff)", len(eng.messages))
	}
	if eng.messages[0].Role != llm.RoleUser {
		t.Errorf("seeded message role = %v, want user", eng.messages[0].Role)
	}
	// The kickoff must embed the report content so BINNY has the prior analysis.
	body := renderMessageText(eng.messages[0])
	for _, want := range []string{"Delphi infostealer", "FTP via Indi", "EXISTING REPORT"} {
		if !strings.Contains(body, want) {
			t.Errorf("kickoff missing %q", want)
		}
	}
	if eng.spentTokens != 0 {
		t.Errorf("StartFromReport spent %d tokens, want 0 (no provider call)", eng.spentTokens)
	}
	if len(lines) == 0 {
		t.Error("expected a phase/status line back")
	}

	// The analyst's first message must MERGE into the seeded user turn, not append
	// a second consecutive user message (which the Messages API rejects).
	eng.Ask("verify the exfil section")
	if len(eng.messages) != 1 {
		t.Errorf("after Ask, %d messages — first analyst turn should merge into the kickoff", len(eng.messages))
	}
}

// renderMessageText concatenates the text blocks of a message for assertions.
func renderMessageText(m llm.Message) string {
	var b strings.Builder
	for _, blk := range m.Blocks {
		b.WriteString(blk.Text)
	}
	return b.String()
}
