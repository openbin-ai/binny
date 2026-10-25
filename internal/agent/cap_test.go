package agent

import (
	"context"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/tools"
)

func capTestEngine(t *testing.T, autonomy app.Autonomy) *Engine {
	t.Helper()
	sess := &app.Session{
		Mode: app.ModeMalware, Autonomy: autonomy, Model: "test", Config: &config.Config{},
		Project: &api.Project{ID: "p1", Name: "s", Kind: api.KindBIN, Status: "READY"},
	}
	inv := NewInvestigation()
	reg := tools.NewRegistry()
	registerOutputTools(reg, inv, nil, sess.Project, sess.Mode)
	return NewEngine(sess, inv, reg, &scriptedProvider{})
}

// TestRoundCapPausesNotSynthesizes is the core of the fix: hitting the round cap
// PAUSES in place (offering continue) instead of jumping to synthesis — and it
// does so even in Autonomous mode, because a spend cap is about money.
func TestRoundCapPausesNotSynthesizes(t *testing.T) {
	eng := capTestEngine(t, app.Autonomous)
	eng.stage = stageInvestigate
	eng.maxRounds = 3
	eng.rounds = 3 // at the cap

	res := eng.Step(context.Background())
	if res.CapReached != "rounds" {
		t.Fatalf("CapReached = %q, want %q", res.CapReached, "rounds")
	}
	if eng.stage != stageInvestigate {
		t.Errorf("stage = %d; a cap must pause in place, not advance to synthesize", eng.stage)
	}
	if eng.CapReason() != "rounds" {
		t.Errorf("CapReason = %q, want rounds", eng.CapReason())
	}

	// Continue extends the cap and clears the pause so the next Step proceeds.
	eng.ContinuePastCap()
	if eng.CapReason() != "" {
		t.Error("CapReason should clear after ContinuePastCap")
	}
	if eng.maxRounds != 3+capRoundExtension {
		t.Errorf("maxRounds = %d, want %d", eng.maxRounds, 3+capRoundExtension)
	}
}

func TestTokenCapPausesAndExtends(t *testing.T) {
	eng := capTestEngine(t, app.Supervised)
	eng.stage = stageInvestigate
	eng.maxTokens = 100
	eng.spentTokens = 100 // budget reached

	res := eng.Step(context.Background())
	if res.CapReached != "tokens" {
		t.Fatalf("CapReached = %q, want tokens", res.CapReached)
	}
	if eng.stage != stageInvestigate {
		t.Errorf("token cap should pause in investigate, not advance (stage=%d)", eng.stage)
	}
	eng.ContinuePastCap()
	if eng.maxTokens != 100+capTokenExtension {
		t.Errorf("maxTokens = %d, want %d", eng.maxTokens, 100+capTokenExtension)
	}
	if eng.CapReason() != "" {
		t.Error("CapReason should clear after continue")
	}
}

// TestStopFromSynthesizeFinalizesToReview covers the "stop" side of a synth-cap
// pause: it should land in REVIEW with the current draft, not loop.
func TestStopFromSynthesizeFinalizesToReview(t *testing.T) {
	eng := capTestEngine(t, app.Supervised)

	eng.stage = stageInvestigate
	if lines := eng.Stop(); len(lines) == 0 {
		t.Error("Stop from investigate should report moving to synthesize")
	}
	if eng.stage != stageSynthesize {
		t.Fatalf("stage = %d, want synthesize after Stop from investigate", eng.stage)
	}

	if lines := eng.Stop(); len(lines) == 0 {
		t.Error("Stop from synthesize should report finalizing to review")
	}
	if eng.stage != stageReview {
		t.Errorf("stage = %d, want review after Stop from synthesize", eng.stage)
	}
}
