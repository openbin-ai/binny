package agent

import (
	"context"
	"encoding/json"
	"testing"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/config"
	"openbin.ai/binny/internal/llm"
	"openbin.ai/binny/internal/tools"
)

func TestEngineStateRoundTrip(t *testing.T) {
	script := &scriptedProvider{turns: []*llm.Response{
		{StopReason: llm.StopToolUse, Blocks: []llm.Block{
			toolUse("c1", "set_classification", `{"malware_types":["ransomware"],"confidence":"high"}`),
		}},
	}}
	sess := &app.Session{
		Mode: app.ModeMalware, Autonomy: app.Supervised, Model: "test", Config: &config.Config{},
		Project: &api.Project{ID: "p1", Name: "s", Kind: api.KindBIN, Status: "READY"},
	}
	inv := NewInvestigation()
	reg := tools.NewRegistry()
	registerOutputTools(reg, inv, nil, sess.Project, sess.Mode)
	eng := NewEngine(sess, inv, reg, script)
	eng.Start()
	eng.Step(context.Background()) // classify → investigate

	// Snapshot → JSON → back (the real persistence path).
	raw, err := json.Marshal(eng.State())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var st EngineState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Restore against a Bedrock provider (llm.New needs no key/network for it).
	sess2 := &app.Session{
		Mode: app.ModeMalware, Autonomy: app.Supervised, Model: "test", Config: &config.Config{},
		Provider: &config.Provider{ID: "bedrock", Kind: config.KindBedrock},
		Project:  &api.Project{ID: "p1", Name: "s", Kind: api.KindBIN, Status: "READY"},
	}
	eng2, inv2, err := RestoreEngine(sess2, nil, st)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if eng2.stage != eng.stage {
		t.Errorf("stage: restored %d, want %d", eng2.stage, eng.stage)
	}
	if len(eng2.messages) != len(eng.messages) {
		t.Errorf("messages: restored %d, want %d", len(eng2.messages), len(eng.messages))
	}
	if len(inv2.MalwareTypes) != 1 || inv2.MalwareTypes[0] != "ransomware" {
		t.Errorf("investigation classification lost: %v", inv2.MalwareTypes)
	}
	if len(eng2.pbs) == 0 {
		t.Error("playbooks were not re-derived from classification on restore")
	}
	if eng2.rounds != eng.rounds {
		t.Errorf("rounds: restored %d, want %d", eng2.rounds, eng.rounds)
	}
}
