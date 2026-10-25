package agent

import (
	"fmt"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/app"
	"openbin.ai/binny/internal/llm"
	"openbin.ai/binny/internal/tools"
)

// Build assembles a ready-to-run engine for the session's attached project: it
// constructs the LLM provider (BYOK), the full tool registry (read + output +
// extraction + local decompile), and a fresh investigation. Returns an error if
// the provider can't be built (e.g. missing key) or no project is attached.
func Build(sess *app.Session, client *api.Client) (*Engine, *Investigation, error) {
	provider, err := llm.New(*sess.Provider)
	if err != nil {
		return nil, nil, err
	}
	inv := NewInvestigation()
	reg := tools.NewRegistry()

	tb := tools.NewToolbox(client, sess.Project)
	tb.RegisterRead(reg)
	var eng *Engine
	tb.Progress = func(format string, args ...any) {
		if eng != nil {
			eng.StreamLine(fmt.Sprintf(format, args...))
		}
	}
	registerOutputTools(reg, inv, client, sess.Project, sess.Mode)
	registerExtractionTools(reg, inv, sess)
	registerSampleTools(reg, sess, tb)
	if sess.Sample != nil {
		// Analyst picked an extra sample before starting (/switch) — load it
		// now so the first read tool serves the right binary. A failure here
		// falls back to the primary rather than refusing to start.
		if _, err := tb.SwitchSample(sess.Sample); err != nil {
			sess.Sample = nil
		}
	}

	eng = NewEngine(sess, inv, reg, provider)
	eng.tb = tb

	// The local Ghidra tool streams its (minutes-long) progress through the
	// engine's live text sink so the analyst sees what's happening mid-call.
	// BIN only: its output feeds the native read tools, which APK/script
	// projects don't have.
	if sess.Project.Kind == api.KindBIN {
		registerDecompileTool(reg, sess, tb, func(format string, args ...any) {
			eng.StreamLine(fmt.Sprintf(format, args...))
		})
	}
	return eng, inv, nil
}
