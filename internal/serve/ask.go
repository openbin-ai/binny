package serve

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"openbin.ai/binny/internal/agent"
	"openbin.ai/binny/internal/llm"
)

// Asking one crew member directly. "@trace where does the C2 address come
// from?" in the chat box sends that turn to Trace instead of BINNY: the same
// agent loop, with Trace's system prompt and Trace's tools, in a fresh context
// that carries the conversation so far as text. No mission runs — there is no
// triage, no tasking and no report — and the answer lands in the conversation
// marked as Trace's, so BINNY can build on it afterwards.
//
// The stream is the chat's, with `agent` on every event.

const (
	askIters     = 10   // provider round-trips one direct question gets
	askTurns     = 10   // text turns of the conversation the member is shown
	askTurnChars = 1500 // …each clipped to this
)

// askTarget is a crew member resolved against what is open.
type askTarget struct {
	role agent.Role
	defs []llm.Tool
}

// askTarget resolves an @mention, or says why that member can't take it.
func (s *server) askTarget(id string) (*askTarget, error) {
	role, ok := agent.RoleByID(id)
	if !ok {
		var names []string
		for _, r := range agent.Roles() {
			names = append(names, "@"+r.ID)
		}
		return nil, fmt.Errorf("there is no crew member %q — the crew: %s", id, strings.Join(names, ", "))
	}
	kind := s.targetKind()
	if kind == "" {
		return nil, fmt.Errorf("open a target first — %s needs something to look at (Open, or Cloud for a project)", role.Name)
	}
	defs, reads, _ := s.roleToolDefs(role)
	if why := s.cantRun(role, kind, reads); why != "" {
		return nil, fmt.Errorf("%s can't take this one: %s", role.Name, why)
	}
	return &askTarget{role: role, defs: defs}, nil
}

// askQuestion and askAnswer are how a direct exchange reads in BINNY's
// transcript.
func askQuestion(role agent.Role, q string) string {
	return fmt.Sprintf("[The analyst asked %s directly] %s", role.Name, q)
}

func askAnswer(role agent.Role, a string) string {
	return fmt.Sprintf("[%s answered]\n%s", role.Name, a)
}

// askCrew puts the newest user turn of history to one crew member and returns
// the conversation's transcript with the exchange added. base carries the
// system prompt, model and output cap of the request.
func (s *server) askCrew(ctx context.Context, provider llm.Provider, t *askTarget, base llm.Request, history []llm.Message, send func(map[string]any)) []llm.Message {
	role := t.role
	prior, question := history, ""
	if n := len(history); n > 0 && history[n-1].Role == llm.RoleUser {
		prior, question = history[:n-1], strings.TrimSpace(messageText(history[n-1]))
	}
	// The analyst's own "@trace" is addressing, not part of the question.
	question = stripMention(question, role)

	allowed := map[string]bool{}
	for _, d := range t.defs {
		allowed[d.Name] = true
	}
	cfg := loopCfg{
		maxIters: askIters,
		tool: func(_ context.Context, name string, _ json.RawMessage) (string, bool, bool) {
			if !allowed[name] {
				return name + " isn't one of your tools. If the question needs it, say so in your answer.", true, true
			}
			return "", false, false
		},
	}
	base.System = agent.CrewSystem(base.System, role)
	base.Messages = []llm.Message{llm.UserText(s.askPrompt(role, prior, question))}
	base.Tools = t.defs
	msgs := s.runAgentLoop(withLoopCfg(agent.WithActor(ctx, role.ID, 0), cfg), provider, base, func(ev map[string]any) {
		ev["agent"] = role.ID
		send(ev)
	})

	answer := lastAssistantText(msgs)
	if answer == "" {
		return prior // the call failed before any reply; the stream said why
	}
	out := append([]llm.Message(nil), prior...)
	return append(out,
		llm.UserText(askQuestion(role, question)),
		llm.Message{Role: llm.RoleAssistant, Blocks: []llm.Block{llm.TextBlock(askAnswer(role, answer))}},
	)
}

// askPrompt is the single message a crew member is handed for a direct
// question: the target, the conversation so far, and the question.
func (s *server) askPrompt(role agent.Role, prior []llm.Message, question string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %q (kind=%s).\n", s.targetName(), s.targetKind())
	fmt.Fprintf(&b, "\nDIRECT QUESTION — the analyst is asking you, %s, directly in the chat. No mission is running: you have no tasking, no objectives and no debrief to write.\n", role.Name)
	if d := convoDigest(prior); d != "" {
		b.WriteString("\nThe conversation so far, oldest first (BINNY is the captain; a turn marked `[Name answered]` is that crew member's own reply):\n" + d)
	}
	fmt.Fprintf(&b, "\nTHE ANALYST ASKS YOU:\n%s\n", question)
	b.WriteString("\nAnswer that question, and only that. Check with your tools before you answer — a handful of calls, not an investigation — and cite the function or file:line behind each claim. " +
		"If you establish a distinct issue while you are there, pin it with record_finding. If the question is really a crewmate's job, say whose in one line and answer what you can. " +
		"Reply to the analyst in your own voice, in Markdown. This is a chat answer: no DEBRIEF heading, and no LESSON or HANDOFF lines.\n")
	return b.String()
}

// convoDigest renders the last few text turns of a transcript for a prompt.
// Tool calls and their results are left out: the member re-reads what it needs.
func convoDigest(msgs []llm.Message) string {
	var turns []string
	for i := len(msgs) - 1; i >= 0 && len(turns) < askTurns; i-- {
		text := strings.TrimSpace(messageText(msgs[i]))
		if text == "" {
			continue
		}
		who := "ANALYST"
		if msgs[i].Role == llm.RoleAssistant {
			who = "BINNY"
		}
		turns = append(turns, who+": "+clipText(text, askTurnChars))
	}
	var b strings.Builder
	for i := len(turns) - 1; i >= 0; i-- {
		b.WriteString(turns[i] + "\n\n")
	}
	return b.String()
}

// messageText is the plain text of a message (its text blocks, joined).
func messageText(m llm.Message) string {
	var b strings.Builder
	for _, blk := range m.Blocks {
		if blk.Kind == llm.BlockText {
			b.WriteString(blk.Text)
		}
	}
	return b.String()
}

// stripMention drops a leading "@trace" / "@Trace," from a question.
func stripMention(q string, role agent.Role) string {
	if !strings.HasPrefix(q, "@") {
		return q
	}
	end := strings.IndexAny(q, " \t\n,:")
	if end < 0 {
		end = len(q)
	}
	if name := q[1:end]; !strings.EqualFold(name, role.ID) && !strings.EqualFold(name, role.Name) {
		return q
	}
	return strings.TrimLeft(q[end:], " \t\n,:")
}
