package agent

import (
	"context"
	"fmt"
	"strings"

	"openbin.ai/binny/internal/llm"
	"openbin.ai/binny/internal/tools"
)

// Runner is one agent's model/tool loop: its own conversation, its own view of
// the tool registry, and its own spend. The captain (BINNY) is a Runner over
// the full registry; a crew member is a Runner over its role's tools with a
// fresh conversation. Runners share one Investigation through the tools, which
// is what makes them a crew rather than strangers.
//
// A Runner knows nothing about phases or missions — the Engine decides who
// runs when, and what a finished turn means.
type Runner struct {
	role   *Role // nil = the captain
	system string
	reg    *tools.Registry

	messages []llm.Message

	used  int // freshly-billed tokens this runner has spent
	turns int // provider round-trips this runner has made

	// context compaction (in-place elision of stale tool results)
	compactThreshold int  // start compacting once message bytes exceed this
	compactedOnce    bool // whether the one-time "compaction on" notice has fired
}

// agentID is the role id lines and findings are attributed to ("" = captain).
func (r *Runner) agentID() string {
	if r == nil || r.role == nil {
		return ""
	}
	return r.role.ID
}

// turnOpts is what the Engine supplies for one round-trip.
type turnOpts struct {
	provider  llm.Provider
	model     string
	maxTokens int
	sink      func(string) // live text deltas; nil = don't stream
	step      int          // 1-based mission step, for provenance (0 = none)
	noAsk     bool         // refuse ask_user instead of suspending (parallel steps)
}

// turnResult is the outcome of one round-trip.
type turnResult struct {
	lines   []Line
	resp    *llm.Response
	usage   llm.Usage
	results []llm.Block   // tool results NOT yet appended when ask != nil
	ask     *llm.ToolCall // the model called ask_user: the caller suspends
	ended   bool          // the model ended its turn without calling a tool
	refused bool          // provider declined (safety); nothing was appended
	err     error
}

// appendUser adds a user-role text turn, merging into a trailing user message
// when there already is one (the Messages API rejects two consecutive user
// turns — this happens when checkpoint steering is followed by a stage brief).
func (r *Runner) appendUser(text string) {
	n := len(r.messages)
	if n > 0 && r.messages[n-1].Role == llm.RoleUser {
		r.messages[n-1].Blocks = append(r.messages[n-1].Blocks, llm.TextBlock(text))
		return
	}
	r.messages = append(r.messages, llm.UserText(text))
}

// turn performs one provider round-trip and runs the tool calls it produced.
// On a plain tool round the results are appended to the conversation; when the
// model called ask_user they are handed back instead, because the analyst's
// answer has to travel in the same user message.
func (r *Runner) turn(ctx context.Context, o turnOpts) turnResult {
	var res turnResult
	res.lines = append(res.lines, r.compact()...) // trim stale tool output before re-sending
	agent := r.agentID()

	r.turns++
	req := llm.Request{
		System:    r.system,
		Messages:  r.messages,
		Tools:     r.reg.Defs(),
		Model:     o.model,
		MaxTokens: o.maxTokens,
	}
	streamed := false
	sink := func(s string) {
		if o.sink != nil {
			streamed = true
			o.sink(s)
		}
	}
	resp, err := o.provider.Stream(ctx, req, sink)
	if err != nil {
		res.err = err
		return res
	}
	res.resp, res.usage = resp, resp.Usage
	// Budget on freshly-billed tokens only: uncached input + cache writes +
	// output. Cache READS (the re-sent conversation prefix) are ~0.1x and are
	// tracked separately — counting them here would defeat the point of caching
	// and burn the budget on context the model already paid to store.
	r.used += resp.Usage.InputTokens + resp.Usage.CacheCreationTokens + resp.Usage.OutputTokens

	if resp.StopReason == llm.StopRefusal {
		// Don't append the refusal — keep the analyst's place. The same context
		// re-sent to the same model will refuse again, so guide them to switch
		// provider (or rephrase) and continue.
		res.lines = append(res.lines, Line{Kind: "err", Agent: agent, Text: fmt.Sprintf(
			"%s declined this (safety classifier — malware RE can trip Claude's cyber safeguards). Your place is kept. Options: /model to a non-Claude provider (e.g. openai, deepseek), then type to continue; or /stop to synthesize with what's gathered so far.",
			o.model)})
		res.refused = true
		return res
	}

	// Only add the text as a transcript line when it wasn't streamed live (the
	// UI already rendered streamed text). Non-streaming providers still surface.
	if txt := strings.TrimSpace(resp.Text()); txt != "" && !streamed {
		res.lines = append(res.lines, Line{Kind: "binny", Agent: agent, Text: txt})
	}
	r.messages = append(r.messages, resp.AsMessage())

	calls := resp.ToolCalls()
	if len(calls) == 0 {
		res.ended = true
		return res
	}

	// Run tool calls, collecting results into one user message. If ask_user is
	// among them, the caller suspends after the others have run.
	tctx := withActor(ctx, actor{role: agent, step: o.step})
	for i := range calls {
		c := calls[i]
		if c.Name == AskUserToolName && !o.noAsk {
			res.ask = &calls[i]
			continue
		}
		res.lines = append(res.lines, Line{Kind: "tool", Agent: agent, Text: toolCallLabel(c)})
		out, isErr := r.reg.Run(tctx, c.Name, c.Input)
		kind := "tool"
		if isErr {
			kind = "err"
		}
		res.lines = append(res.lines, Line{Kind: kind, Agent: agent, Text: toolResultLabel(c.Name, out)})
		res.results = append(res.results, llm.ToolResult(c.ID, out, isErr))
	}
	if res.ask == nil {
		r.messages = append(r.messages, llm.Message{Role: llm.RoleUser, Blocks: res.results})
	}
	return res
}

// messagesBytes estimates the conversation size (chars ≈ 4× tokens).
func (r *Runner) messagesBytes() int {
	n := 0
	for _, m := range r.messages {
		for _, b := range m.Blocks {
			n += len(b.Text) + len(b.Content) + len(b.Input)
		}
	}
	return n
}

// compact bounds the re-sent context by stubbing the CONTENT of stale, large
// tool_result blocks (everything except the last compactKeepRecent messages and
// the opening kickoff). It edits content in place — tool_use/tool_result pairing
// and user/assistant alternation are untouched — so it's safe for the Messages
// API. Conclusions live in the Investigation, so the raw output is disposable;
// the model can re-run a tool if it truly needs the detail again. No-op until the
// history crosses compactThreshold (short runs stay pristine + cache well).
func (r *Runner) compact() []Line {
	if r.messagesBytes() < r.compactThreshold {
		return nil
	}
	cut := len(r.messages) - compactKeepRecent
	if cut <= 1 { // keep messages[0] (kickoff) + the recent tail
		return nil
	}
	elided, saved := 0, 0
	for i := 1; i < cut; i++ {
		for j := range r.messages[i].Blocks {
			b := &r.messages[i].Blocks[j]
			if b.Kind == llm.BlockToolResult && len(b.Content) > compactMinElideBytes {
				saved += len(b.Content)
				b.Content = fmt.Sprintf("[output elided to save context — %d chars; conclusions are recorded. Re-run the tool if you need the detail again.]", len(b.Content))
				elided++
			}
		}
	}
	if elided == 0 || r.compactedOnce {
		return nil
	}
	r.compactedOnce = true
	return []Line{{Kind: "sys", Agent: r.agentID(), Text: fmt.Sprintf(
		"Context compaction: trimmed %d older tool result(s) (~%dk chars) to keep this run affordable — your scrollback is unchanged and all findings are preserved.",
		elided, saved/1000)}}
}

// lastText returns the text of the runner's final assistant message — a crew
// member's debrief.
func (r *Runner) lastText() string {
	for i := len(r.messages) - 1; i >= 0; i-- {
		if r.messages[i].Role != llm.RoleAssistant {
			continue
		}
		var b strings.Builder
		for _, blk := range r.messages[i].Blocks {
			if blk.Kind == llm.BlockText {
				b.WriteString(blk.Text)
			}
		}
		return strings.TrimSpace(b.String())
	}
	return ""
}

// actor is who is calling a tool: which crew member, in which mission step.
// It rides on the tool context so the output tools can stamp provenance on
// what they record without the handlers knowing about runners.
type actor struct {
	role string
	step int
}

type actorKey struct{}

func withActor(ctx context.Context, a actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

func actorFrom(ctx context.Context) actor {
	a, _ := ctx.Value(actorKey{}).(actor)
	return a
}
