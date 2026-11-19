package llm

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// anthropicProvider speaks the Anthropic Messages API directly (raw HTTP). We
// don't use anthropic-sdk-go: the whole point of this layer is to normalize
// three wire schemas onto one internal representation, and the SDK's typed
// unions would fight that (and it needs a newer Go than we target). This is the
// flagship adapter — tool_use/tool_result blocks + prompt caching for the long
// agent loop.
type anthropicProvider struct {
	id      string
	baseURL string
	apiKey  string
	http    *http.Client
}

func (p *anthropicProvider) Name() string { return p.id }

// --- wire types (Messages API) --------------------------------------------

type antReq struct {
	Model     string        `json:"model"`
	MaxTokens int           `json:"max_tokens"`
	Stream    bool          `json:"stream"`
	System    []antSysBlock `json:"system,omitempty"`
	Messages  []antMessage  `json:"messages"`
	Tools     []antTool     `json:"tools,omitempty"`
}

type antSysBlock struct {
	Type         string           `json:"type"` // "text"
	Text         string           `json:"text"`
	CacheControl *antCacheControl `json:"cache_control,omitempty"`
}

type antCacheControl struct {
	Type string `json:"type"` // "ephemeral"
}

type antTool struct {
	Name         string           `json:"name"`
	Description  string           `json:"description,omitempty"`
	InputSchema  map[string]any   `json:"input_schema"`
	CacheControl *antCacheControl `json:"cache_control,omitempty"`
}

type antMessage struct {
	Role    string     `json:"role"`
	Content []antBlock `json:"content"`
}

// antBlock is the union over text / tool_use / tool_result on the wire.
type antBlock struct {
	Type string `json:"type"`
	// text
	Text string `json:"text,omitempty"`
	// tool_use
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
	// tool_result
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content   string `json:"content,omitempty"`
	IsError   bool   `json:"is_error,omitempty"`
	// a cache breakpoint may sit on any block (used on the last message block to
	// cache the whole conversation prefix turn-over-turn).
	CacheControl *antCacheControl `json:"cache_control,omitempty"`
}

// buildAntReq assembles the wire request AND places the prompt-cache
// breakpoints. Anthropic allows up to 4 ephemeral breakpoints; BINNY uses three
// stable ones, all as a strict prefix so each turn's cache is a prefix of the
// next:
//  1. system prompt — fixed for the whole session
//  2. tool list — fixed for the whole session (rendered before messages)
//  3. last message — caches the entire conversation so far; next round the
//     unchanged prefix is a cache READ (~0.1x) and only the new turn is billed.
//
// (3) is the one that matters for cost: without it, every round re-bills the
// full, growing history at full price — the difference between a run costing
// ~100k tokens and ~1M.
func buildAntReq(req Request) antReq {
	body := antReq{
		Model:     req.Model,
		MaxTokens: req.MaxTokens,
		Stream:    true,
		Messages:  toAntMessages(req.Messages),
		Tools:     toAntTools(req.Tools),
	}
	if req.System != "" {
		body.System = []antSysBlock{{
			Type: "text", Text: req.System,
			CacheControl: &antCacheControl{Type: "ephemeral"},
		}}
	}
	if n := len(body.Tools); n > 0 {
		body.Tools[n-1].CacheControl = &antCacheControl{Type: "ephemeral"}
	}
	if n := len(body.Messages); n > 0 {
		if c := len(body.Messages[n-1].Content); c > 0 {
			body.Messages[n-1].Content[c-1].CacheControl = &antCacheControl{Type: "ephemeral"}
		}
	}
	return body
}

func (p *anthropicProvider) Stream(ctx context.Context, req Request, onText func(string)) (*Response, error) {
	body := buildAntReq(req)

	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(p.baseURL, "/") + "/v1/messages"
	resp, err := postSSE(ctx, p.http, endpoint,
		map[string]string{
			"x-api-key":         p.apiKey,
			"anthropic-version": "2023-06-01",
			"content-type":      "application/json",
			"accept":            "text/event-stream",
		}, raw)
	if err != nil {
		return nil, describeRequestErr(p.id, endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("anthropic error (status %d): %s", resp.StatusCode, abbreviate(string(errBody), 400))
	}
	return parseAnthropicSSE(resp.Body, onText)
}

// antEvent is the union of Messages-API SSE event payloads we care about.
type antEvent struct {
	Type         string `json:"type"`
	Index        int    `json:"index"`
	ContentBlock struct {
		Type string `json:"type"`
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"content_block"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		PartialJSON string `json:"partial_json"`
		StopReason  string `json:"stop_reason"`
	} `json:"delta"`
	Message struct {
		Usage struct {
			InputTokens              int `json:"input_tokens"`
			CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     int `json:"cache_read_input_tokens"`
		} `json:"usage"`
	} `json:"message"`
	Usage struct {
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// accBlock accumulates one content block across its deltas.
type accBlock struct {
	kind  BlockKind
	text  strings.Builder
	id    string
	name  string
	input strings.Builder // tool_use input JSON, streamed as partial_json
}

func parseAnthropicSSE(body io.Reader, onText func(string)) (*Response, error) {
	out := &Response{StopReason: StopEndTurn}
	var blocks []*accBlock

	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(line[len("data:"):])
		if data == "" {
			continue
		}
		var ev antEvent
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			continue // ignore keep-alives / unparseable frames
		}
		switch ev.Type {
		case "error":
			if ev.Error != nil {
				return nil, fmt.Errorf("anthropic stream error: %s", ev.Error.Message)
			}
		case "message_start":
			out.Usage.InputTokens = ev.Message.Usage.InputTokens
			out.Usage.CacheCreationTokens = ev.Message.Usage.CacheCreationInputTokens
			out.Usage.CacheReadTokens = ev.Message.Usage.CacheReadInputTokens
		case "content_block_start":
			b := &accBlock{}
			switch ev.ContentBlock.Type {
			case "tool_use":
				b.kind = BlockToolUse
				b.id = ev.ContentBlock.ID
				b.name = ev.ContentBlock.Name
			default:
				b.kind = BlockText
			}
			blocks = append(blocks, b)
		case "content_block_delta":
			if ev.Index < 0 || ev.Index >= len(blocks) {
				continue
			}
			b := blocks[ev.Index]
			switch ev.Delta.Type {
			case "text_delta":
				b.text.WriteString(ev.Delta.Text)
				if onText != nil {
					onText(ev.Delta.Text)
				}
			case "input_json_delta":
				b.input.WriteString(ev.Delta.PartialJSON)
			}
		case "message_delta":
			if ev.Delta.StopReason != "" {
				out.StopReason = mapAntStop(ev.Delta.StopReason)
			}
			out.Usage.OutputTokens = ev.Usage.OutputTokens
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("anthropic stream read: %w", err)
	}
	for _, b := range blocks {
		switch b.kind {
		case BlockText:
			out.Blocks = append(out.Blocks, Block{Kind: BlockText, Text: b.text.String()})
		case BlockToolUse:
			in := b.input.String()
			if strings.TrimSpace(in) == "" {
				in = "{}"
			}
			out.Blocks = append(out.Blocks, Block{
				Kind: BlockToolUse, ToolID: b.id, ToolName: b.name, Input: json.RawMessage(in),
			})
		}
	}
	return out, nil
}

func toAntMessages(msgs []Message) []antMessage {
	out := make([]antMessage, 0, len(msgs))
	for _, m := range msgs {
		am := antMessage{Role: string(m.Role)}
		for _, b := range m.Blocks {
			switch b.Kind {
			case BlockText:
				am.Content = append(am.Content, antBlock{Type: "text", Text: b.Text})
			case BlockToolUse:
				am.Content = append(am.Content, antBlock{
					Type: "tool_use", ID: b.ToolID, Name: b.ToolName, Input: b.Input,
				})
			case BlockToolResult:
				am.Content = append(am.Content, antBlock{
					Type: "tool_result", ToolUseID: b.ToolUseID, Content: b.Content, IsError: b.IsError,
				})
			}
		}
		out = append(out, am)
	}
	return out
}

func toAntTools(tools []Tool) []antTool {
	if len(tools) == 0 {
		return nil
	}
	out := make([]antTool, 0, len(tools))
	for _, t := range tools {
		out = append(out, antTool{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	return out
}

func mapAntStop(s string) StopReason {
	switch s {
	case "end_turn", "stop_sequence":
		return StopEndTurn
	case "tool_use":
		return StopToolUse
	case "max_tokens":
		return StopMaxTokens
	case "refusal":
		return StopRefusal
	default:
		return StopOther
	}
}

func abbreviate(s string, max int) string {
	s = oneLine(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// oneLine collapses runs of whitespace (incl. newlines) into single spaces, so
// a multi-line JSON error body renders as one readable line.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
