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

// openAIProvider speaks the OpenAI Chat Completions API. The same adapter
// drives DeepSeek, Qwen (DashScope compat), Kimi (Moonshot), and Gemini's
// OpenAI-compat endpoint — they differ only by baseURL + key, so those are
// config-only with zero extra code.
type openAIProvider struct {
	id      string
	baseURL string
	apiKey  string
	http    *http.Client
}

func (p *openAIProvider) Name() string { return p.id }

// --- wire types (Chat Completions) ----------------------------------------

type oaiReq struct {
	Model         string         `json:"model"`
	Messages      []oaiMessage   `json:"messages"`
	Tools         []oaiTool      `json:"tools,omitempty"`
	MaxTokens     int            `json:"max_tokens,omitempty"`
	Stream        bool           `json:"stream"`
	StreamOptions *oaiStreamOpts `json:"stream_options,omitempty"`
}

type oaiStreamOpts struct {
	IncludeUsage bool `json:"include_usage"`
}

type oaiTool struct {
	Type     string      `json:"type"` // "function"
	Function oaiFunction `json:"function"`
}

type oaiFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters"`
}

type oaiMessage struct {
	Role       string        `json:"role"` // system|user|assistant|tool
	Content    string        `json:"content,omitempty"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"` // for role=tool
}

type oaiToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"` // "function"
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"` // JSON-encoded string
	} `json:"function"`
}

// oaiStreamChunk is one SSE delta frame.
type oaiStreamChunk struct {
	Choices []struct {
		Delta struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *oaiUsage `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// oaiUsage covers the Chat Completions usage block AND the cache-hit fields the
// compatible providers report — each under its own name. All of Kimi/OpenAI/
// Qwen/Gemini cache automatically (no breakpoints exist in this API); this just
// reads how much was served from cache so the budget can exclude it.
type oaiUsage struct {
	PromptTokens        int `json:"prompt_tokens"`
	CompletionTokens    int `json:"completion_tokens"`
	PromptTokensDetails *struct {
		CachedTokens int `json:"cached_tokens"` // OpenAI / Kimi / Qwen / Gemini
	} `json:"prompt_tokens_details"`
	PromptCacheHitTokens int `json:"prompt_cache_hit_tokens"` // DeepSeek
	CachedTokens         int `json:"cached_tokens"`           // top-level fallback
}

// cached returns tokens served from cache, whichever field the provider used.
func (u *oaiUsage) cached() int {
	if u.PromptTokensDetails != nil && u.PromptTokensDetails.CachedTokens > 0 {
		return u.PromptTokensDetails.CachedTokens
	}
	if u.PromptCacheHitTokens > 0 {
		return u.PromptCacheHitTokens
	}
	return u.CachedTokens
}

func (p *openAIProvider) Stream(ctx context.Context, req Request, onText func(string)) (*Response, error) {
	body := oaiReq{
		Model:         req.Model,
		Messages:      toOAIMessages(req.System, req.Messages),
		Tools:         toOAITools(req.Tools),
		MaxTokens:     req.MaxTokens,
		Stream:        true,
		StreamOptions: &oaiStreamOpts{IncludeUsage: true},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "text/event-stream",
	}
	if p.apiKey != "" { // a local server (Ollama, LM Studio) has no key to send
		headers["Authorization"] = "Bearer " + p.apiKey
	}
	endpoint := strings.TrimRight(p.baseURL, "/") + "/chat/completions"
	resp, err := postSSE(ctx, p.http, endpoint, headers, raw)
	if err != nil {
		return nil, describeRequestErr(p.id, endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("openai error (status %d): %s", resp.StatusCode, abbreviate(string(errBody), 400))
	}
	return parseOpenAISSE(resp.Body, req.Model, onText)
}

// oaiToolAcc accumulates one fragmented tool call across chunks.
type oaiToolAcc struct {
	id   string
	name string
	args strings.Builder
}

func parseOpenAISSE(body io.Reader, model string, onText func(string)) (*Response, error) {
	out := &Response{StopReason: StopEndTurn, Model: model}
	var text strings.Builder
	// tool calls keyed by their stream index (fragments arrive out of a single
	// call across many chunks).
	byIndex := map[int]*oaiToolAcc{}
	var order []int

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
		if data == "[DONE]" {
			break
		}
		var ch oaiStreamChunk
		if err := json.Unmarshal([]byte(data), &ch); err != nil {
			continue
		}
		if ch.Error != nil {
			return nil, fmt.Errorf("openai stream error: %s", ch.Error.Message)
		}
		if ch.Usage != nil {
			// prompt_tokens is the TOTAL input (cached + uncached) for every
			// provider here — DeepSeek's hit+miss also sums to it — so uncached =
			// prompt − cached. Budgeting on uncached mirrors the Anthropic path.
			cached := ch.Usage.cached()
			out.Usage = Usage{
				InputTokens:     ch.Usage.PromptTokens - cached,
				OutputTokens:    ch.Usage.CompletionTokens,
				CacheReadTokens: cached,
			}
		}
		if len(ch.Choices) == 0 {
			continue
		}
		c := ch.Choices[0]
		if c.Delta.Content != "" {
			text.WriteString(c.Delta.Content)
			if onText != nil {
				onText(c.Delta.Content)
			}
		}
		for _, tc := range c.Delta.ToolCalls {
			acc := byIndex[tc.Index]
			if acc == nil {
				acc = &oaiToolAcc{}
				byIndex[tc.Index] = acc
				order = append(order, tc.Index)
			}
			if tc.ID != "" {
				acc.id = tc.ID
			}
			if tc.Function.Name != "" {
				acc.name = tc.Function.Name
			}
			acc.args.WriteString(tc.Function.Arguments)
		}
		if c.FinishReason != "" {
			out.StopReason = mapOAIStop(c.FinishReason)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("openai stream read: %w", err)
	}
	if text.Len() > 0 {
		out.Blocks = append(out.Blocks, Block{Kind: BlockText, Text: text.String()})
	}
	for _, idx := range order {
		acc := byIndex[idx]
		out.Blocks = append(out.Blocks, Block{
			Kind: BlockToolUse, ToolID: acc.id, ToolName: acc.name,
			Input: json.RawMessage(orEmptyObject(acc.args.String())),
		})
	}
	return out, nil
}

// toOAIMessages flattens the internal representation into OpenAI's shape:
// system prompt → a leading system message; each internal tool_use → an
// assistant message with tool_calls; each tool_result → a role=tool message.
func toOAIMessages(system string, msgs []Message) []oaiMessage {
	var out []oaiMessage
	if system != "" {
		out = append(out, oaiMessage{Role: "system", Content: system})
	}
	for _, m := range msgs {
		switch m.Role {
		case RoleUser:
			// A user turn may carry text and/or tool_result blocks. OpenAI wants
			// tool results as their own role=tool messages, and text as a user
			// message — emit both as needed.
			var text strings.Builder
			for _, b := range m.Blocks {
				switch b.Kind {
				case BlockText:
					text.WriteString(b.Text)
				case BlockToolResult:
					out = append(out, oaiMessage{
						Role: "tool", ToolCallID: b.ToolUseID, Content: b.Content,
					})
				}
			}
			if text.Len() > 0 {
				out = append(out, oaiMessage{Role: "user", Content: text.String()})
			}
		case RoleAssistant:
			am := oaiMessage{Role: "assistant"}
			for _, b := range m.Blocks {
				switch b.Kind {
				case BlockText:
					am.Content += b.Text
				case BlockToolUse:
					tc := oaiToolCall{ID: b.ToolID, Type: "function"}
					tc.Function.Name = b.ToolName
					tc.Function.Arguments = string(orEmptyObject(string(b.Input)))
					am.ToolCalls = append(am.ToolCalls, tc)
				}
			}
			out = append(out, am)
		}
	}
	return out
}

func toOAITools(tools []Tool) []oaiTool {
	if len(tools) == 0 {
		return nil
	}
	out := make([]oaiTool, 0, len(tools))
	for _, t := range tools {
		out = append(out, oaiTool{
			Type: "function",
			Function: oaiFunction{
				Name: t.Name, Description: t.Description, Parameters: t.InputSchema,
			},
		})
	}
	return out
}

func mapOAIStop(s string) StopReason {
	switch s {
	case "stop":
		return StopEndTurn
	case "tool_calls", "function_call":
		return StopToolUse
	case "length":
		return StopMaxTokens
	case "content_filter":
		return StopRefusal
	default:
		return StopOther
	}
}

// orEmptyObject guards against providers that send an empty tool-argument
// string, which is invalid JSON when the loop tries to parse it.
func orEmptyObject(s string) string {
	if strings.TrimSpace(s) == "" {
		return "{}"
	}
	return s
}
