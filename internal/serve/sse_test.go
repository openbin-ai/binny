package serve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openbin.ai/binny/internal/config"
)

// A malformed json.RawMessage (truncated tool arguments from a local model) used
// to make json.Marshal fail; the ignored error wrote a bare "data: \n\n" frame
// and the browser died on JSON.parse("") — "unexpected end of data" — taking the
// whole chat stream down. marshalSSE must now emit a valid frame instead.
func TestMarshalSSENeverEmitsBrokenFrame(t *testing.T) {
	ev := map[string]any{
		"type":  "tool_call",
		"name":  "get_function",
		"input": json.RawMessage(`{"name":"FUN_00008790"`), // truncated: invalid JSON
	}
	b := marshalSSE(ev)
	if len(b) == 0 {
		t.Fatal("marshalSSE returned empty bytes — would write `data: \\n\\n`")
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("marshalSSE produced invalid JSON %q: %v", b, err)
	}
	if got["type"] != "error" {
		t.Fatalf("expected a fallback error event, got %q", got["type"])
	}
}

func TestMarshalSSEPassesValidEvents(t *testing.T) {
	ev := map[string]any{"type": "chunk", "text": "hello"}
	var got map[string]any
	if err := json.Unmarshal(marshalSSE(ev), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got["type"] != "chunk" || got["text"] != "hello" {
		t.Fatalf("event mangled: %v", got)
	}
}

func TestToolCallInput(t *testing.T) {
	// Valid arguments pass through as raw JSON (object), so the card renders them.
	valid := json.RawMessage(`{"name":"FUN_00008790"}`)
	if _, ok := toolCallInput(valid).(json.RawMessage); !ok {
		t.Fatal("valid input should pass through as json.RawMessage")
	}
	// Malformed arguments fall back to a JSON string so the whole event still
	// marshals (and the card still shows what the model tried).
	bad := json.RawMessage(`{"name":`)
	s, ok := toolCallInput(bad).(string)
	if !ok || s != `{"name":` {
		t.Fatalf("malformed input should become the raw string, got %#v", toolCallInput(bad))
	}
	// A whole tool_call event with malformed input must still marshal cleanly.
	b := marshalSSE(map[string]any{"type": "tool_call", "name": "x", "input": toolCallInput(bad)})
	if err := json.Unmarshal(b, new(map[string]any)); err != nil {
		t.Fatalf("event with sanitized input did not marshal: %v", err)
	}
}

// A user with no openbin account can set a BYOK key from the desktop UI; it is
// persisted and applied live, so the provider becomes usable without a restart.
func TestHandleKeyStoresAndActivates(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // don't touch the real ~/.config

	s := &server{opts: Options{Providers: []config.Provider{
		{ID: "anthropic", Kind: config.KindAnthropic, Models: []string{"claude-x"}},
	}}}
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	// Before: not ready, no stored key.
	if got := fetchConfig(t, srv.URL); got["anthropic"].Ready {
		t.Fatal("provider should not be ready before a key is set")
	}

	// Set the key.
	resp, err := http.Post(srv.URL+"/api/key", "application/json",
		strings.NewReader(`{"providerId":"anthropic","key":"sk-test-123"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/key: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// After: ready, stored key — and the live registry resolves it.
	got := fetchConfig(t, srv.URL)
	if !got["anthropic"].Ready || !got["anthropic"].StoredKey {
		t.Fatalf("provider not activated after key set: %+v", got["anthropic"])
	}
	if p, err := s.resolveProvider(chatRequest{ProviderID: "anthropic"}); err != nil || p.Key() != "sk-test-123" {
		t.Fatalf("resolveProvider didn't pick up the live key: key=%q err=%v", p.Key(), err)
	}

	// Clearing it (empty key) drops the stored key again.
	resp, _ = http.Post(srv.URL+"/api/key", "application/json",
		strings.NewReader(`{"providerId":"anthropic","key":""}`))
	resp.Body.Close()
	if fetchConfig(t, srv.URL)["anthropic"].StoredKey {
		t.Fatal("stored key should be cleared by an empty key")
	}
}

type cfgProv struct {
	Ready     bool `json:"ready"`
	StoredKey bool `json:"storedKey"`
}

func fetchConfig(t *testing.T, base string) map[string]cfgProv {
	t.Helper()
	resp, err := http.Get(base + "/api/config")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Providers []struct {
			ID string `json:"id"`
			cfgProv
		} `json:"providers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	m := map[string]cfgProv{}
	for _, p := range out.Providers {
		m[p.ID] = p.cfgProv
	}
	return m
}
