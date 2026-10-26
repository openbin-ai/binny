package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A local runtime that answers /v1/models with the standard shape is detected and
// its models surfaced; a dead address is silently skipped.
func TestDetectLocal(t *testing.T) {
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"qwen2.5-coder:7b"},{"id":"llama3.1:8b"}]}`))
	}))
	defer live.Close()

	got := detectLocal(context.Background(), []localCandidate{
		{"Live", live.URL + "/v1"},
		{"Dead", "http://127.0.0.1:1/v1"}, // nothing listens on port 1
	})

	if len(got) != 1 {
		t.Fatalf("expected 1 detected runtime, got %d: %+v", len(got), got)
	}
	rt := got[0]
	if rt.Name != "Live" {
		t.Errorf("name = %q, want Live", rt.Name)
	}
	if len(rt.Models) != 2 || rt.Models[0] != "llama3.1:8b" || rt.Models[1] != "qwen2.5-coder:7b" {
		t.Errorf("models = %v, want sorted [llama3.1:8b qwen2.5-coder:7b]", rt.Models)
	}
}

// A server that doesn't answer /models (not an inference server) is not reported.
func TestDetectLocalIgnoresNonModelServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	got := detectLocal(context.Background(), []localCandidate{{"NotLLM", srv.URL + "/v1"}})
	if len(got) != 0 {
		t.Fatalf("expected nothing detected, got %+v", got)
	}
}
