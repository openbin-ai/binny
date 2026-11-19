package serve

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openbin.ai/binny/internal/config"
)

// A busy fixed port must fall back to the next one (so BINNY Desktop keeps a
// stable origin and doesn't wipe localStorage), while :0 and fallback-off bind
// exactly once.
func TestListenPortFallback(t *testing.T) {
	// Occupy a port, then ask listen to bind it with fallback on.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	addr := busy.Addr().String()

	ln, err := listen(addr, true)
	if err != nil {
		t.Fatalf("fallback should have found a nearby port: %v", err)
	}
	defer ln.Close()
	if ln.Addr().String() == addr {
		t.Fatal("expected a different port than the busy one")
	}

	// Without fallback, binding a busy port fails.
	if ln2, err := listen(addr, false); err == nil {
		ln2.Close()
		t.Fatal("expected a bind error without fallback")
	}
}

func TestHandleAddModelAndProvider(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	s := &server{opts: Options{Providers: config.DefaultConfig().Providers}}
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	// Pin a model the shipped kimi list doesn't name.
	resp, err := http.Post(srv.URL+"/api/model", "application/json",
		strings.NewReader(`{"providerId":"kimi","model":"kimi-k3.1-pro"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("/api/model: %d", resp.StatusCode)
	}
	resp.Body.Close()

	got := fetchConfig(t, srv.URL)
	if _, ok := got["kimi"]; !ok {
		t.Fatal("kimi missing from config")
	}
	// The live registry now resolves the pinned model as kimi's default.
	s.mu.RLock()
	kimi := func() *config.Provider {
		for i := range s.opts.Providers {
			if s.opts.Providers[i].ID == "kimi" {
				return &s.opts.Providers[i]
			}
		}
		return nil
	}()
	firstModel := ""
	if kimi != nil && len(kimi.Models) > 0 {
		firstModel = kimi.Models[0]
	}
	s.mu.RUnlock()
	if firstModel != "kimi-k3.1-pro" {
		t.Fatalf("pinned model not applied to live registry: %q", firstModel)
	}

	// Add a keyless custom OpenAI-compatible endpoint.
	resp, err = http.Post(srv.URL+"/api/provider", "application/json",
		strings.NewReader(`{"id":"my-llm","baseURL":"http://localhost:8000/v1","models":["my-model"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("/api/provider: %d", resp.StatusCode)
	}
	resp.Body.Close()

	if cfg := fetchConfig(t, srv.URL); !cfg["my-llm"].Ready {
		t.Fatal("keyless custom endpoint should be ready")
	}
	if p, err := s.resolveProvider(chatRequest{ProviderID: "my-llm", Model: "my-model"}); err != nil || p.BaseURL != "http://localhost:8000/v1" {
		t.Fatalf("resolveProvider didn't pick up the custom endpoint: %+v err=%v", p, err)
	}

	// A bad endpoint is rejected.
	resp, _ = http.Post(srv.URL+"/api/provider", "application/json",
		strings.NewReader(`{"id":"bad","baseURL":"not-a-url","models":["m"]}`))
	if resp.StatusCode == 200 {
		t.Fatal("expected a 4xx for a bad base URL")
	}
	resp.Body.Close()
}
