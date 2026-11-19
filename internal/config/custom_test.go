package config

import "testing"

func TestAddModelPinsNewModel(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	c := DefaultConfig()

	if err := c.AddModel("kimi", "kimi-k3.1-pro"); err != nil {
		t.Fatal(err)
	}
	kimi := c.Find("kimi")
	if kimi.Models[0] != "kimi-k3.1-pro" {
		t.Fatalf("new model should be first (default pick), got %v", kimi.Models)
	}
	// Idempotent: adding again doesn't duplicate.
	before := len(kimi.Models)
	if err := c.AddModel("kimi", "kimi-k3.1-pro"); err != nil {
		t.Fatal(err)
	}
	if len(c.Find("kimi").Models) != before {
		t.Fatal("re-adding a model duplicated it")
	}
	if err := c.AddModel("nope", "x"); err == nil {
		t.Fatal("expected an error for an unknown provider")
	}
	if err := c.AddModel("kimi", "  "); err == nil {
		t.Fatal("expected an error for a blank model id")
	}
}

func TestAddProviderCustomEndpoint(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	c := DefaultConfig()

	// Keyless local endpoint.
	if err := c.AddProvider(Provider{ID: "my-llm", BaseURL: "http://localhost:8000/v1/", Models: []string{"my-model", ""}}); err != nil {
		t.Fatal(err)
	}
	p := c.Find("my-llm")
	if p == nil {
		t.Fatal("custom provider not added")
	}
	if p.Kind != KindOpenAI {
		t.Fatalf("kind should default to openai, got %q", p.Kind)
	}
	if !p.Local || !p.HasKey() {
		t.Fatal("a keyless custom endpoint should be Local and ready")
	}
	if p.BaseURL != "http://localhost:8000/v1" {
		t.Fatalf("trailing slash not trimmed: %q", p.BaseURL)
	}
	if len(p.Models) != 1 || p.Models[0] != "my-model" {
		t.Fatalf("blank model id not dropped: %v", p.Models)
	}

	// Keyed endpoint is not Local.
	if err := c.AddProvider(Provider{ID: "proxy", BaseURL: "https://llm.example.com", APIKey: "sk-1", Models: []string{"m"}}); err != nil {
		t.Fatal(err)
	}
	if pr := c.Find("proxy"); pr.Local || pr.Key() != "sk-1" {
		t.Fatalf("keyed endpoint should carry its key and not be Local: %+v", pr)
	}

	// Same id replaces, not duplicates.
	n := len(c.Providers)
	if err := c.AddProvider(Provider{ID: "my-llm", BaseURL: "http://localhost:9000/v1", Models: []string{"m2"}}); err != nil {
		t.Fatal(err)
	}
	if len(c.Providers) != n {
		t.Fatal("re-adding the same id should replace, not append")
	}
	if c.Find("my-llm").BaseURL != "http://localhost:9000/v1" {
		t.Fatal("replace didn't update the endpoint")
	}

	// Bad input.
	if err := c.AddProvider(Provider{ID: "", BaseURL: "http://x"}); err == nil {
		t.Fatal("expected an error for a blank id")
	}
	if err := c.AddProvider(Provider{ID: "bad", BaseURL: "not-a-url"}); err == nil {
		t.Fatal("expected an error for a bad base URL")
	}
}
