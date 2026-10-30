// Package config resolves BINNY's runtime endpoints, the shared openbin
// credential location, and BINNY's own LLM provider registry.
//
// BINNY deliberately reuses two separate on-disk surfaces:
//   - ~/.config/openbin/credentials.json  — the *openbin* CLI's Keycloak
//     tokens, for BACKEND auth (project read + report write). BINNY never
//     mints its own login; run `openbin login` first.
//   - ~/.config/binny/config.json         — BINNY's OWN LLM provider list
//     (BYOK). Keys live in env vars referenced by apiKeyEnv, never on disk.
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Defaults point at production, matching the openbin CLI. Local dev overrides
// with OPENBIN_API_URL / OPENBIN_AUTH_URL exactly like the CLI, so a developer
// who already points the CLI at localhost gets BINNY pointed there too.
const (
	defaultAPIBaseURL  = "https://api.openapk.ai"
	defaultAuthBaseURL = "https://auth.openapk.ai"
	keycloakRealm      = "openapk"
	// Reuse the openbin CLI's public client id — BINNY authenticates as the
	// same first-party CLI against the shared realm. (Its own client id +
	// entitlement gate arrive with the Stripe slice; free/ungated for now.)
	cliClientID = "openbin-cli"
)

// Endpoints groups the resolved backend + Keycloak URLs.
type Endpoints struct {
	APIBase  string
	AuthBase string
	Realm    string
	ClientID string
}

// LoadEndpoints resolves endpoints from env (falling back to prod), mirroring
// the openbin CLI's loadConfig so both tools agree on where the backend is.
func LoadEndpoints() Endpoints {
	return Endpoints{
		APIBase:  envOr("OPENBIN_API_URL", defaultAPIBaseURL),
		AuthBase: envOr("OPENBIN_AUTH_URL", defaultAuthBaseURL),
		Realm:    keycloakRealm,
		ClientID: cliClientID,
	}
}

// TokenEndpoint returns the Keycloak token URL (device-flow poll + refresh).
func (e Endpoints) TokenEndpoint() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		strings.TrimRight(e.AuthBase, "/"), e.Realm)
}

// DeviceAuthEndpoint returns the Keycloak device authorization URL (RFC 8628) —
// where BINNY Desktop starts the browser login flow, same as `openbin login`.
func (e Endpoints) DeviceAuthEndpoint() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth/device",
		strings.TrimRight(e.AuthBase, "/"), e.Realm)
}

// CredentialsPath returns ~/.config/openbin/credentials.json — the SAME file
// the openbin CLI writes, honoring XDG_CONFIG_HOME. BINNY reads (and refreshes)
// it but is not responsible for creating it; `openbin login` does that.
func CredentialsPath() (string, error) {
	dir, err := xdgConfigHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "openbin", "credentials.json"), nil
}

// BinnyConfigPath returns ~/.config/binny/config.json.
func BinnyConfigPath() (string, error) {
	dir, err := xdgConfigHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "binny", "config.json"), nil
}

// SessionPath returns the resume-state file for a project:
// ~/.config/binny/sessions/<sanitized-id>.json.
func SessionPath(projectID string) (string, error) {
	dir, err := xdgConfigHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "binny", "sessions", sanitizeID(projectID)+".json"), nil
}

// sanitizeID keeps a project id safe as a filename component.
func sanitizeID(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "session"
	}
	return b.String()
}

// HistoryPath returns ~/.config/binny/history — a line-delimited REPL input
// history so ↑/↓ recall works across restarts.
func HistoryPath() (string, error) {
	dir, err := xdgConfigHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "binny", "history"), nil
}

func xdgConfigHome() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return xdg, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home dir: %w", err)
	}
	return filepath.Join(home, ".config"), nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ProviderKind selects which wire adapter drives a provider. Most real
// providers are OpenAI-compatible, so `openai` + a custom BaseURL covers
// DeepSeek / Qwen / Kimi / Gemini(compat) with no new code.
type ProviderKind string

const (
	KindOpenAI    ProviderKind = "openai"    // Chat Completions + tools (+ compat via BaseURL)
	KindAnthropic ProviderKind = "anthropic" // Messages API, tool_use blocks, prompt caching
	KindBedrock   ProviderKind = "bedrock"   // Converse API; end-user AWS creds (SigV4)
)

// Provider is one configured, BYOK LLM backend.
type Provider struct {
	ID        string       `json:"id"`                  // stable handle used by /model <id>
	Kind      ProviderKind `json:"kind"`                // which adapter
	BaseURL   string       `json:"baseURL,omitempty"`   // override endpoint (compat providers, self-host)
	APIKeyEnv string       `json:"apiKeyEnv,omitempty"` // env var to read the key from (fallback)
	APIKey    string       `json:"apiKey,omitempty"`    // key stored locally (set via first-run setup / /key)
	Region    string       `json:"region,omitempty"`    // bedrock only
	Models    []string     `json:"models"`              // selectable model ids for this provider
	// Local marks a server on this machine (Ollama, LM Studio, llama.cpp,
	// vLLM): no key is needed, so the provider is ready as soon as the server
	// answers. Requests go out without an Authorization header unless a key
	// is set anyway.
	Local bool `json:"local,omitempty"`
	// ContextTokens is the model's context window when it is small enough to
	// matter (local models). The engine compacts history earlier so the
	// system prompt and tool list are never pushed out of the window.
	ContextTokens int `json:"contextTokens,omitempty"`
}

// Key resolves the provider's BYOK key: an explicitly-stored apiKey wins, else
// the env var named by apiKeyEnv. Empty when neither is set.
func (p Provider) Key() string {
	if p.APIKey != "" {
		return p.APIKey
	}
	if p.APIKeyEnv != "" {
		return os.Getenv(p.APIKeyEnv)
	}
	return ""
}

// HasKey reports whether the provider has a usable key. Bedrock uses the
// ambient AWS credential chain and a Local server needs none, so both count
// as ready without one.
func (p Provider) HasKey() bool {
	if p.Kind == KindBedrock || p.Local {
		return true
	}
	return p.Key() != ""
}

// Keyless reports whether requests may go out without a key: a Local server.
func (p Provider) Keyless() bool { return p.Local }

// DefaultTokenBudget is the per-run token cap when a project has no explicit
// budget set. Conservative for BYOK; the analyst can raise it in Settings.
const DefaultTokenBudget = 120_000

// Config is BINNY's on-disk config: the provider registry plus the
// last-selected provider/model so a session resumes where it left off.
type Config struct {
	Providers       []Provider `json:"providers"`
	DefaultProvider string     `json:"defaultProvider,omitempty"`
	DefaultModel    string     `json:"defaultModel,omitempty"`
	// ProjectBudgets maps a project id → its per-run token budget (Settings).
	ProjectBudgets map[string]int `json:"projectBudgets,omitempty"`
}

// ProjectBudget returns the token budget for a project, falling back to
// DefaultTokenBudget when none is set.
func (c *Config) ProjectBudget(projectID string) int {
	if n, ok := c.ProjectBudgets[projectID]; ok && n > 0 {
		return n
	}
	return DefaultTokenBudget
}

// SetProjectBudget stores a project's token budget and persists the config.
func (c *Config) SetProjectBudget(projectID string, budget int) error {
	if c.ProjectBudgets == nil {
		c.ProjectBudgets = map[string]int{}
	}
	c.ProjectBudgets[projectID] = budget
	return c.Save()
}

// Find returns the provider with the given id, or nil.
func (c *Config) Find(id string) *Provider {
	for i := range c.Providers {
		if c.Providers[i].ID == id {
			return &c.Providers[i]
		}
	}
	return nil
}

// Load reads BINNY's config, seeding a default provider registry on first run
// (or when the file is missing). The returned bool is true on first run (no
// config file existed yet) so the UI can offer a key-setup flow. Seeded
// providers have no key until one is set (via setup / /key) or its env var is
// populated.
func Load() (*Config, bool, error) {
	path, err := BinnyConfigPath()
	if err != nil {
		return nil, false, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return DefaultConfig(), true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read binny config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, false, fmt.Errorf("parse binny config %s: %w", path, err)
	}
	if len(c.Providers) == 0 {
		c.Providers = DefaultConfig().Providers
	}
	migrate(&c)
	return &c, false, nil
}

// migrate rewrites provider entries that still match a stale shipped default.
// Each rule keys on the FULL old default (base URL + model list) so a value the
// user deliberately changed — even back to the old default's URL with different
// models — is never clobbered, and a migrated entry never re-triggers.
func migrate(c *Config) {
	// Presets added after the user's config was first written are appended
	// (never inserted, so cursor positions in the picker stay stable). A user
	// who deleted one on purpose gets it back; they can delete it again.
	for _, d := range DefaultConfig().Providers {
		if d.Local && c.Find(d.ID) == nil {
			c.Providers = append(c.Providers, d)
		}
	}
	for i := range c.Providers {
		p := &c.Providers[i]
		// Kimi shipped pointing at the China host with retired moonshot-v1
		// models; keys from platform.kimi.ai need api.moonshot.ai and kimi-k3.
		if p.ID == "kimi" && p.BaseURL == "https://api.moonshot.cn/v1" &&
			len(p.Models) == 2 && p.Models[0] == "moonshot-v1-32k" && p.Models[1] == "moonshot-v1-128k" {
			p.BaseURL = "https://api.moonshot.ai/v1"
			p.Models = []string{"kimi-k3"}
		}
	}
}

// SetKey stores a key for a provider and persists the config. Returns an error
// for an unknown provider id.
func (c *Config) SetKey(providerID, key string) error {
	p := c.Find(providerID)
	if p == nil {
		return fmt.Errorf("unknown provider %q", providerID)
	}
	p.APIKey = key
	return c.Save()
}

// DefaultBaseURL returns the shipped endpoint for a provider id, or "" when
// the id is not one of the seeded providers (or has no HTTP endpoint).
func DefaultBaseURL(providerID string) string {
	for _, p := range DefaultConfig().Providers {
		if p.ID == providerID {
			return p.BaseURL
		}
	}
	return ""
}

// SetBaseURL points a provider at a different API root (a proxy or gateway
// such as a hosted Claude endpoint, or a self-hosted compat server) and
// persists the config. The URL must carry an http(s) scheme and a host; the
// path is kept as given because compat providers differ in whether /v1 is
// part of the root. Bedrock is SDK-driven and has no endpoint to override.
func (c *Config) SetBaseURL(providerID, rawURL string) error {
	p := c.Find(providerID)
	if p == nil {
		return fmt.Errorf("unknown provider %q", providerID)
	}
	if p.Kind == KindBedrock {
		return fmt.Errorf("provider %q uses the AWS SDK; set AWS_ENDPOINT_URL in your environment instead", providerID)
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("endpoint must be a full URL like https://anthropic.example.com (got %q)", rawURL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("endpoint must not carry a query string or fragment")
	}
	p.BaseURL = strings.TrimRight(u.String(), "/")
	return c.Save()
}

// HasConfiguredKey reports whether any provider has a real BYOK key (stored or
// via env). Used to decide whether to offer first-run key setup — unlike
// HasKey, this does NOT count Bedrock's ambient AWS readiness, so a fresh
// install still gets the setup prompt.
func (c *Config) HasConfiguredKey() bool {
	for i := range c.Providers {
		if c.Providers[i].Key() != "" {
			return true
		}
	}
	return false
}

// Save persists the config (used to remember the last /model choice).
func (c *Config) Save() error {
	path, err := BinnyConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir binny config dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// DefaultConfig seeds the provider registry from the locked provider plan:
// Anthropic (flagship, native), OpenAI, the OpenAI-compat family (DeepSeek /
// Qwen / Kimi / Gemini) as BaseURL presets, and Bedrock. Model lists are
// starting points the user can edit in config.json.
func DefaultConfig() *Config {
	return &Config{
		DefaultProvider: "anthropic",
		DefaultModel:    "claude-opus-4-8",
		Providers: []Provider{
			{
				ID: "anthropic", Kind: KindAnthropic,
				BaseURL: "https://api.anthropic.com", APIKeyEnv: "ANTHROPIC_API_KEY",
				// Current Claude family (2026). Fable 5 is the most capable for
				// long-horizon RE reasoning; Opus 4.8 is the balanced default.
				Models: []string{"claude-opus-4-8", "claude-fable-5", "claude-sonnet-5", "claude-haiku-4-5"},
			},
			{
				ID: "openai", Kind: KindOpenAI,
				BaseURL: "https://api.openai.com/v1", APIKeyEnv: "OPENAI_API_KEY",
				Models: []string{"gpt-4o", "gpt-4o-mini", "o3-mini"},
			},
			{
				ID: "deepseek", Kind: KindOpenAI,
				BaseURL: "https://api.deepseek.com/v1", APIKeyEnv: "DEEPSEEK_API_KEY",
				Models: []string{"deepseek-chat", "deepseek-reasoner"},
			},
			{
				ID: "qwen", Kind: KindOpenAI,
				BaseURL: "https://dashscope.aliyuncs.com/compatible-mode/v1", APIKeyEnv: "DASHSCOPE_API_KEY",
				Models: []string{"qwen-max", "qwen-plus"},
			},
			{
				ID: "kimi", Kind: KindOpenAI,
				// International endpoint — keys from platform.kimi.ai only work
				// against api.moonshot.ai, not the .cn (China) host.
				BaseURL: "https://api.moonshot.ai/v1", APIKeyEnv: "MOONSHOT_API_KEY",
				Models: []string{"kimi-k3"},
			},
			{
				ID: "gemini", Kind: KindOpenAI,
				BaseURL: "https://generativelanguage.googleapis.com/v1beta/openai", APIKeyEnv: "GEMINI_API_KEY",
				Models: []string{"gemini-2.0-flash", "gemini-1.5-pro"},
			},
			{
				ID: "bedrock", Kind: KindBedrock,
				Region: "us-east-1",
				Models: []string{"anthropic.claude-opus-4-8", "anthropic.claude-sonnet-5"},
			},
			// Local servers. Both expose the OpenAI API without a key; the live
			// /models call lists whatever the user has pulled, so the static
			// lists below are only the fallback. llama.cpp (llama-server) and
			// vLLM work the same way: /endpoint ollama http://host:8080/v1.
			{
				ID: "ollama", Kind: KindOpenAI, Local: true,
				BaseURL: "http://localhost:11434/v1",
				Models:  []string{"qwen3:14b", "gpt-oss:20b", "llama3.1:8b"},
				// Ollama's default window is 4k; see the hint printed on pick.
				ContextTokens: 32768,
			},
			{
				ID: "lmstudio", Kind: KindOpenAI, Local: true,
				BaseURL:       "http://localhost:1234/v1",
				Models:        []string{},
				ContextTokens: 32768,
			},
		},
	}
}

// LocalProviderIDs lists the shipped keyless presets, in registry order.
func LocalProviderIDs() []string {
	var ids []string
	for _, p := range DefaultConfig().Providers {
		if p.Local {
			ids = append(ids, p.ID)
		}
	}
	return ids
}
