// Package auth handles backend (Keycloak) authentication, sharing the openbin
// CLI's on-disk credentials (~/.config/openbin/credentials.json) so a login in
// either tool satisfies the other. This file reads + refreshes those tokens;
// login.go adds the device-authorization browser flow BINNY Desktop uses to log
// in on its own (the CLI/TUI still rely on `openbin login`). Both mirror
// cli/auth.go so token shape + refresh policy stay in sync.
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"openbin.ai/binny/internal/config"
)

// credentials is the on-disk shape written by the openbin CLI.
type credentials struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	AuthBase     string    `json:"auth_base"`
	Realm        string    `json:"realm"`
	ClientID     string    `json:"client_id"`
}

// TokenSource yields a valid bearer token, refreshing when near expiry. It is
// safe for concurrent use by the agent's tool calls. The zero value is not
// usable; construct with NewTokenSource.
type TokenSource struct {
	ep  config.Endpoints
	mu  sync.Mutex
	cur *credentials
}

// NewTokenSource loads stored credentials once. Returns an error (surfaced to
// the user as "run `openbin login` first") when the user isn't logged in.
func NewTokenSource(ep config.Endpoints) (*TokenSource, error) {
	c, err := loadCredentials()
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, errors.New("not logged in — run `openbin login` first")
	}
	return &TokenSource{ep: ep, cur: c}, nil
}

// Token returns a currently-valid access token, refreshing if it expires
// within 30s (matching the CLI's pre-flight refresh window).
func (t *TokenSource) Token() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if time.Until(t.cur.ExpiresAt) < 30*time.Second {
		if err := t.refresh(); err != nil {
			return "", err
		}
	}
	return t.cur.AccessToken, nil
}

func (t *TokenSource) refresh() error {
	if t.cur.RefreshToken == "" {
		return errors.New("no refresh token — run `openbin login` again")
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.cur.RefreshToken},
		"client_id":     {t.ep.ClientID},
	}
	resp, err := http.PostForm(t.ep.TokenEndpoint(), form)
	if err != nil {
		return fmt.Errorf("refresh request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("refresh failed: status=%d body=%s",
			resp.StatusCode, abbreviate(string(body), 300))
	}
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return fmt.Errorf("parse refresh response: %w", err)
	}
	t.cur.AccessToken = tr.AccessToken
	if tr.RefreshToken != "" {
		t.cur.RefreshToken = tr.RefreshToken // Keycloak may rotate it
	}
	t.cur.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return saveCredentials(t.cur)
}

func loadCredentials() (*credentials, error) {
	path, err := config.CredentialsPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	var c credentials
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse credentials at %s: %w", path, err)
	}
	return &c, nil
}

func saveCredentials(c *credentials) error {
	path, err := config.CredentialsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir credentials dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func abbreviate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
