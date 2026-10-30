package auth

// Browser login for BINNY Desktop. The CLI (and the TUI) rely on `openbin login`
// having run first; the GUI can't ask the user to drop to a terminal, so we port
// the openbin CLI's OAuth 2.0 device authorization grant (RFC 8628) here. The
// token shape + on-disk file are identical, so a login done in the desktop also
// satisfies the CLI and vice-versa (both read ~/.config/openbin/credentials.json).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"openbin.ai/binny/internal/config"
)

// DeviceLogin is an in-progress device-authorization login. Show the user
// VerificationURIComplete (or VerificationURI + UserCode), then call Poll.
type DeviceLogin struct {
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`

	deviceCode string // kept private: the secret the token poll exchanges
}

// Account is the identity behind the stored credentials, for display.
type Account struct {
	LoggedIn bool   `json:"loggedIn"`
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
	Name     string `json:"name,omitempty"`
	Endpoint string `json:"endpoint,omitempty"` // API base, so the UI can show which instance
}

// StartDeviceLogin kicks off the device grant: returns a code + URL to show the
// user. It does not block; call Poll to wait for them to finish in the browser.
func StartDeviceLogin(ep config.Endpoints) (*DeviceLogin, error) {
	form := url.Values{
		"client_id": {ep.ClientID},
		"scope":     {"openid profile email offline_access"},
	}
	resp, err := http.PostForm(ep.DeviceAuthEndpoint(), form)
	if err != nil {
		return nil, fmt.Errorf("device auth request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("device auth failed: status=%d body=%s",
			resp.StatusCode, abbreviate(string(body), 300))
	}
	var dc struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &dc); err != nil {
		return nil, fmt.Errorf("parse device auth response: %w", err)
	}
	if dc.Interval <= 0 {
		dc.Interval = 5
	}
	return &DeviceLogin{
		UserCode:                dc.UserCode,
		VerificationURI:         dc.VerificationURI,
		VerificationURIComplete: dc.VerificationURIComplete,
		ExpiresIn:               dc.ExpiresIn,
		Interval:                dc.Interval,
		deviceCode:              dc.DeviceCode,
	}, nil
}

// Poll waits for the user to confirm in the browser, then saves the credentials
// to the shared openbin file. Honors ctx cancellation and the device-code
// deadline. Mirrors the openbin CLI's pollDeviceFlow backoff rules (RFC 8628).
func (d *DeviceLogin) Poll(ctx context.Context, ep config.Endpoints) (*Account, error) {
	interval := time.Duration(d.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(d.ExpiresIn) * time.Second)

	for {
		if time.Now().After(deadline) {
			return nil, errors.New("code expired before login completed — start again")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		form := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {d.deviceCode},
			"client_id":   {ep.ClientID},
		}
		resp, err := http.PostForm(ep.TokenEndpoint(), form)
		if err != nil {
			continue // transient; the device flow tolerates network blips
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var tr struct {
			AccessToken      string `json:"access_token"`
			RefreshToken     string `json:"refresh_token"`
			ExpiresIn        int    `json:"expires_in"`
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &tr)

		if resp.StatusCode == 200 && tr.AccessToken != "" {
			creds := &credentials{
				AccessToken:  tr.AccessToken,
				RefreshToken: tr.RefreshToken,
				ExpiresAt:    time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
				AuthBase:     ep.AuthBase,
				Realm:        ep.Realm,
				ClientID:     ep.ClientID,
			}
			if err := saveCredentials(creds); err != nil {
				return nil, err
			}
			acct := accountFromToken(tr.AccessToken)
			acct.LoggedIn = true
			acct.Endpoint = ep.APIBase
			return &acct, nil
		}
		switch tr.Error {
		case "authorization_pending":
			// not confirmed yet — keep polling
		case "slow_down":
			interval += 5 * time.Second
		case "expired_token":
			return nil, errors.New("code expired — start again")
		case "access_denied":
			return nil, errors.New("login denied")
		default:
			return nil, fmt.Errorf("login failed: status=%d error=%q desc=%q",
				resp.StatusCode, tr.Error, tr.ErrorDescription)
		}
	}
}

// Status reports who is logged in, refreshing the token if needed so a stale
// (but refreshable) session still shows as logged in.
func Status(ep config.Endpoints) (Account, error) {
	c, err := loadCredentials()
	if err != nil {
		return Account{}, err
	}
	if c == nil {
		return Account{LoggedIn: false, Endpoint: ep.APIBase}, nil
	}
	// A refresh here both validates the session and yields a fresh access
	// token to read claims from. Build a TokenSource to reuse its refresh.
	ts := &TokenSource{ep: ep, cur: c}
	tok, err := ts.Token()
	if err != nil {
		// Refresh token is dead/expired: treat as logged out (don't error the UI).
		return Account{LoggedIn: false, Endpoint: ep.APIBase}, nil
	}
	acct := accountFromToken(tok)
	acct.LoggedIn = true
	acct.Endpoint = ep.APIBase
	return acct, nil
}

// Logout deletes the stored credentials (shared with the openbin CLI).
func Logout() error {
	path, err := config.CredentialsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// accountFromToken reads display claims from a JWT access token without
// verifying it (the server verified it; we only want email/name for the UI).
func accountFromToken(tok string) Account {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return Account{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Account{}
	}
	var claims struct {
		Email    string `json:"email"`
		Username string `json:"preferred_username"`
		Name     string `json:"name"`
	}
	_ = json.Unmarshal(payload, &claims)
	return Account{Email: claims.Email, Username: claims.Username, Name: claims.Name}
}
