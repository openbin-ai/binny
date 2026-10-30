package auth

import (
	"encoding/base64"
	"strings"
	"testing"

	"openbin.ai/binny/internal/config"
)

func TestAccountFromToken(t *testing.T) {
	// A JWT is header.payload.signature; we only read the payload claims.
	payload := base64.RawURLEncoding.EncodeToString([]byte(
		`{"email":"husam@keycomagix.com","preferred_username":"husam","name":"Husam Abdalla"}`))
	tok := "eyJhbGciOiJSUzI1NiJ9." + payload + ".sig"

	acct := accountFromToken(tok)
	if acct.Email != "husam@keycomagix.com" {
		t.Errorf("email = %q", acct.Email)
	}
	if acct.Username != "husam" {
		t.Errorf("username = %q", acct.Username)
	}
	if acct.Name != "Husam Abdalla" {
		t.Errorf("name = %q", acct.Name)
	}
}

func TestAccountFromTokenGarbage(t *testing.T) {
	// Must not panic on malformed tokens.
	for _, tok := range []string{"", "notajwt", "a.b", "a..c"} {
		_ = accountFromToken(tok)
	}
}

func TestStatusLoggedOut(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // no credentials file
	acct, err := Status(config.LoadEndpoints())
	if err != nil {
		t.Fatal(err)
	}
	if acct.LoggedIn {
		t.Errorf("LoggedIn = true, want false with no credentials")
	}
}

func TestDeviceAuthEndpoint(t *testing.T) {
	ep := config.Endpoints{AuthBase: "https://auth.example.com/", Realm: "openapk"}
	got := ep.DeviceAuthEndpoint()
	want := "https://auth.example.com/realms/openapk/protocol/openid-connect/auth/device"
	if got != want {
		t.Errorf("DeviceAuthEndpoint() = %q, want %q", got, want)
	}
	if !strings.HasSuffix(ep.TokenEndpoint(), "/protocol/openid-connect/token") {
		t.Errorf("TokenEndpoint() = %q", ep.TokenEndpoint())
	}
}

func TestLogoutNoCredentials(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := Logout(); err != nil { // deleting a non-existent file is not an error
		t.Errorf("Logout() with no credentials: %v", err)
	}
}
