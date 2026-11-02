package serve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"openbin.ai/binny/internal/config"
)

// isolateCreds points XDG_CONFIG_HOME at an empty temp dir so these tests see a
// logged-out state and never read or write the developer's real credentials.
func isolateCreds(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

func newConnectedServer() *server {
	return &server{opts: Options{}, ep: config.LoadEndpoints()}
}

func TestAuthStatusLoggedOut(t *testing.T) {
	isolateCreds(t)
	s := newConnectedServer()
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/auth/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var acct map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&acct); err != nil {
		t.Fatal(err)
	}
	if acct["loggedIn"] != false {
		t.Errorf("loggedIn = %v, want false", acct["loggedIn"])
	}
}

func TestProjectsRequiresLogin(t *testing.T) {
	isolateCreds(t)
	s := newConnectedServer()
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/projects")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["loggedIn"] != false {
		t.Errorf("loggedIn = %v, want false", body["loggedIn"])
	}
}

func TestOpenProjectRequiresLogin(t *testing.T) {
	isolateCreds(t)
	s := newConnectedServer()
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/project/open?id=abc", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestOpenProjectMissingID(t *testing.T) {
	isolateCreds(t)
	s := newConnectedServer()
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/project/open", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestLogoutOK(t *testing.T) {
	isolateCreds(t)
	s := newConnectedServer()
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/auth/logout", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestHealthReportsProject(t *testing.T) {
	s := newConnectedServer()
	s.setDirProject("/tmp/whatever/src", "proj-123")
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["projectId"] != "proj-123" {
		t.Errorf("projectId = %v, want proj-123", body["projectId"])
	}
	// setDir (a local tree) must clear the project id.
	s.setDir("/tmp/local/src")
	if got := s.projectID(); got != "" {
		t.Errorf("after setDir, projectID = %q, want empty", got)
	}
}
