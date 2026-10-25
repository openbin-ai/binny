package tui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openbin.ai/binny/internal/api"
	"openbin.ai/binny/internal/config"
)

type staticToken struct{}

func (staticToken) Token() (string, error) { return "t", nil }

func statusServer(t *testing.T, statuses ...string) *api.Client {
	t.Helper()
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		st := statuses[len(statuses)-1]
		if i < len(statuses) {
			st = statuses[i]
		}
		i++
		json.NewEncoder(w).Encode(api.Project{ID: "p1", Name: "evil.apk", Status: st, ErrorMessage: "boom"})
	}))
	t.Cleanup(srv.Close)
	return api.New(config.Endpoints{APIBase: srv.URL}, staticToken{})
}

func TestWaitReadyFollowsIngest(t *testing.T) {
	p, err := waitReady(statusServer(t, "DECOMPILING", "DECOMPILING", "READY"), "p1", time.Second, time.Millisecond)
	if err != nil || p.Status != "READY" {
		t.Fatalf("waitReady = %+v, %v", p, err)
	}
	if _, err := waitReady(statusServer(t, "FAILED"), "p1", time.Second, time.Millisecond); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("FAILED ingest error = %v", err)
	}
	if _, err := waitReady(statusServer(t, "DECOMPILING"), "p1", 20*time.Millisecond, time.Millisecond); err == nil || !strings.Contains(err.Error(), "still DECOMPILING") {
		t.Errorf("timeout error = %v", err)
	}
}
