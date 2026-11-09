package serve

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRunReportsListenURL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	urlCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, Options{Addr: "127.0.0.1:0", OnListen: func(u string) { urlCh <- u }})
	}()
	var u string
	select {
	case u = <-urlCh:
	case err := <-errCh:
		t.Fatalf("Run exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("OnListen never called")
	}
	if !strings.HasPrefix(u, "http://127.0.0.1:") || strings.HasSuffix(u, ":0") {
		t.Fatalf("url = %q, want a real loopback port", u)
	}
	resp, err := http.Get(u + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("Run returned %v after cancel", err)
	}
}

func TestBrowserCommandPerOS(t *testing.T) {
	for goos, want := range map[string]string{"linux": "xdg-open", "darwin": "open", "windows": "rundll32"} {
		name, args := browserCommand(goos, "http://127.0.0.1:1")
		if name != want || args[len(args)-1] != "http://127.0.0.1:1" {
			t.Errorf("%s: %s %v", goos, name, args)
		}
	}
}
