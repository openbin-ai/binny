package llm

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "i/o timeout" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return true }

func TestDescribeRequestErr(t *testing.T) {
	// A timeout (net.Error or a context deadline) → actionable message naming the
	// provider host, not a bare "context deadline exceeded".
	for _, err := range []error{fakeTimeout{}, context.DeadlineExceeded} {
		got := describeRequestErr("kimi", "https://api.moonshot.ai/v1/chat/completions", err)
		if got == nil || !strings.Contains(got.Error(), "didn't respond in time") || !strings.Contains(got.Error(), "api.moonshot.ai") {
			t.Fatalf("timeout message not actionable: %v", got)
		}
	}
	// A user interrupt passes through untouched so the UI can treat it as a stop.
	if got := describeRequestErr("kimi", "https://x/y", context.Canceled); !errors.Is(got, context.Canceled) {
		t.Fatalf("cancel should pass through, got %v", got)
	}
	// A generic dial failure still names the host.
	got := describeRequestErr("openai", "https://api.openai.com/v1/chat/completions", errors.New("connection refused"))
	if got == nil || !strings.Contains(got.Error(), "api.openai.com") || !strings.Contains(got.Error(), "couldn't reach") {
		t.Fatalf("generic error not helpful: %v", got)
	}
	if describeRequestErr("x", "y", nil) != nil {
		t.Fatal("nil error must stay nil")
	}
}

// The shared client must NOT impose a blanket total timeout (which would cut off
// long streams and make a hung endpoint wait the full timeout), but must bound
// time-to-response-headers so a wedged endpoint fails fast.
func TestSharedClientTimeouts(t *testing.T) {
	c := sharedClient()
	if c.Timeout != 0 {
		t.Errorf("client should have no blanket timeout, got %v", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected a configured *http.Transport")
	}
	if tr.ResponseHeaderTimeout == 0 || tr.ResponseHeaderTimeout > 5*time.Minute {
		t.Errorf("ResponseHeaderTimeout should be set and modest, got %v", tr.ResponseHeaderTimeout)
	}
	if tr.TLSHandshakeTimeout == 0 {
		t.Error("TLSHandshakeTimeout should be set")
	}
}
