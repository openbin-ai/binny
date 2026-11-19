package llm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"openbin.ai/binny/internal/config"
)

// New builds a Provider from a configured provider entry. The key is resolved
// (BYOK) via Provider.Key() — a stored key, else the env var — at construction
// time; Bedrock uses the ambient AWS credential chain instead.
func New(p config.Provider) (Provider, error) {
	switch p.Kind {
	case config.KindOpenAI:
		key := p.Key()
		if key == "" && !p.Keyless() {
			return nil, fmt.Errorf("provider %q has no key — set one with /key (BYOK)", p.ID)
		}
		return &openAIProvider{id: p.ID, baseURL: p.BaseURL, apiKey: key, http: sharedClient()}, nil
	case config.KindAnthropic:
		key := p.Key()
		if key == "" {
			return nil, fmt.Errorf("provider %q has no key — set one with /key (BYOK)", p.ID)
		}
		return &anthropicProvider{id: p.ID, baseURL: p.BaseURL, apiKey: key, http: sharedClient()}, nil
	case config.KindBedrock:
		return &bedrockProvider{id: p.ID, region: p.Region}, nil
	default:
		return nil, fmt.Errorf("unknown provider kind %q", p.Kind)
	}
}

// sharedClient returns the HTTP client used for every provider call. It has NO
// blanket Client.Timeout on purpose: that caps the entire request including the
// streamed body, which both cuts off long turns and, when an endpoint hangs,
// makes the user wait the full 10 minutes before seeing a cryptic
// "context deadline exceeded" (exactly the kimi/api.moonshot.ai case). Instead
// the transport bounds each *phase* — connect, TLS, and time-to-response-headers
// — so an unreachable or wedged endpoint fails in ~2 minutes with a clear
// message, while a healthy stream can run as long as it needs. The request
// context (Esc / interrupt) still cancels everything.
func sharedClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 2 * time.Minute, // first response byte; covers prompt processing + TTFT
			ExpectContinueTimeout: time.Second,
			IdleConnTimeout:       90 * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
}

// describeRequestErr turns a transport-level failure (no HTTP response was ever
// received) into an actionable message naming the provider and endpoint. A bare
// "context deadline exceeded" tells the user nothing about what to do.
func describeRequestErr(provider, endpoint string, err error) error {
	if err == nil {
		return nil
	}
	host := endpoint
	if u, e := url.Parse(endpoint); e == nil && u.Host != "" {
		host = u.Host
	}
	var netErr net.Error
	timedOut := errors.As(err, &netErr) && netErr.Timeout()
	// http.Client surfaces a hit ResponseHeaderTimeout as a context-deadline error.
	if timedOut || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s (%s) didn't respond in time — it may be unreachable from your network, the endpoint or key may be wrong, or the request too large. Try another model, check the endpoint, or verify the key", provider, host)
	}
	if errors.Is(err, context.Canceled) {
		return err // user interrupt — leave as-is
	}
	return fmt.Errorf("couldn't reach %s (%s): %w — check the endpoint and your network", provider, host, err)
}
