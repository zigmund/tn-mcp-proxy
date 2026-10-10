package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/tokens"
)

// An optional credential (the SID) is not
// verified by validate, so varying it must not yield a fresh per-grant budget.
func TestGrantKeyIgnoresOptionalCredentials(t *testing.T) {
	cfg := offLimits()
	cfg.Token = config.Limit{PerMinute: 60, Burst: 1}
	e, _, clk := limitsEnv(t, cfg, nil)

	tokWithSID := func(sid string) string {
		creds := goodCreds()
		creds["X-Tn-Sid"] = sid
		return e.token(t, seal.KindAccess, tokens.Access{Upstream: "tn", ClientID: "c", Creds: creds}, time.Hour)
	}
	if r := status(e, t, tokWithSID("sid-A")); r.StatusCode != 200 {
		t.Fatalf("first request: %d", r.StatusCode)
	}
	if r := status(e, t, tokWithSID("sid-B")); r.StatusCode != http.StatusTooManyRequests {
		t.Errorf("other SID got a fresh budget: %d", r.StatusCode)
	}
	if r := status(e, t, tokWithSID("")); r.StatusCode != http.StatusTooManyRequests {
		t.Errorf("no SID got a fresh budget: %d", r.StatusCode)
	}
	// A required credential does identify another grant.
	creds := goodCreds()
	creds["X-Tn-Api-Key"] = "key-other"
	other := e.token(t, seal.KindAccess, tokens.Access{Upstream: "tn", ClientID: "c", Creds: creds}, time.Hour)
	if r := status(e, t, other); r.StatusCode != 200 {
		t.Errorf("other required credential throttled: %d", r.StatusCode)
	}
	clk.advance(time.Second)
}

func TestGrantKeyIgnoresOptionalConcurrency(t *testing.T) {
	cfg := offLimits()
	cfg.MaxConcurrentPerToken = 1
	b := newBlocking()
	e, _, _ := limitsEnv(t, cfg, b.handle)
	defer close(b.release)

	mk := func(sid string) string {
		creds := goodCreds()
		creds["X-Tn-Sid"] = sid
		return e.token(t, seal.KindAccess, tokens.Access{Upstream: "tn", ClientID: "c", Creds: creds}, time.Hour)
	}
	a, other := mk("sid-A"), mk("sid-B")
	done := make(chan *http.Response, 1)
	go func() { done <- status(e, t, a) }()
	waitFor(t, "first request in flight", func() bool { return len(e.requests()) == 1 })
	if r := status(e, t, other); r.StatusCode != http.StatusTooManyRequests {
		t.Errorf("same key pair, other SID: %d, want 429", r.StatusCode)
	}
}

func TestGrantCredsDropsOptional(t *testing.T) {
	h := &handler{hdrs: []credHeader{{name: "X-A"}, {name: "X-B", optional: true}}}
	got := h.grantCreds(map[string]string{"X-A": "1", "X-B": "2", "X-C": "3"})
	if len(got) != 1 || got["X-A"] != "1" {
		t.Errorf("grantCreds = %v", got)
	}
}
