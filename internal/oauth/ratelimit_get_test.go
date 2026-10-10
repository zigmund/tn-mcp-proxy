package oauth

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

func TestRateLimitAuthorizeForm(t *testing.T) {
	e := newRL(t, 1, func(r *config.RateLimit) { r.AuthorizeForm = config.Limit{PerMinute: 60, Burst: 2} })
	const peer = "192.0.2.10:4000"
	for i := range 2 {
		if rec := e.do("GET", PathAuthorize, peer, nil); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("GET %d limited within burst", i)
		}
	}
	rec := e.do("GET", PathAuthorize, peer, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want 1", got)
	}
	// HEAD is served by the GET route and is charged to the same bucket.
	if rec := e.do("HEAD", PathAuthorize, peer, nil); rec.Code != http.StatusTooManyRequests {
		t.Errorf("HEAD status = %d, want 429", rec.Code)
	}
	// Another client is unaffected.
	if rec := e.do("GET", PathAuthorize, "192.0.2.11:4000", nil); rec.Code == http.StatusTooManyRequests {
		t.Error("other client limited")
	}
	// The POST bucket is separate: still has its own burst of 1.
	if rec := e.do("POST", PathAuthorize, peer, nil); rec.Code == http.StatusTooManyRequests {
		t.Error("POST charged to the GET bucket")
	}
}

func TestRateLimitAuthorizeFormDefaultsAndGlobal(t *testing.T) {
	// The default is several times the POST limit, and GET never touches the
	// global POST ceiling (which is set to 1 here).
	e := newRL(t, 1, func(r *config.RateLimit) { r.AuthorizeGlobal = config.Limit{PerMinute: 1, Burst: 1} })
	if config.DefaultAuthorizeFormPerMinute < 5*config.DefaultAuthorizePerMinute {
		t.Fatalf("default form limit %d is not generous", config.DefaultAuthorizeFormPerMinute)
	}
	passed := 0
	for i := range config.DefaultAuthorizeFormBurst + 20 {
		if e.do("GET", PathAuthorize, "192.0.2.10:4000", nil).Code != http.StatusTooManyRequests {
			passed++
		}
		_ = i
	}
	if passed != config.DefaultAuthorizeFormBurst {
		t.Fatalf("passed = %d, want the default burst %d", passed, config.DefaultAuthorizeFormBurst)
	}
	// Many distinct clients: the global ceiling does not apply to GET.
	for i := range 20 {
		if rec := e.do("GET", PathAuthorize, fmt.Sprintf("198.51.100.%d:1", i+1), nil); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("client %d limited by the global ceiling", i)
		}
	}
}

func TestRateLimitAuthorizeFormDisabled(t *testing.T) {
	e := newRL(t, 1, func(r *config.RateLimit) { r.Disabled = true })
	for range 1000 {
		if e.do("GET", PathAuthorize, "192.0.2.10:4000", nil).Code == http.StatusTooManyRequests {
			t.Fatal("limited although rate limiting is disabled")
		}
	}
}

func TestRateLimitAuthorizeFormIPv6Tiers(t *testing.T) {
	// /64: 1, /56: 4, /48: 16 for the form limiter.
	e := newRL(t, 1, func(r *config.RateLimit) { r.AuthorizeForm = config.Limit{PerMinute: 60, Burst: 1} })
	passed := 0
	for i := range 300 { // one /64 each, spread over the /56s of 2001:db8:2::/48
		ip := fmt.Sprintf("[2001:db8:2:%x::1]:1", (i%256)<<8)
		if e.do("GET", PathAuthorize, ip, nil).Code != http.StatusTooManyRequests {
			passed++
		}
	}
	if passed != 16 {
		t.Errorf("one /48 passed %d GETs, want 16", passed)
	}
	if e.do("GET", PathAuthorize, "[2001:db8:3::1]:1", nil).Code == http.StatusTooManyRequests {
		t.Error("unrelated /48 limited")
	}
}
