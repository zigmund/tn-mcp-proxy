package oauth

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

type rlEnv struct {
	srv *Server
	mux *http.ServeMux
	now time.Time
}

// newRL builds a server whose three limited endpoints allow burst requests
// (refilling one per second) per client.
func newRL(t *testing.T, burst int, mod func(*config.RateLimit)) *rlEnv {
	t.Helper()
	l := config.Limit{PerMinute: 60, Burst: burst}
	cfg := &config.Config{
		PublicURL: "https://mcp.example.com",
		OAuth: config.OAuth{
			AllowedRedirectURIs: []string{cbClaudeAI},
			RateLimit:           config.RateLimit{Register: l, Authorize: l, Token: l},
		},
	}
	if mod != nil {
		mod(&cfg.OAuth.RateLimit)
	}
	e := &rlEnv{now: fixedNow}
	e.srv = New(cfg, testSealer(t, 0), slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.srv.now = func() time.Time { return e.now }
	e.mux = http.NewServeMux()
	e.srv.Register(e.mux)
	return e
}

func (e *rlEnv) do(method, path, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(""))
	req.RemoteAddr = remote
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func TestRateLimitRegister(t *testing.T) {
	e := newRL(t, 2, nil)
	const peer = "192.0.2.10:4000"
	for i := range 2 {
		if rec := e.do("POST", PathRegister, peer, nil); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d limited within burst", i)
		}
	}
	rec := e.do("POST", PathRegister, peer, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want 1", got)
	}
	h := rec.Header()
	if h.Get("Content-Type") != "application/json" || h.Get("Cache-Control") != "no-store" ||
		h.Get("Pragma") != "no-cache" || h.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("headers = %v", h)
	}
	if h.Get("Access-Control-Expose-Headers") != "Retry-After" {
		t.Errorf("Access-Control-Expose-Headers = %q", h.Get("Access-Control-Expose-Headers"))
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "temporarily_unavailable" || body["error_description"] != "rate limit exceeded" {
		t.Errorf("body = %s", rec.Body.String())
	}

	// Recovery after refill.
	e.now = e.now.Add(time.Second)
	if rec := e.do("POST", PathRegister, peer, nil); rec.Code == http.StatusTooManyRequests {
		t.Fatal("still limited after the bucket refilled")
	}
	if rec := e.do("POST", PathRegister, peer, nil); rec.Code != http.StatusTooManyRequests {
		t.Fatal("refill must give one token only")
	}
	// A preflight is never limited.
	if rec := e.do("OPTIONS", PathRegister, peer, nil); rec.Code == http.StatusTooManyRequests {
		t.Fatal("OPTIONS limited")
	}
}

func TestRateLimitToken(t *testing.T) {
	e := newRL(t, 1, nil)
	const peer = "192.0.2.10:4000"
	if rec := e.do("POST", PathToken, peer, nil); rec.Code == http.StatusTooManyRequests {
		t.Fatal("first request limited")
	}
	rec := e.do("POST", PathToken, peer, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	h := rec.Header()
	if h.Get("Retry-After") != "1" || h.Get("Content-Type") != "application/json" ||
		h.Get("Cache-Control") != "no-store" || h.Get("Pragma") != "no-cache" {
		t.Errorf("headers = %v", h)
	}
	if h.Get("Access-Control-Allow-Origin") != "" {
		t.Error("token endpoint must not get CORS headers")
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"temporarily_unavailable","error_description":"rate limit exceeded"}` {
		t.Errorf("body = %s", got)
	}
	// Non-POST requests are neither counted nor limited (405 as before).
	if rec := e.do("GET", PathToken, peer, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /oauth/token = %d, want 405", rec.Code)
	}
}

func TestRateLimitAuthorizePost(t *testing.T) {
	e := newRL(t, 1, nil)
	const peer = "192.0.2.10:4000"
	if rec := e.do("POST", PathAuthorize, peer, nil); rec.Code == http.StatusTooManyRequests {
		t.Fatal("first request limited")
	}
	rec := e.do("POST", PathAuthorize, peer, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "1" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Errorf("headers = %v", rec.Header())
	}
	if rec.Header().Get("Location") != "" {
		t.Error("rate limit must not redirect to the client")
	}
	if !strings.Contains(rec.Body.String(), "Too many requests") {
		t.Errorf("body = %s", rec.Body.String())
	}
	// GET (the form) is never limited.
	for range 5 {
		if rec := e.do("GET", PathAuthorize, peer, nil); rec.Code == http.StatusTooManyRequests {
			t.Fatal("GET /oauth/authorize limited")
		}
	}
}

func TestRateLimitEndpointsHaveSeparateBuckets(t *testing.T) {
	e := newRL(t, 1, nil)
	const peer = "192.0.2.10:4000"
	for _, p := range []string{PathRegister, PathAuthorize, PathToken} {
		if rec := e.do("POST", p, peer, nil); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("%s limited by another endpoint's bucket", p)
		}
	}
	for _, p := range []string{PathRegister, PathAuthorize, PathToken} {
		if rec := e.do("POST", p, peer, nil); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("%s second request = %d, want 429", p, rec.Code)
		}
	}
}

func TestRateLimitPerIPAndIPv6Prefix(t *testing.T) {
	e := newRL(t, 1, nil)
	e.do("POST", PathToken, "192.0.2.10:1", nil)
	if rec := e.do("POST", PathToken, "192.0.2.10:2", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatal("same IP, other port must share the bucket")
	}
	if rec := e.do("POST", PathToken, "192.0.2.11:1", nil); rec.Code == http.StatusTooManyRequests {
		t.Fatal("different IP must not be limited")
	}
	e.do("POST", PathToken, "[2001:db8:1:2::1]:1", nil)
	if rec := e.do("POST", PathToken, "[2001:db8:1:2:aaaa::9]:1", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatal("same /64 must share the bucket")
	}
	if rec := e.do("POST", PathToken, "[2001:db8:1:3::1]:1", nil); rec.Code == http.StatusTooManyRequests {
		t.Fatal("different /64 must not be limited")
	}
}

func TestRateLimitForwardedFor(t *testing.T) {
	e := newRL(t, 1, nil)
	// Trusted (loopback) proxy: the forwarded client IP is the key.
	xff := func(ip string) map[string]string { return map[string]string{"X-Forwarded-For": ip} }
	e.do("POST", PathToken, "127.0.0.1:1", xff("203.0.113.1"))
	if rec := e.do("POST", PathToken, "127.0.0.1:2", xff("203.0.113.1")); rec.Code != http.StatusTooManyRequests {
		t.Fatal("same forwarded client must share the bucket")
	}
	if rec := e.do("POST", PathToken, "127.0.0.1:3", xff("203.0.113.2")); rec.Code == http.StatusTooManyRequests {
		t.Fatal("other forwarded client must not be limited")
	}
	// Untrusted peer: the header is ignored, so rotating it does not help.
	e.do("POST", PathToken, "192.0.2.50:1", xff("203.0.113.100"))
	if rec := e.do("POST", PathToken, "192.0.2.50:2", xff("203.0.113.101")); rec.Code != http.StatusTooManyRequests {
		t.Fatal("spoofed X-Forwarded-For from an untrusted peer bypassed the limiter")
	}
}

func TestRateLimitDisabled(t *testing.T) {
	e := newRL(t, 1, func(r *config.RateLimit) { r.Disabled = true })
	for i := range 50 {
		for _, p := range []string{PathRegister, PathAuthorize, PathToken} {
			if rec := e.do("POST", p, "192.0.2.10:1", nil); rec.Code == http.StatusTooManyRequests {
				t.Fatalf("%s limited on request %d although disabled", p, i)
			}
		}
	}
}

func TestRateLimitZeroConfigUsesDefaults(t *testing.T) {
	cfg := &config.Config{PublicURL: "https://mcp.example.com", OAuth: config.OAuth{AllowedRedirectURIs: []string{cbClaudeAI}}}
	srv := New(cfg, testSealer(t, 0), nil)
	if srv.limits == nil {
		t.Fatal("limiters must be active with default limits")
	}
	mux := http.NewServeMux()
	srv.Register(mux)
	var limited int
	for range config.DefaultAuthorizeBurst + 5 {
		req := httptest.NewRequest("POST", PathAuthorize, strings.NewReader(""))
		req.RemoteAddr = "192.0.2.10:1"
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited != 5 {
		t.Fatalf("limited = %d, want 5", limited)
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	for _, tt := range []struct {
		d    time.Duration
		want string
	}{
		{time.Millisecond, "1"}, {time.Second, "1"}, {time.Second + time.Millisecond, "2"},
		{59500 * time.Millisecond, "60"}, {0, "1"},
	} {
		if got := retryAfterSeconds(tt.d); got != tt.want {
			t.Errorf("retryAfterSeconds(%v) = %s, want %s", tt.d, got, tt.want)
		}
	}
}
