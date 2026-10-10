package oauth

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func TestRateLimitIPv6Hierarchy(t *testing.T) {
	e := newRL(t, 1, nil) // /64: 1, /56: 4, /48: 16 per endpoint
	count := func(f func(i int) string) (passed int) {
		for i := range 300 {
			if e.do("POST", PathToken, f(i), nil).Code != http.StatusTooManyRequests {
				passed++
			}
		}
		return passed
	}
	// Distinct /64s in one /56 stop at the /56 budget.
	if got := count(func(i int) string { return fmt.Sprintf("[2001:db8:1:%x::1]:1", 0x100+i%256) }); got != 4 {
		t.Errorf("one /56 passed %d, want 4", got)
	}
	// Distinct /56s in another /48 stop at the /48 budget.
	if got := count(func(i int) string { return fmt.Sprintf("[2001:db8:2:%x::1]:1", (i%256)<<8) }); got != 16 {
		t.Errorf("one /48 passed %d, want 16", got)
	}
	// IPv4 and an unrelated /48 are unaffected.
	if got := count(func(i int) string { return fmt.Sprintf("[2001:db8:3:%x::1]:1", i<<8) }); got == 0 {
		t.Error("other /48 limited")
	}
	if e.do("POST", PathToken, "192.0.2.77:1", nil).Code == http.StatusTooManyRequests {
		t.Error("IPv4 limited by IPv6 tiers")
	}
}

func TestGlobalAuthorizeDefaultDerivation(t *testing.T) {
	for _, tt := range []struct {
		ttl  time.Duration
		want int
	}{
		{5 * time.Minute, 2500}, {0, 2500}, {time.Minute, 12500}, {30 * time.Second, 12500},
		{10 * time.Minute, 1250}, {time.Hour, 208}, {1000 * time.Hour, 1},
	} {
		got := globalAuthorizeDefault(tt.ttl)
		if got.PerMinute != tt.want || got.Burst != tt.want {
			t.Errorf("ttl %v: %+v, want %d/%d", tt.ttl, got, tt.want, tt.want)
		}
		// The cache cannot fill: burst plus a whole code_ttl of sustained issuance.
		ttl := max(tt.ttl, time.Minute)
		if tt.ttl == 0 {
			ttl = config.DefaultCodeTTL
		}
		mins := int(ttl.Minutes() + 0.999)
		if live := got.Burst + got.PerMinute*mins; live > maxReplayEntries/2 && tt.want > 1 {
			t.Errorf("ttl %v: %d live codes possible, over half of %d", tt.ttl, live, maxReplayEntries)
		}
	}
}

func TestGlobalAuthorizeDerivedVsConfigured(t *testing.T) {
	drain := func(rl config.RateLimit, ttl time.Duration) int {
		now := fixedNow
		lim := newLimiters(rl, ttl, func() time.Time { return now })[globalKey]
		n := 0
		for n < 100_000 {
			if ok, _ := lim.Allow(""); !ok {
				break
			}
			n++
		}
		return n
	}
	if got := drain(config.RateLimit{}, 5*time.Minute); got != 2500 {
		t.Errorf("derived burst = %d, want 2500", got)
	}
	if got := drain(config.RateLimit{}, 10*time.Minute); got != 1250 {
		t.Errorf("derived burst for a longer code_ttl = %d, want 1250", got)
	}
	if got := drain(config.RateLimit{AuthorizeGlobal: config.Limit{PerMinute: 7, Burst: 3}}, 5*time.Minute); got != 3 {
		t.Errorf("configured burst = %d, want 3", got)
	}
	if got := drain(config.RateLimit{AuthorizeGlobal: config.Limit{PerMinute: 7}}, 5*time.Minute); got != 7 {
		t.Errorf("burst defaults to per_minute: %d, want 7", got)
	}
	if newLimiters(config.RateLimit{Disabled: true}, 0, time.Now) != nil {
		t.Error("disabled must build no limiters, the global ceiling included")
	}
}

// Rotating /64s inside one /48 (a routed prefix) must be throttled long before
// the code cache could fill, with the default limits.
func TestCodeCacheNotFillableFromOnePrefix(t *testing.T) {
	cfg := &config.Config{PublicURL: "https://mcp.example.com",
		OAuth: config.OAuth{AllowedRedirectURIs: []string{cbClaudeAI}}}
	e := &rlEnv{now: fixedNow}
	e.srv = New(cfg, testSealer(t, 0), slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.srv.now = func() time.Time { return e.now }
	e.mux = http.NewServeMux()
	e.srv.Register(e.mux)
	var passed int
	for i := range 20_000 { // vastly more attempts than the cache holds
		// One /64 per attempt: 256 /56s x 256 /64s inside 2001:db8:1::/48.
		ip := fmt.Sprintf("[2001:db8:1:%x::1]:1", (i%256)<<8|(i/256)%256)
		if e.do("POST", PathAuthorize, ip, nil).Code != http.StatusTooManyRequests {
			passed++
		}
	}
	// /48 burst: 16 x the authorize burst; no time passed, so no refill.
	if want := config.DefaultAuthorizeBurst * 16; passed != want {
		t.Fatalf("passed = %d, want %d", passed, want)
	}
	if passed*10 > maxReplayEntries {
		t.Fatalf("%d attempts passed, too close to the cache size %d", passed, maxReplayEntries)
	}
}

// Drives authorize from many distinct sources for several code_ttls at the
// ceiling, claiming a code per admitted request: the cache stays far from full.
func TestGlobalCeilingKeepsCodeCacheBelowCapacity(t *testing.T) {
	cfg := &config.Config{PublicURL: "https://mcp.example.com",
		OAuth: config.OAuth{AllowedRedirectURIs: []string{cbClaudeAI}, CodeTTL: 5 * time.Minute}}
	e := &rlEnv{now: fixedNow}
	e.srv = New(cfg, testSealer(t, 0), slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.srv.now = func() time.Time { return e.now }
	var issued, peak int
	h := e.srv.limit("authorize", e.srv.denyAuthorize, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !e.srv.chargeGlobalAuthorize(w) { // as authorizeSubmit, right before a code
			return
		}
		issued++
		now := e.now
		if err := e.srv.codes.claim(fmt.Sprint("code", issued), now.Add(cfg.OAuth.CodeTTL), now); err != nil {
			t.Fatalf("code cache refused after %d codes: %v", issued, err)
		}
		peak = max(peak, len(e.srv.codes.seen))
	}))
	n := 0
	for sec := range 20 * 60 { // 20 minutes, 4 code_ttls
		e.now = fixedNow.Add(time.Duration(sec) * time.Second)
		for range 100 { // 6,000/min offered, well above the 2,500/min ceiling
			n++
			req := httptest.NewRequest("POST", PathAuthorize, strings.NewReader(""))
			req.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:1", n>>16&255, n>>8&255, n&255)
			h.ServeHTTP(httptest.NewRecorder(), req)
		}
	}
	if peak == 0 || peak > maxReplayEntries/2 {
		t.Fatalf("peak live codes = %d, want within (0, %d]", peak, maxReplayEntries/2)
	}
	if issued > 2500+2500*20+100 {
		t.Fatalf("issued = %d, ceiling not enforced", issued)
	}
}

func TestWarnGlobalOversized(t *testing.T) {
	for _, tt := range []struct {
		g    config.Limit
		warn bool
	}{
		{config.Limit{}, false}, {config.Limit{PerMinute: 2500, Burst: 2500}, false},
		{config.Limit{PerMinute: 5000}, true}, {config.Limit{PerMinute: 100, Burst: 40_000}, true},
	} {
		var logs bytes.Buffer
		e := newRL(t, 1, func(r *config.RateLimit) { r.AuthorizeGlobal = tt.g })
		e.srv.log = slog.New(slog.NewTextHandler(&logs, nil))
		e.srv.warnGlobalOversized()
		if got := strings.Contains(logs.String(), "level=WARN"); got != tt.warn {
			t.Errorf("%+v: warned = %v, want %v", tt.g, got, tt.warn)
		}
	}
}
