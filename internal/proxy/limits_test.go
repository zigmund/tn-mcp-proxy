package proxy

import (
	"bufio"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/tokens"
)

// offLimits disables every limit; tests enable only what they exercise.
func offLimits() config.ProxyLimits {
	return config.ProxyLimits{
		IP:                    config.Limit{PerMinute: config.Disable},
		Token:                 config.Limit{PerMinute: config.Disable},
		MaxConcurrentPerToken: config.Disable,
		MaxInFlight:           config.Disable,
	}
}

type fakeClock struct{ ns atomic.Int64 }

func newFakeClock() *fakeClock {
	c := &fakeClock{}
	c.ns.Store(time.Unix(1_800_000_000, 0).UnixNano())
	return c
}
func (c *fakeClock) now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *fakeClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

func limitsEnv(t *testing.T, cfg config.ProxyLimits, backend http.HandlerFunc) (*env, *Limits, *fakeClock) {
	t.Helper()
	clk := newFakeClock()
	var lim *Limits
	e := newEnvUp(t, backend, nil, func(h *handler) {
		lim = NewLimits(cfg, h.log, WithLimitsClock(clk.now))
		h.limits = lim
	})
	return e, lim, clk
}

// tokFor returns an access token for a distinct grant: client names both the
// client_id and the API key value, since grants are keyed by credentials.
func (e *env) tokFor(t *testing.T, client string) string {
	t.Helper()
	creds := goodCreds()
	creds["X-Tn-Api-Key"] = "key-" + client
	return e.token(t, seal.KindAccess, tokens.Access{Upstream: "tn", ClientID: client, Creds: creds}, time.Hour)
}

func status(e *env, t *testing.T, tok string) *http.Response {
	t.Helper()
	return e.do(t, "POST", "/mcp/tn", "Bearer "+tok, nil, `{}`)
}

func TestTokenRateLimit(t *testing.T) {
	cfg := offLimits()
	cfg.Token = config.Limit{PerMinute: 60, Burst: 2}
	e, _, clk := limitsEnv(t, cfg, nil)
	a, b := e.tokFor(t, "a"), e.tokFor(t, "b")

	for i := range 2 {
		if r := status(e, t, a); r.StatusCode != 200 {
			t.Fatalf("request %d: %d", i, r.StatusCode)
		}
	}
	r := status(e, t, a)
	if r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over burst: %d", r.StatusCode)
	}
	if ra := r.Header.Get("Retry-After"); ra != "1" {
		t.Errorf("Retry-After %q", ra)
	}
	if got := len(e.requests()); got != 2 {
		t.Errorf("upstream saw %d requests, want 2 (denied one must not be forwarded)", got)
	}
	if r := status(e, t, b); r.StatusCode != 200 {
		t.Errorf("other grant throttled: %d", r.StatusCode)
	}
	clk.advance(time.Second)
	if r := status(e, t, a); r.StatusCode != 200 {
		t.Errorf("after refill: %d", r.StatusCode)
	}
}

func TestTokenRateKeyIsGrantNotTokenString(t *testing.T) {
	cfg := offLimits()
	cfg.Token = config.Limit{PerMinute: 60, Burst: 1}
	e, _, _ := limitsEnv(t, cfg, nil)
	// Two different sealed tokens (fresh nonce) of the same grant share a bucket.
	t1, t2 := e.tokFor(t, "a"), e.tokFor(t, "a")
	if t1 == t2 {
		t.Fatal("tokens identical")
	}
	if r := status(e, t, t1); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	if r := status(e, t, t2); r.StatusCode != http.StatusTooManyRequests {
		t.Errorf("same grant, new token: %d", r.StatusCode)
	}
}

func TestGrantKey(t *testing.T) {
	creds := map[string]string{"X-K": "secret-v", "X-S": "s2"}
	k := grantKey("tn", creds)
	if k != grantKey("tn", map[string]string{"X-S": "s2", "X-K": "secret-v"}) {
		t.Error("key depends on map order")
	}
	for name, other := range map[string]string{
		"upstream": grantKey("x", creds),
		"value":    grantKey("tn", map[string]string{"X-K": "other", "X-S": "s2"}),
		"shifted":  grantKey("tn", map[string]string{"X-KX-S": "secret-v", "": "s2"}),
	} {
		if other == k {
			t.Errorf("%s change gives the same key", name)
		}
	}
	if strings.Contains(k, "secret-v") {
		t.Error("key contains a credential value")
	}
}

func TestIPRateLimitBeforeAuth(t *testing.T) {
	cfg := offLimits()
	cfg.IP = config.Limit{PerMinute: 60, Burst: 2}
	e, _, clk := limitsEnv(t, cfg, nil)

	// Unauthenticated requests are charged too: the limit is checked first.
	for i := range 2 {
		if r := e.do(t, "POST", "/mcp/tn", "Bearer garbage", nil, ""); r.StatusCode != 401 {
			t.Fatalf("request %d: %d", i, r.StatusCode)
		}
	}
	r := e.do(t, "POST", "/mcp/tn", "Bearer garbage", nil, "")
	if r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") == "" {
		t.Fatalf("status %d, Retry-After %q", r.StatusCode, r.Header.Get("Retry-After"))
	}
	if r.Header.Get("WWW-Authenticate") != "" {
		t.Error("rate-limited request got an auth challenge")
	}
	// Wrong method and path are rejected before the limiter and cost nothing.
	if r := e.do(t, "PUT", "/mcp/tn", "", nil, ""); r.StatusCode != 405 {
		t.Errorf("PUT: %d", r.StatusCode)
	}
	clk.advance(time.Second)
	if r := status(e, t, e.tokFor(t, "a")); r.StatusCode != 200 {
		t.Errorf("after refill: %d", r.StatusCode)
	}
}

func TestIPResolverUsed(t *testing.T) {
	cfg := offLimits()
	cfg.IP = config.Limit{PerMinute: 60, Burst: 1}
	clk := newFakeClock()
	e := newEnvUp(t, nil, nil, func(h *handler) {
		h.limits = NewLimits(cfg, nil, WithLimitsClock(clk.now), WithClientIP(func(r *http.Request) string { return r.Header.Get("X-Test-IP") }))
	})
	tok := e.tokFor(t, "a")
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		if r := e.do(t, "POST", "/mcp/tn", "Bearer "+tok, map[string]string{"X-Test-IP": ip}, ""); r.StatusCode != 200 {
			t.Errorf("%s: %d", ip, r.StatusCode)
		}
	}
	if r := e.do(t, "POST", "/mcp/tn", "Bearer "+tok, map[string]string{"X-Test-IP": "192.0.2.1"}, ""); r.StatusCode != 429 {
		t.Errorf("repeat IP: %d", r.StatusCode)
	}
}

func TestDeniedRequestRefundsOtherTiers(t *testing.T) {
	cfg := offLimits()
	cfg.IP = config.Limit{PerMinute: 60, Burst: 3}
	cfg.Token = config.Limit{PerMinute: 60, Burst: 1}
	e, _, _ := limitsEnv(t, cfg, nil)
	a := e.tokFor(t, "a")

	if r := status(e, t, a); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	for range 5 { // token-denied: must hand the IP token back each time
		if r := status(e, t, a); r.StatusCode != 429 {
			t.Fatal(r.StatusCode)
		}
	}
	// 1 IP token was spent for real; 2 are left for two other grants.
	for _, c := range []string{"b", "c"} {
		if r := status(e, t, e.tokFor(t, c)); r.StatusCode != 200 {
			t.Errorf("grant %s: %d (IP tokens leaked by denials)", c, r.StatusCode)
		}
	}
	if r := status(e, t, e.tokFor(t, "d")); r.StatusCode != 429 {
		t.Errorf("IP bucket should be empty: %d", r.StatusCode)
	}
}

// blockingBackend holds each request until release is closed or the client
// goes away, and counts how many are inside.
type blockingBackend struct {
	in      atomic.Int32
	release chan struct{}
}

func newBlocking() *blockingBackend { return &blockingBackend{release: make(chan struct{})} }

func (b *blockingBackend) handle(w http.ResponseWriter, r *http.Request) {
	b.in.Add(1)
	defer b.in.Add(-1)
	select {
	case <-b.release:
	case <-r.Context().Done():
	}
	_, _ = io.WriteString(w, `{"ok":true}`)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPerTokenConcurrency(t *testing.T) {
	cfg := offLimits()
	cfg.MaxConcurrentPerToken = 2
	bb := newBlocking()
	e, lim, _ := limitsEnv(t, cfg, bb.handle)
	a, b := e.tokFor(t, "a"), e.tokFor(t, "b")

	done := make(chan int, 4)
	fire := func(tok string) {
		go func() {
			req, _ := http.NewRequest("POST", e.proxy.URL+"/mcp/tn", strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				done <- -1
				return
			}
			_ = resp.Body.Close()
			done <- resp.StatusCode
		}()
	}
	fire(a)
	fire(a)
	waitFor(t, "two in flight", func() bool { return bb.in.Load() == 2 })

	// Denied repeatedly: must not hold or leak slots.
	for range 3 {
		r := status(e, t, a)
		if r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") != "1" {
			t.Fatalf("status %d, Retry-After %q", r.StatusCode, r.Header.Get("Retry-After"))
		}
	}
	if got := bb.in.Load(); got != 2 {
		t.Errorf("%d requests reached upstream, want 2", got)
	}
	// Another grant has its own slots.
	fire(b)
	waitFor(t, "other grant in flight", func() bool { return bb.in.Load() == 3 })

	close(bb.release)
	for range 3 {
		if c := <-done; c != 200 {
			t.Errorf("held request finished with %d", c)
		}
	}
	waitFor(t, "slots released", func() bool { return lim.perToken.Keys() == 0 })
	for range 2 { // two slots are free again
		if r := status(e, t, a); r.StatusCode != 200 {
			t.Errorf("after release: %d", r.StatusCode)
		}
	}
}

func TestGlobalInFlightCap503(t *testing.T) {
	cfg := offLimits()
	cfg.MaxInFlight = 1
	cfg.Token = config.Limit{PerMinute: 60, Burst: 2}
	cfg.IP = config.Limit{PerMinute: 60, Burst: 2}
	bb := newBlocking()
	e, lim, _ := limitsEnv(t, cfg, bb.handle)
	a, b := e.tokFor(t, "a"), e.tokFor(t, "b")

	done := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest("POST", e.proxy.URL+"/mcp/tn", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+a)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- -1
			return
		}
		_ = resp.Body.Close()
		done <- resp.StatusCode
	}()
	waitFor(t, "request in flight", func() bool { return bb.in.Load() == 1 })

	// IP burst is 2 and one is used; the 503s below must refund theirs.
	for range 4 {
		r := status(e, t, b)
		if r.StatusCode != http.StatusServiceUnavailable || r.Header.Get("Retry-After") != "1" {
			t.Fatalf("status %d, Retry-After %q", r.StatusCode, r.Header.Get("Retry-After"))
		}
	}
	close(bb.release)
	if c := <-done; c != 200 {
		t.Fatalf("held request: %d", c)
	}
	waitFor(t, "slot released", func() bool { return lim.global.Held("") == 0 })
	// Grant b spent no token and the IP spent only the first request's.
	if r := status(e, t, b); r.StatusCode != 200 {
		t.Errorf("after the cap cleared: %d", r.StatusCode)
	}
}

func TestMaxConnsPerHostFollowsInFlightCap(t *testing.T) {
	cfg := offLimits()
	cfg.MaxInFlight = 7
	_, lim, _ := limitsEnv(t, cfg, nil)
	if got := lim.maxConns(); got != 7 {
		t.Errorf("maxConns %d, want 7", got)
	}
	if got := newTransport(7).MaxConnsPerHost; got != 7 {
		t.Errorf("MaxConnsPerHost %d", got)
	}
	if got := NewLimits(offLimits(), nil).maxConns(); got != 0 {
		t.Errorf("disabled cap gives MaxConnsPerHost %d, want 0 (unlimited)", got)
	}
}

// sseBackend sends one event, then another after the gate opens, then ends the
// stream when end is closed (or the client disconnects).
type sseBackend struct {
	gate, end chan struct{}
}

func (s *sseBackend) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	fl := w.(http.Flusher)
	_, _ = io.WriteString(w, "data: one\n\n")
	fl.Flush()
	select {
	case <-s.gate:
	case <-r.Context().Done():
		return
	}
	_, _ = io.WriteString(w, "data: two\n\n")
	fl.Flush()
	select {
	case <-s.end:
	case <-r.Context().Done():
	}
}

func readEvent(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading stream: %v", err)
	}
	if _, err := br.ReadString('\n'); err != nil { // blank separator
		t.Fatalf("reading stream: %v", err)
	}
	return strings.TrimSpace(line)
}

func TestSSEStreamHoldsSlotAndIsNotCut(t *testing.T) {
	cfg := offLimits()
	cfg.MaxConcurrentPerToken = 1
	cfg.MaxInFlight = 4
	cfg.Token = config.Limit{PerMinute: 600, Burst: 100}
	sb := &sseBackend{gate: make(chan struct{}), end: make(chan struct{})}
	e, lim, clk := limitsEnv(t, cfg, sb.handle)
	a := e.tokFor(t, "a")

	open := func() (*http.Response, error) {
		req, _ := http.NewRequest("GET", e.proxy.URL+"/mcp/tn", nil)
		req.Header.Set("Authorization", "Bearer "+a)
		req.Header.Set("Accept", "text/event-stream")
		return http.DefaultClient.Do(req)
	}
	resp, err := open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	br := bufio.NewReader(resp.Body)
	if got := readEvent(t, br); got != "data: one" {
		t.Fatalf("first event %q", got)
	}

	// The open stream is one in-flight request: a second one is refused.
	if r := status(e, t, a); r.StatusCode != http.StatusTooManyRequests {
		t.Errorf("second request while the stream is open: %d", r.StatusCode)
	}
	// Time passing (far beyond any rate window) does not cut the stream, and
	// the proxy imposes no deadline on it.
	clk.advance(time.Hour)
	close(sb.gate)
	if got := readEvent(t, br); got != "data: two" {
		t.Fatalf("second event %q", got)
	}
	if lim.perToken.Keys() != 1 || lim.global.Held("") != 1 {
		t.Fatalf("slots: keys=%d global=%d, want 1 and 1", lim.perToken.Keys(), lim.global.Held(""))
	}

	// Client disconnect releases the slot.
	_ = resp.Body.Close()
	waitFor(t, "slots released after disconnect", func() bool {
		return lim.perToken.Keys() == 0 && lim.global.Held("") == 0
	})
	if r := status(e, t, a); r.StatusCode != 200 {
		t.Errorf("after disconnect: %d", r.StatusCode)
	}
}

func TestSSEStreamEndReleasesSlot(t *testing.T) {
	cfg := offLimits()
	cfg.MaxConcurrentPerToken = 1
	sb := &sseBackend{gate: make(chan struct{}), end: make(chan struct{})}
	close(sb.gate)
	e, lim, _ := limitsEnv(t, cfg, sb.handle)
	a := e.tokFor(t, "a")

	req, _ := http.NewRequest("GET", e.proxy.URL+"/mcp/tn", nil)
	req.Header.Set("Authorization", "Bearer "+a)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	br := bufio.NewReader(resp.Body)
	readEvent(t, br)
	readEvent(t, br)
	if lim.perToken.Keys() != 1 {
		t.Fatal("stream does not hold a slot")
	}
	close(sb.end) // the upstream ends the stream
	if b, err := io.ReadAll(br); err != nil || len(b) != 0 {
		t.Fatalf("rest of stream: %q, %v", b, err)
	}
	waitFor(t, "slot released at stream end", func() bool { return lim.perToken.Keys() == 0 })
}

func TestLimitsOffAllowsEverything(t *testing.T) {
	e, _, _ := limitsEnv(t, offLimits(), nil)
	a := e.tokFor(t, "a")
	for i := range 50 {
		if r := status(e, t, a); r.StatusCode != 200 {
			t.Fatalf("request %d: %d", i, r.StatusCode)
		}
	}
	cfg := config.ProxyLimits{Disabled: true}
	e2, lim, _ := limitsEnv(t, cfg, nil)
	if lim.ip != nil || lim.token != nil || lim.perToken != nil || lim.global != nil {
		t.Error("disabled: true left a limiter on")
	}
	for i := range 50 {
		if r := status(e2, t, e2.tokFor(t, "a")); r.StatusCode != 200 {
			t.Fatalf("request %d: %d", i, r.StatusCode)
		}
	}
}

func TestConfiguredBodyCap(t *testing.T) {
	cfg := offLimits()
	cfg.MaxRequestBody = 2048
	e, _, _ := limitsEnv(t, cfg, nil)
	a := e.tokFor(t, "a")
	if r := e.do(t, "POST", "/mcp/tn", "Bearer "+a, nil, strings.Repeat("x", 2048)); r.StatusCode != 200 {
		t.Errorf("at the cap: %d", r.StatusCode)
	}
	if r := e.do(t, "POST", "/mcp/tn", "Bearer "+a, nil, strings.Repeat("x", 2049)); r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("over the cap: %d", r.StatusCode)
	}
}

func TestDefaultLimitsHandlerWorks(t *testing.T) {
	// No WithLimits: the handler applies the defaults and ordinary traffic passes.
	e := newEnv(t, nil)
	a := e.tokFor(t, "a")
	for i := range 20 {
		if r := status(e, t, a); r.StatusCode != 200 {
			t.Fatalf("request %d: %d", i, r.StatusCode)
		}
	}
}

func TestLimitLogsNeverLeak(t *testing.T) {
	cfg := offLimits()
	cfg.Token = config.Limit{PerMinute: 60, Burst: 1}
	cfg.IP = config.Limit{PerMinute: 60, Burst: 100}
	e, _, _ := limitsEnv(t, cfg, nil)
	a := e.tokFor(t, "a")
	status(e, t, a)
	status(e, t, a)
	for _, s := range []string{"key-a", "secret-456", "sid-789", a} {
		if strings.Contains(e.logs.String(), s) {
			t.Errorf("log contains %q", s[:min(len(s), 8)])
		}
	}
}

type panicRT struct{ v any }

func (p panicRT) RoundTrip(*http.Request) (*http.Response, error) { panic(p.v) }

func TestSlotsReleasedOnPanic(t *testing.T) {
	for name, v := range map[string]any{"abort": http.ErrAbortHandler, "panic": "boom"} {
		t.Run(name, func(t *testing.T) {
			cfg := offLimits()
			cfg.MaxConcurrentPerToken = 1
			cfg.MaxInFlight = 1
			e := newEnv(t, nil)
			lim := NewLimits(cfg, nil)
			hh, err := New(e.up, publicURL, e.sealer, slog.New(slog.NewTextHandler(io.Discard, nil)), WithLimits(lim))
			if err != nil {
				t.Fatal(err)
			}
			hh.(*handler).rp.Transport = panicRT{v}
			req := httptest.NewRequest("POST", "/mcp/tn", strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+e.tokFor(t, "a"))
			func() {
				defer func() {
					if recover() == nil {
						t.Error("expected the panic to propagate")
					}
				}()
				hh.ServeHTTP(httptest.NewRecorder(), req)
			}()
			if lim.perToken.Keys() != 0 || lim.global.Held("") != 0 {
				t.Errorf("slots leaked: token keys=%d global=%d", lim.perToken.Keys(), lim.global.Held(""))
			}
		})
	}
}

func TestOversizeContentLengthRefundsIP(t *testing.T) {
	cfg := offLimits()
	cfg.IP = config.Limit{PerMinute: 60, Burst: 2}
	cfg.MaxRequestBody = 2048
	e, _, _ := limitsEnv(t, cfg, nil)
	a := e.tokFor(t, "a")
	for range 5 {
		if r := e.do(t, "POST", "/mcp/tn", "Bearer "+a, nil, strings.Repeat("x", 3000)); r.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status %d", r.StatusCode)
		}
	}
	for range 2 {
		if r := status(e, t, a); r.StatusCode != 200 {
			t.Errorf("IP tokens not refunded: %d", r.StatusCode)
		}
	}
}
