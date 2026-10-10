package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/tokens"
)

const (
	publicURL = "https://proxy.example.com"
	meta      = `resource_metadata="https://proxy.example.com/.well-known/oauth-protected-resource/mcp/tn"`
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// seen is what the fake upstream observed.
type seen struct {
	method, uri, host string
	header            http.Header
	body              string
}

type env struct {
	sealer *seal.Sealer
	now    *atomic.Int64 // unix seconds
	proxy  *httptest.Server
	up     config.Upstream
	logs   *syncBuf

	mu   sync.Mutex
	reqs []seen
}

func (e *env) requests() []seen {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]seen(nil), e.reqs...)
}

func testUpstream(url string) config.Upstream {
	return config.Upstream{
		Name: "tn", Path: "/mcp/tn", URL: url + "/mcp",
		Credentials: []config.Credential{
			{Header: "X-TN-API-Key"},
			{Header: "X-TN-API-Secret", Secret: true},
			{Header: "X-TN-SID", Optional: true},
		},
	}
}

// newEnv starts a fake upstream running backend (or a recording default) and
// a proxy in front of it.
func newEnv(t *testing.T, backend http.HandlerFunc) *env {
	t.Helper()
	e := &env{now: new(atomic.Int64), logs: &syncBuf{}}
	e.now.Store(1_800_000_000)

	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.reqs = append(e.reqs, seen{r.Method, r.RequestURI, r.Host, r.Header.Clone(), string(body)})
		e.mu.Unlock()
		if backend != nil {
			backend(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(back.Close)

	var err error
	e.sealer, err = seal.New([][]byte{bytes32(1)}, seal.WithClock(func() time.Time { return time.Unix(e.now.Load(), 0) }))
	if err != nil {
		t.Fatal(err)
	}
	e.up = testUpstream(back.URL)
	log := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h, err := New(e.up, publicURL+"/", e.sealer, log)
	if err != nil {
		t.Fatal(err)
	}
	e.proxy = httptest.NewServer(h)
	t.Cleanup(e.proxy.Close)
	return e
}

func bytes32(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func (e *env) token(t *testing.T, kind seal.Kind, payload any, ttl time.Duration) string {
	t.Helper()
	tok, err := e.sealer.Seal(kind, payload, time.Unix(e.now.Load(), 0).Add(ttl))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (e *env) access(t *testing.T, creds map[string]string) string {
	return e.token(t, seal.KindAccess, tokens.Access{Upstream: "tn", ClientID: "cid", Creds: creds}, time.Hour)
}

func goodCreds() map[string]string {
	return map[string]string{"X-Tn-Api-Key": "key-123", "X-Tn-Api-Secret": "secret-456", "X-Tn-Sid": "sid-789"}
}

func (e *env) do(t *testing.T, method, path, auth string, hdr map[string]string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, e.proxy.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestInjectAndStrip(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			e := newEnv(t, nil)
			creds := goodCreds()
			creds["X-Evil"] = "ignored" // not configured: must not be injected
			tok := e.access(t, creds)

			resp := e.do(t, method, "/mcp/tn?a=1&b=x%20y", "Bearer "+tok, map[string]string{
				"Cookie":               "session=abc",
				"Proxy-Authorization":  "Basic zzz",
				"X-TN-API-Key":         "attacker-key",
				"X-TN-SID":             "attacker-sid",
				"X-Forwarded-For":      "203.0.113.7",
				"X-Forwarded-Host":     "evil.example",
				"X-Forwarded-Proto":    "http",
				"X-Forwarded-Port":     "1234",
				"Forwarded":            "for=203.0.113.7",
				"X-Real-IP":            "203.0.113.7",
				"Mcp-Session-Id":       "sess-1",
				"Mcp-Protocol-Version": "2025-06-18",
				"Accept":               "application/json, text/event-stream",
				"Content-Type":         "application/json",
				"Last-Event-ID":        "42",
			}, `{"jsonrpc":"2.0"}`)
			if resp.StatusCode != 200 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			rs := e.requests()
			if len(rs) != 1 {
				t.Fatalf("upstream got %d requests", len(rs))
			}
			got := rs[0]
			if got.method != method {
				t.Errorf("method %s", got.method)
			}
			if got.uri != "/mcp?a=1&b=x%20y" {
				t.Errorf("uri %q", got.uri)
			}
			if got.host != strings.TrimPrefix(e.up.URL[:strings.LastIndex(e.up.URL, "/mcp")], "http://") {
				t.Errorf("host %q", got.host)
			}
			if got.body != `{"jsonrpc":"2.0"}` {
				t.Errorf("body %q", got.body)
			}
			want := map[string]string{
				"X-Tn-Api-Key": "key-123", "X-Tn-Api-Secret": "secret-456", "X-Tn-Sid": "sid-789",
				"Mcp-Session-Id": "sess-1", "Mcp-Protocol-Version": "2025-06-18",
				"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
				"Last-Event-Id": "42",
			}
			for k, v := range want {
				if g := got.header.Get(k); g != v {
					t.Errorf("header %s = %q, want %q", k, g, v)
				}
			}
			for _, k := range []string{"Authorization", "Cookie", "Proxy-Authorization", "X-Forwarded-For",
				"X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "Forwarded", "X-Real-Ip", "X-Evil"} {
				if v := got.header.Values(k); len(v) != 0 {
					t.Errorf("header %s leaked: %q", k, v)
				}
			}
			if v := got.header.Values("X-Tn-Api-Key"); len(v) != 1 {
				t.Errorf("X-TN-API-Key values %q", v)
			}
		})
	}
}

func TestOptionalCredentialAbsentIsStripped(t *testing.T) {
	e := newEnv(t, nil)
	tok := e.access(t, map[string]string{"X-TN-API-Key": "k", "X-TN-API-Secret": "s"}) // non-canonical keys tolerated
	resp := e.do(t, "POST", "/mcp/tn", "bearer "+tok, map[string]string{"X-TN-SID": "attacker"}, "{}")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	h := e.requests()[0].header
	if h.Get("X-Tn-Api-Key") != "k" || h.Get("X-Tn-Api-Secret") != "s" {
		t.Errorf("creds not injected: %v", h)
	}
	if v := h.Values("X-Tn-Sid"); len(v) != 0 {
		t.Errorf("inbound optional header forwarded: %q", v)
	}
}

func TestOnlyExactPath(t *testing.T) {
	e := newEnv(t, nil)
	h, err := New(e.up, publicURL, e.sealer, nil)
	if err != nil {
		t.Fatal(err)
	}
	tok := e.access(t, goodCreds())
	for _, target := range []string{
		"/mcp/tn/x", "/mcp/tn/", "/mcp/tn/%2e%2e/admin", "/mcp/tn/../admin",
		"/mcp/tn//x", "/mcp/tn%2fx", "/mcp/t%6e", "/mcp", "/",
	} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest("GET", target, nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("status %d", rec.Code)
			}
		})
	}
	// Over the wire as well (the client keeps the escapes it was given).
	for _, p := range []string{"/mcp/tn/x", "/mcp/tn/%2e%2e/admin", "/mcp/tn//x", "/mcp/tn%2fx"} {
		if resp := e.do(t, "GET", p, "Bearer "+tok, nil, ""); resp.StatusCode == 200 {
			t.Errorf("%s: served", p)
		}
	}
	if n := len(e.requests()); n != 0 {
		t.Errorf("upstream was called %d times", n)
	}
	// The exact path works.
	if resp := e.do(t, "GET", "/mcp/tn", "Bearer "+tok, nil, ""); resp.StatusCode != 200 {
		t.Errorf("exact path: status %d", resp.StatusCode)
	}
}

func TestUpstreamQueryWins(t *testing.T) {
	tests := []struct {
		name, upstreamQuery, clientQuery, want string
	}{
		{"client query forwarded", "", "a=1", "/mcp?a=1"},
		{"upstream query only", "k=v", "", "/mcp?k=v"},
		{"client query ignored", "k=v", "a=1&k=evil", "/mcp?k=v"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			up := e.up
			if tc.upstreamQuery != "" {
				up.URL += "?" + tc.upstreamQuery
			}
			h, err := New(up, publicURL, e.sealer, nil)
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(h)
			defer srv.Close()
			target := "/mcp/tn"
			if tc.clientQuery != "" {
				target += "?" + tc.clientQuery
			}
			req, _ := http.NewRequest("GET", srv.URL+target, nil)
			req.Header.Set("Authorization", "Bearer "+e.access(t, goodCreds()))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if got := e.requests()[0].uri; got != tc.want {
				t.Errorf("uri %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAuthFailures(t *testing.T) {
	bareMeta := "Bearer " + meta
	invalid := func(desc string) string {
		return `Bearer error="invalid_token", error_description="` + desc + `", ` + meta
	}
	tests := []struct {
		name string
		auth func(t *testing.T, e *env) string
		want string
	}{
		{"missing", func(*testing.T, *env) string { return "" }, bareMeta},
		{"other scheme", func(*testing.T, *env) string { return "Basic dXNlcjpwYXNz" }, bareMeta},
		{"empty bearer", func(*testing.T, *env) string { return "Bearer " }, invalid("token invalid")},
		{"garbage", func(*testing.T, *env) string { return "Bearer not-a-token" }, invalid("token invalid")},
		{"expired", func(t *testing.T, e *env) string {
			tok := e.access(t, goodCreds())
			e.now.Add(2 * 3600)
			return "Bearer " + tok
		}, invalid("token expired")},
		{"wrong kind", func(t *testing.T, e *env) string {
			return "Bearer " + e.token(t, seal.KindRefresh, tokens.Refresh{Upstream: "tn", Creds: goodCreds()}, time.Hour)
		}, invalid("token invalid")},
		{"wrong upstream", func(t *testing.T, e *env) string {
			return "Bearer " + e.token(t, seal.KindAccess, tokens.Access{Upstream: "other", Creds: goodCreds()}, time.Hour)
		}, invalid("token not valid for this resource")},
		{"missing required cred", func(t *testing.T, e *env) string {
			return "Bearer " + e.access(t, map[string]string{"X-Tn-Api-Key": "k"})
		}, invalid("token lacks required credentials")},
		{"control chars in cred", func(t *testing.T, e *env) string {
			c := goodCreds()
			c["X-Tn-Api-Key"] = "k\r\nX-Injected: 1"
			return "Bearer " + e.access(t, c)
		}, invalid("token lacks required credentials")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			resp := e.do(t, "POST", "/mcp/tn", tc.auth(t, e), nil, "{}")
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status %d", resp.StatusCode)
			}
			if got := resp.Header.Get("WWW-Authenticate"); got != tc.want {
				t.Errorf("WWW-Authenticate:\n got %s\nwant %s", got, tc.want)
			}
			if n := len(e.requests()); n != 0 {
				t.Errorf("upstream was called %d times", n)
			}
		})
	}
}

func TestPayloadMismatchIs401(t *testing.T) {
	e := newEnv(t, nil)
	tok := e.token(t, seal.KindAccess, []int{1, 2, 3}, time.Hour)
	resp := e.do(t, "POST", "/mcp/tn", "Bearer "+tok, nil, "{}")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
	want := `Bearer error="invalid_token", error_description="token invalid", ` + meta
	if got := resp.Header.Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate %q", got)
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "level=ERROR") {
		t.Errorf("no error log: %s", logs)
	}
	if strings.Contains(logs, tok) {
		t.Error("token leaked to logs")
	}
	if n := len(e.requests()); n != 0 {
		t.Errorf("upstream was called %d times", n)
	}
}

func TestCredentialFailureLogsHeaderOnly(t *testing.T) {
	e := newEnv(t, nil)
	c := goodCreds()
	c["X-Tn-Api-Key"] = "leaky\r\nvalue"
	e.do(t, "POST", "/mcp/tn", "Bearer "+e.access(t, c), nil, "{}")
	e.do(t, "POST", "/mcp/tn", "Bearer "+e.access(t, map[string]string{"X-Tn-Api-Key": "k"}), nil, "{}")
	logs := e.logs.String()
	if strings.Count(logs, "level=WARN") != 2 || !strings.Contains(logs, "header=X-Tn-Api-Key") ||
		!strings.Contains(logs, "header=X-Tn-Api-Secret") {
		t.Errorf("unexpected logs: %s", logs)
	}
	if strings.Contains(logs, "leaky") {
		t.Error("credential value leaked to logs")
	}
}

func TestConnectionHeaderCannotDropCredential(t *testing.T) {
	e := newEnv(t, nil)
	tok := e.access(t, goodCreds())
	e.do(t, "POST", "/mcp/tn", "Bearer "+tok, map[string]string{
		"Connection":   "X-TN-API-Key, X-TN-SID",
		"X-TN-API-Key": "attacker",
	}, "{}")
	h := e.requests()[0].header
	if h.Get("X-Tn-Api-Key") != "key-123" || h.Get("X-Tn-Sid") != "sid-789" {
		t.Errorf("credentials dropped or replaced: %v", h)
	}
}

func TestUpstream401RewritesChallenge(t *testing.T) {
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="upstream"`)
		w.WriteHeader(http.StatusUnauthorized)
	})
	resp := e.do(t, "POST", "/mcp/tn", "Bearer "+e.access(t, goodCreds()), nil, "{}")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
	want := `Bearer error="invalid_token", error_description="upstream rejected credentials", ` + meta
	if got := resp.Header.Values("WWW-Authenticate"); len(got) != 1 || got[0] != want {
		t.Errorf("WWW-Authenticate %q", got)
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "level=WARN") || strings.Contains(logs, "key-123") {
		t.Errorf("logs: %s", logs)
	}
}

func TestUpgradeRejected(t *testing.T) {
	e := newEnv(t, nil)
	resp := e.do(t, "GET", "/mcp/tn", "Bearer "+e.access(t, goodCreds()),
		map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"}, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d", resp.StatusCode)
	}
	if n := len(e.requests()); n != 0 {
		t.Errorf("upstream was called %d times", n)
	}
}

// opaqueReader hides the length so the client sends a chunked body.
type opaqueReader struct{ r io.Reader }

func (o opaqueReader) Read(p []byte) (int, error) { return o.r.Read(p) }

func TestBodyLimit(t *testing.T) {
	tests := []struct {
		name string
		body func() io.Reader
	}{
		{"content-length", func() io.Reader { return bytes.NewReader(make([]byte, maxRequestBody+1)) }},
		{"chunked", func() io.Reader { return opaqueReader{bytes.NewReader(make([]byte, maxRequestBody+1))} }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			req, _ := http.NewRequest("POST", e.proxy.URL+"/mcp/tn", tc.body())
			req.Header.Set("Authorization", "Bearer "+e.access(t, goodCreds()))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusRequestEntityTooLarge {
				t.Errorf("status %d", resp.StatusCode)
			}
		})
	}
	// A body at the limit is fine.
	e := newEnv(t, nil)
	resp := e.do(t, "POST", "/mcp/tn", "Bearer "+e.access(t, goodCreds()), nil, strings.Repeat("x", 1<<20))
	if resp.StatusCode != 200 {
		t.Errorf("small body: status %d", resp.StatusCode)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

func TestErrorHandlerStatuses(t *testing.T) {
	e := newEnv(t, nil)
	hh, err := New(e.up, publicURL, e.sealer, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := hh.(*handler)
	tests := []struct {
		name string
		err  error
		code int // 0: nothing written
	}{
		{"deadline", context.DeadlineExceeded, 504},
		{"net timeout", &net.OpError{Op: "dial", Err: timeoutErr{}}, 504},
		{"refused", errors.New("connection refused"), 502},
		{"canceled", context.Canceled, 0},
		{"too large", &http.MaxBytesError{Limit: 1}, 413},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.errorHandler(rec, httptest.NewRequest("GET", "/", nil), tc.err)
			if tc.code == 0 {
				if rec.Body.Len() != 0 || len(rec.Header()) != 0 {
					t.Errorf("response written: %q", rec.Body.String())
				}
				return
			}
			if rec.Code != tc.code {
				t.Errorf("status %d, want %d", rec.Code, tc.code)
			}
		})
	}
}

func TestClientDisconnectCancelsUpstream(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "data: hi\n\n")
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(canceled)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", e.proxy.URL+"/mcp/tn", nil)
	req.Header.Set("Authorization", "Bearer "+e.access(t, goodCreds()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never started")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request was not canceled after client disconnect")
	}
}

func TestSSEStreamsIncrementally(t *testing.T) {
	release := make(chan struct{})
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "data: two\n\n")
	})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	tok := e.access(t, goodCreds())

	resp := e.do(t, "GET", "/mcp/tn", "Bearer "+tok, map[string]string{"Accept": "text/event-stream"}, "")
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type %q", ct)
	}
	lines := make(chan string)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	next := func() string {
		t.Helper()
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatal("stream ended early")
			}
			return l
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for event; proxy is buffering")
			return ""
		}
	}
	// The upstream is still blocked, so this event can only arrive if flushed.
	if l := next(); l != "data: one" {
		t.Fatalf("first line %q", l)
	}
	close(release)
	for l := next(); l != "data: two"; l = next() {
	}
}

func TestResponseHeaders(t *testing.T) {
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.Header().Set("Mcp-Session-Id", "sess-from-upstream")
		w.WriteHeader(http.StatusAccepted)
	})
	tok := e.access(t, goodCreds())
	resp := e.do(t, "POST", "/mcp/tn", "Bearer "+tok, map[string]string{"Mcp-Session-Id": "sess-in"}, "{}")
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status %d", resp.StatusCode)
	}
	if v := resp.Header.Values("Set-Cookie"); len(v) != 0 {
		t.Errorf("Set-Cookie leaked: %q", v)
	}
	if g := resp.Header.Get("Mcp-Session-Id"); g != "sess-from-upstream" {
		t.Errorf("Mcp-Session-Id %q", g)
	}
	if g := e.requests()[0].header.Get("Mcp-Session-Id"); g != "sess-in" {
		t.Errorf("upstream saw Mcp-Session-Id %q", g)
	}
	if !strings.Contains(e.logs.String(), "status=202") {
		t.Errorf("no debug status log: %s", e.logs.String())
	}
}

func TestUpstreamDownIs502(t *testing.T) {
	back := httptest.NewServer(http.NotFoundHandler())
	up := testUpstream(back.URL)
	back.Close() // nothing listens any more

	logs := &syncBuf{}
	s, err := seal.New([][]byte{bytes32(1)})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(up, publicURL, s, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	tok, err := s.Seal(seal.KindAccess, tokens.Access{Upstream: "tn", Creds: goodCreds()}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/mcp/tn", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway || strings.TrimSpace(string(b)) != "bad gateway" {
		t.Errorf("got %d %q", resp.StatusCode, b)
	}
	l := logs.String()
	if !strings.Contains(l, "level=WARN") {
		t.Errorf("no warn log: %s", l)
	}
	for _, secret := range []string{tok, "key-123", "secret-456"} {
		if strings.Contains(l, secret) {
			t.Errorf("secret %q leaked to logs", secret)
		}
	}
}

func TestNewValidation(t *testing.T) {
	s, err := seal.New([][]byte{bytes32(1)})
	if err != nil {
		t.Fatal(err)
	}
	good := testUpstream("http://127.0.0.1:1")
	if _, err := New(good, publicURL, nil, nil); err == nil {
		t.Error("nil sealer accepted")
	}
	bad := good
	bad.URL = "ftp://x"
	if _, err := New(bad, publicURL, s, nil); err == nil {
		t.Error("bad url accepted")
	}
	bad = good
	bad.Path = ""
	if _, err := New(bad, publicURL, s, nil); err == nil {
		t.Error("empty path accepted")
	}
	if _, err := New(good, publicURL, s, nil); err != nil {
		t.Errorf("good config: %v", err)
	}
}
