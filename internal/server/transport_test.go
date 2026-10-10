package server

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
)

func transportHandler(t *testing.T, extra string) http.Handler {
	t.Helper()
	cfg, err := config.Parse([]byte(extra+testYAML), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(cfg.Secrets.Keys)
	if err != nil {
		t.Fatal(err)
	}
	h, err := Handler(cfg, sealer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHSTSWithBuiltinTLS(t *testing.T) {
	h := transportHandler(t, "tls: { cert_file: c.pem, key_file: k.pem }\n")
	for _, path := range []string{"/healthz", "/.well-known/oauth-authorization-server", "/nope", "/oauth/token"} {
		rec := get(t, h, http.MethodGet, path)
		if got := rec.Header().Values("Strict-Transport-Security"); len(got) != 1 || got[0] != "max-age=31536000" {
			t.Errorf("%s: HSTS = %q", path, got)
		}
	}
}

func TestNoHSTSWithoutBuiltinTLS(t *testing.T) {
	h := transportHandler(t, "")
	for _, path := range []string{"/healthz", "/nope"} {
		if got := get(t, h, http.MethodGet, path).Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("%s: unexpected HSTS %q", path, got)
		}
	}
}

func TestHSTSOverridesUpstreamValue(t *testing.T) {
	h := withHSTS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=1")
		_, _ = w.Write([]byte("body")) // implicit 200
	}))
	rec := get(t, h, http.MethodGet, "/x")
	if got := rec.Header().Values("Strict-Transport-Security"); len(got) != 1 || got[0] != "max-age=31536000" {
		t.Errorf("HSTS = %q", got)
	}
	if rec.Body.String() != "body" {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// deadlineWriter records SetReadDeadline calls.
type deadlineWriter struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineWriter) SetReadDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

func TestReadDeadlineOnlyOnOAuthPaths(t *testing.T) {
	h := withOAuthReadDeadline(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for path, want := range map[string]bool{
		"/oauth/token": true, "/oauth/register": true, "/oauth/authorize": true, "/oauth": true,
		"/.well-known/oauth-protected-resource/tn/mcp": true,
		"/tn/mcp": false, "/healthz": false, "/oauthx": false,
	} {
		w := &deadlineWriter{ResponseRecorder: httptest.NewRecorder()}
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, nil))
		if got := len(w.deadlines) == 1; got != want {
			t.Errorf("%s: deadline set = %v, want %v", path, got, want)
		}
		if want && time.Until(w.deadlines[0]) > oauthReadTimeout {
			t.Errorf("%s: deadline too far", path)
		}
	}
	// A writer without deadline support must not break the request.
	rec := httptest.NewRecorder()
	called := false
	withOAuthReadDeadline(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).
		ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/oauth/token", nil))
	if !called {
		t.Error("handler not called when SetReadDeadline is unsupported")
	}
}

// A client that stalls mid-body on an OAuth endpoint is cut off by the read
// deadline instead of holding the connection open.
func TestSlowOAuthBodyIsCutOff(t *testing.T) {
	old := oauthReadTimeout
	oauthReadTimeout = 300 * time.Millisecond
	t.Cleanup(func() { oauthReadTimeout = old })

	srv := httptest.NewServer(transportHandler(t, ""))
	t.Cleanup(srv.Close)

	slow := func(path string) (cut bool) {
		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.WriteString(conn, "POST "+path+" HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1000\r\n\r\ngrant_type=")
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		// Either a response (400) or a closed connection counts as cut off; a
		// read timeout on our side means the server kept waiting for the body.
		_, err = bufio.NewReader(conn).ReadString('\n')
		if err == nil {
			return true
		}
		ne, isNet := err.(net.Error)
		return !isNet || !ne.Timeout()
	}
	start := time.Now()
	if !slow("/oauth/token") {
		t.Error("slow body on /oauth/token was not cut off")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("cut off after %v, want about the read timeout", time.Since(start))
	}
	// The MCP path has no read deadline: the server keeps waiting for the body.
	// (Unauthenticated requests are rejected before reading it, so only the
	// deadline wiring is asserted for that path, in TestReadDeadlineOnlyOnOAuthPaths.)
}

func TestHSTSStreamingThroughRealServer(t *testing.T) {
	second := make(chan struct{})
	srv := httptest.NewServer(withHSTS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=1") // upstream value
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		// Flush through the ResponseController (exercises Unwrap/Flush).
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush: %v", err)
		}
		<-second // the client must see chunk one before this is released
		_, _ = io.WriteString(w, "data: two\n\n")
	})))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Values("Strict-Transport-Security"); len(got) != 1 || got[0] != "max-age=31536000" {
		t.Errorf("HSTS = %q", got)
	}
	r := bufio.NewReader(resp.Body)
	line, err := r.ReadString('\n')
	if err != nil || line != "data: one\n" {
		t.Fatalf("first chunk = %q, %v (stream buffered?)", line, err)
	}
	close(second)
	rest, _ := io.ReadAll(r)
	if !strings.Contains(string(rest), "data: two") {
		t.Errorf("second chunk missing: %q", rest)
	}
}

func TestHSTSNotOnInformationalResponse(t *testing.T) {
	var early http.Header
	srv := httptest.NewServer(withHSTS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", "</x.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})))
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
			if code == http.StatusEarlyHints {
				early = http.Header(h)
			}
			return nil
		},
	}))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if early == nil {
		t.Fatal("no 103 response seen")
	}
	if early.Get("Strict-Transport-Security") != "" {
		t.Errorf("HSTS on the 103 response: %v", early)
	}
	if got := resp.Header.Values("Strict-Transport-Security"); len(got) != 1 {
		t.Errorf("final HSTS = %q", got)
	}
}

// withHSTS wrapping the deadline handler must keep the deadline effective:
// ResponseController reaches the connection through hstsWriter.Unwrap.
func TestSlowBodyCutOffThroughHSTS(t *testing.T) {
	old := oauthReadTimeout
	oauthReadTimeout = 300 * time.Millisecond
	t.Cleanup(func() { oauthReadTimeout = old })

	srv := httptest.NewServer(withHSTS(withOAuthReadDeadline(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		if err == nil {
			t.Error("body read finished without error")
		}
		w.WriteHeader(http.StatusBadRequest)
	}))))
	t.Cleanup(srv.Close)

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "POST /oauth/token HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\nabc")
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 400") {
		t.Fatalf("response = %q, %v", line, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("cut off after %v", time.Since(start))
	}
}
