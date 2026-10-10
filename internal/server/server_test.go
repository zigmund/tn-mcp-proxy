package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
)

const testYAML = `
listen: 127.0.0.1:0
public_url: https://mcp.example.com
secrets:
  token_keys: ["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]
upstreams:
  - name: tn
    path: /tn/mcp
    url: https://upstream.example.com/mcp
    credentials:
      - { header: X-Key, label: Key }
`

func newTestServer(t *testing.T, logw io.Writer) *Server {
	t.Helper()
	cfg, err := config.Parse([]byte(testYAML), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(cfg.Secrets.Keys)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(logw, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s, err := New(cfg, sealer, log)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func get(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestHealthz(t *testing.T) {
	var logs bytes.Buffer
	h := newTestServer(t, &logs).Handler()
	rec := get(t, h, http.MethodGet, "/healthz")
	if rec.Code != 200 || rec.Body.String() != "ok" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if strings.Contains(logs.String(), "http request") {
		t.Errorf("healthz must not be access-logged: %s", logs.String())
	}
	if rec := get(t, h, http.MethodPost, "/healthz"); rec.Code == 200 {
		t.Errorf("POST /healthz = %d", rec.Code)
	}
}

func TestRouting(t *testing.T) {
	var logs bytes.Buffer
	h := newTestServer(t, &logs).Handler()

	// Exact upstream path reaches the proxy (401 challenge: no bearer token).
	rec := get(t, h, http.MethodPost, "/tn/mcp")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("/tn/mcp = %d, want 401", rec.Code)
	}
	for _, p := range []string{"/tn/mcp/", "/tn/mcp/x", "/tn", "/nope"} {
		if rec := get(t, h, http.MethodPost, p); rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", p, rec.Code)
		}
	}
	logs.Reset()
	if rec := get(t, h, http.MethodGet, "//tn/x"); rec.Code != http.StatusTemporaryRedirect {
		t.Errorf("non-clean path = %d, want 307", rec.Code)
	}
	if !strings.Contains(logs.String(), "http request") {
		t.Error("mux redirect must be access-logged")
	}
	rec = get(t, h, http.MethodGet, "/.well-known/oauth-authorization-server")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "https://mcp.example.com") {
		t.Errorf("metadata = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(logs.String(), "http request") {
		t.Error("expected access log for non-healthz requests at debug")
	}
}

func TestServeGracefulShutdown(t *testing.T) {
	s := newTestServer(t, io.Discard)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestServeShutdownTimeoutClosesStreams(t *testing.T) {
	var logs syncBuf
	s := newTestServer(t, &logs)
	s.shutdownTimeout = 100 * time.Millisecond
	started := make(chan struct{})
	// Replace the handler with one that streams forever (SSE-like).
	s.http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	<-started
	readDone := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, resp.Body); readDone <- err }()
	begin := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve blocked on a streaming connection")
	}
	if el := time.Since(begin); el < s.shutdownTimeout {
		t.Errorf("Serve returned after %v, before the shutdown timeout %v", el, s.shutdownTimeout)
	}
	select {
	case <-readDone: // the forced Close ends the stream (EOF or reset)
	case <-time.After(5 * time.Second):
		t.Fatal("client stream still open after Serve returned")
	}
	if !strings.Contains(logs.String(), "timed out") {
		t.Errorf("missing timeout log: %s", logs.String())
	}
}

func TestReloadHooks(t *testing.T) {
	var logs bytes.Buffer
	s := newTestServer(t, &logs)
	s.Reload()
	if !strings.Contains(logs.String(), "nothing to reload") {
		t.Errorf("logs: %s", logs.String())
	}

	var calls atomic.Int32
	s.OnReload("a", func() error { calls.Add(1); return os.ErrInvalid })
	s.OnReload("b", func() error { calls.Add(1); return nil })

	sigs := make(chan os.Signal)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.WatchReload(ctx, sigs); close(done) }()
	sigs <- os.Interrupt // unbuffered: handled once received
	sigs <- os.Interrupt // second send returns only after first Reload finished
	cancel()
	<-done
	if got := calls.Load(); got < 2 {
		t.Errorf("hook calls = %d, want >= 2", got)
	}
	if !strings.Contains(logs.String(), "reload failed") {
		t.Errorf("failing hook not logged: %s", logs.String())
	}
}

// syncBuf is a goroutine-safe log sink.
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
