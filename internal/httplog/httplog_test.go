package httplog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newLogger(level slog.Level) (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level})), &buf
}

func records(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func TestInfoLevelLogsNothingButCallsNext(t *testing.T) {
	log, buf := newLogger(slog.LevelInfo)
	called := false
	h := Middleware(log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	if !called {
		t.Fatal("next not called")
	}
	if buf.Len() != 0 {
		t.Fatalf("unexpected output: %q", buf.String())
	}
}

func TestDebugRecordAttrs(t *testing.T) {
	log, buf := newLogger(slog.LevelDebug)
	h := Middleware(log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hello"))
	}))
	req := httptest.NewRequest("POST", "/mcp/foo?code=SECRET&state=S2", strings.NewReader("body-secret"))
	req.RemoteAddr = "203.0.113.7:5555"
	req.Header.Set("User-Agent", "test-agent/1")
	req.Header.Set("Authorization", "Bearer TOPSECRET")
	req.Header.Set("Cookie", "sid=COOKIESECRET")
	h.ServeHTTP(httptest.NewRecorder(), req)

	recs := records(t, buf)
	if len(recs) != 1 {
		t.Fatalf("got %d records: %s", len(recs), buf)
	}
	r := recs[0]
	want := map[string]any{
		"level": "DEBUG", "msg": "http request", "method": "POST", "path": "/mcp/foo",
		"status": float64(418), "bytes": float64(5), "remote": "203.0.113.7",
		"user_agent": "test-agent/1", "proto": "HTTP/1.1",
	}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("%s = %v, want %v", k, r[k], v)
		}
	}
	if _, ok := r["duration"]; !ok {
		t.Error("duration missing")
	}
	for _, s := range []string{"SECRET", "S2", "TOPSECRET", "COOKIESECRET", "body-secret", "?"} {
		if strings.Contains(buf.String(), s) {
			t.Errorf("output leaks %q: %s", s, buf)
		}
	}
}

func TestDefaultStatus200(t *testing.T) {
	log, buf := newLogger(slog.LevelDebug)
	h := Middleware(log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("abc"))
		_, _ = w.Write([]byte("de"))
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	r := records(t, buf)[0]
	if r["status"] != float64(200) || r["bytes"] != float64(5) {
		t.Fatalf("status/bytes = %v/%v", r["status"], r["bytes"])
	}
}

func TestNoWriteDefaultsTo200(t *testing.T) {
	log, buf := newLogger(slog.LevelDebug)
	h := Middleware(log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	if r := records(t, buf)[0]; r["status"] != float64(200) || r["bytes"] != float64(0) {
		t.Fatalf("status/bytes = %v/%v", r["status"], r["bytes"])
	}
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name, peer, realIP, xff, want string
	}{
		{"direct", "198.51.100.1:1", "", "", "198.51.100.1"},
		{"loopback real-ip", "127.0.0.1:1", "203.0.113.9", "", "203.0.113.9"},
		{"loopback xff wins over real-ip", "127.0.0.1:1", "1.1.1.1", "203.0.113.9", "203.0.113.9"},
		{"loopback xff invalid falls to real-ip", "127.0.0.1:1", "203.0.113.9", "bad", "203.0.113.9"},
		{"loopback zone stripped real-ip", "127.0.0.1:1", "fe80::1%eth0", "", "fe80::1"},
		{"loopback zone stripped xff", "127.0.0.1:1", "", "1.1.1.1, fe80::2%eth0", "fe80::2"},
		{"loopback mapped v4 header", "127.0.0.1:1", "::ffff:203.0.113.9", "", "203.0.113.9"},
		{"loopback xff rightmost", "127.0.0.1:1", "", "6.6.6.6, 203.0.113.9", "203.0.113.9"},
		{"loopback xff trailing empty is invalid", "127.0.0.1:1", "", "203.0.113.9,", "127.0.0.1"},
		{"loopback v6 peer", "[::1]:1", "2001:db8::1", "", "2001:db8::1"},
		{"loopback invalid headers", "127.0.0.1:1", "garbage", "also, bad", "127.0.0.1"},
		{"loopback invalid real-ip falls to xff", "127.0.0.1:1", "garbage", "203.0.113.9", "203.0.113.9"},
		{"loopback no headers", "127.0.0.1:1", "", "", "127.0.0.1"},
		{"spoofed real-ip non-loopback", "198.51.100.1:1", "9.9.9.9", "8.8.8.8", "198.51.100.1"},
		{"v4-mapped loopback peer", "[::ffff:127.0.0.1]:1", "", "203.0.113.9", "203.0.113.9"},
		{"unparsable peer", "weird", "9.9.9.9", "", "weird"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.peer
			if tt.realIP != "" {
				r.Header.Set("X-Real-IP", tt.realIP)
			}
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := ClientIP(r); got != tt.want {
				t.Fatalf("ClientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

// Flushed chunks must reach the client before the handler returns.
func TestFlushStreamsIncrementally(t *testing.T) {
	for _, mode := range []string{"flusher", "controller"} {
		t.Run(mode, func(t *testing.T) {
			log, _ := newLogger(slog.LevelDebug)
			release := make(chan struct{})
			srv := httptest.NewServer(Middleware(log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("data: 1\n\n"))
				if mode == "flusher" {
					w.(http.Flusher).Flush()
				} else if err := http.NewResponseController(w).Flush(); err != nil {
					t.Errorf("ResponseController.Flush: %v", err)
				}
				<-release
				_, _ = w.Write([]byte("data: 2\n\n"))
			})))
			defer srv.Close()
			defer close(release)

			resp, err := http.Get(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			lineCh := make(chan string, 1)
			go func() {
				line, _ := bufio.NewReader(resp.Body).ReadString('\n')
				lineCh <- line
			}()
			select {
			case line := <-lineCh:
				if line != "data: 1\n" {
					t.Fatalf("first line = %q", line)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("flushed chunk did not reach client while handler was blocked")
			}
		})
	}
}

func TestUnwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &recorder{ResponseWriter: rec}
	if rw.Unwrap() != http.ResponseWriter(rec) {
		t.Fatal("Unwrap did not return the underlying writer")
	}
	// ResponseController must reach the underlying Flusher through Unwrap.
	if err := http.NewResponseController(rw).Flush(); err != nil {
		t.Fatalf("ResponseController.Flush via Unwrap: %v", err)
	}
	if !rec.Flushed {
		t.Fatal("underlying recorder not flushed")
	}
}

func serve(t *testing.T, h http.HandlerFunc, req *http.Request) (map[string]any, *httptest.ResponseRecorder) {
	t.Helper()
	log, buf := newLogger(slog.LevelDebug)
	rec := httptest.NewRecorder()
	Middleware(log, h).ServeHTTP(rec, req)
	recs := records(t, buf)
	if len(recs) != 1 {
		t.Fatalf("got %d records: %s", len(recs), buf)
	}
	return recs[0], rec
}

func TestStatusSemantics(t *testing.T) {
	tests := []struct {
		name string
		h    http.HandlerFunc
		want float64
	}{
		{"103 then 200", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusEarlyHints)
			w.WriteHeader(http.StatusOK)
		}, 200},
		{"103 then 404", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusEarlyHints)
			w.WriteHeader(http.StatusNotFound)
		}, 404},
		{"101", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusSwitchingProtocols)
		}, 101},
		{"double WriteHeader first wins", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			w.WriteHeader(http.StatusInternalServerError)
		}, 202},
		{"WriteHeader then Write", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("x"))
		}, 201},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := serve(t, tt.h, httptest.NewRequest("GET", "/", nil))
			if r["status"] != tt.want {
				t.Fatalf("status = %v, want %v", r["status"], tt.want)
			}
		})
	}
}

func TestInvalidStatusPanicNotRecorded(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &recorder{ResponseWriter: rec}
	func() {
		defer func() { _ = recover() }()
		rw.WriteHeader(42) // httptest/net/http panic on codes < 100
	}()
	if rw.status != 0 {
		t.Fatalf("bogus status recorded: %d", rw.status)
	}
}

func TestBytesAcrossFlush(t *testing.T) {
	r, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("abc"))
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("defg"))
		w.(http.Flusher).Flush()
	}, httptest.NewRequest("GET", "/", nil))
	if r["bytes"] != float64(7) || r["status"] != float64(200) {
		t.Fatalf("bytes/status = %v/%v", r["bytes"], r["status"])
	}
}

func TestFlushSetsDefaultStatus(t *testing.T) {
	r, _ := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush()
	}, httptest.NewRequest("GET", "/", nil))
	if r["status"] != float64(200) {
		t.Fatalf("status = %v", r["status"])
	}
}

func TestMultipleXFFLines(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Add("X-Forwarded-For", "6.6.6.6, 7.7.7.7")
	req.Header.Add("X-Forwarded-For", "8.8.8.8, 203.0.113.9")
	if got := ClientIP(req); got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q", got)
	}
}

func TestPanicIsLoggedAndRepanicked(t *testing.T) {
	for _, tt := range []struct {
		name    string
		val     any
		attr    string
		wantVal any
	}{
		{"panic", "boom", "panic", true},
		{"abort", http.ErrAbortHandler, "aborted", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			log, buf := newLogger(slog.LevelDebug)
			h := Middleware(log, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(tt.val) }))
			var got any
			func() {
				defer func() { got = recover() }()
				h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/p", nil))
			}()
			if got != tt.val {
				t.Fatalf("re-panic value = %v, want %v", got, tt.val)
			}
			recs := records(t, buf)
			if len(recs) != 1 {
				t.Fatalf("got %d records", len(recs))
			}
			if recs[0][tt.attr] != tt.wantVal || recs[0]["status"] != float64(0) || recs[0]["path"] != "/p" {
				t.Fatalf("unexpected record: %v", recs[0])
			}
		})
	}
}

func TestPanicAfterStatusKeepsStatus(t *testing.T) {
	log, buf := newLogger(slog.LevelDebug)
	h := Middleware(log, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		panic("late")
	}))
	func() {
		defer func() { _ = recover() }()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}()
	if r := records(t, buf)[0]; r["status"] != float64(418) || r["panic"] != true {
		t.Fatalf("unexpected record: %v", r)
	}
}

func TestHijackViaResponseController(t *testing.T) {
	log, _ := newLogger(slog.LevelDebug)
	hijacked := make(chan error, 1)
	srv := httptest.NewServer(Middleware(log, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := http.NewResponseController(w).Hijack()
		hijacked <- err
		if err == nil {
			_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
			_ = conn.Close()
		}
	})))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := <-hijacked; err != nil {
		t.Fatalf("Hijack via ResponseController: %v", err)
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != "ok" {
		t.Fatalf("body = %q", b)
	}
}

type nopWriter struct{ h http.Header }

func (w nopWriter) Header() http.Header       { return w.h }
func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriter) WriteHeader(int)             {}

// With debug disabled the middleware must not allocate (no recorder, no attrs).
func TestDisabledPathAllocatesNothing(t *testing.T) {
	log, _ := newLogger(slog.LevelInfo)
	h := Middleware(log, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	req := httptest.NewRequest("GET", "/", nil)
	w := nopWriter{h: http.Header{}}
	if n := testing.AllocsPerRun(100, func() { h.ServeHTTP(w, req) }); n != 0 {
		t.Fatalf("allocs = %v, want 0", n)
	}
}
