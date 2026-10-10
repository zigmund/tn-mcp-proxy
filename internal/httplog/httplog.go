// Package httplog provides a debug-level HTTP access log middleware.
//
// It records one "http request" record per request after the handler
// returns: method, path (never the query string), status, response bytes,
// duration, client address, user agent and protocol. Headers (Authorization,
// Cookie, ...) and bodies are never logged.
package httplog

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Middleware logs every request handled by next at Debug level. When Debug is
// disabled on log it only calls next. The record is written when the handler
// returns, so a long-lived stream (SSE) is logged only once it closes.
//
// If the handler panics, the record is still written with panic=true (or
// aborted=true for http.ErrAbortHandler), status 0 unless a status was already
// sent, and the panic is re-raised for net/http to handle.
func Middleware(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if !log.Enabled(ctx, slog.LevelDebug) {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rw := &recorder{ResponseWriter: w}
		defer func() {
			p := recover()
			attrs := make([]slog.Attr, 0, 10)
			status := rw.status
			if status == 0 && p == nil {
				status = http.StatusOK
			}
			attrs = append(attrs,
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Int64("bytes", rw.bytes),
				slog.Duration("duration", time.Since(start)),
				slog.String("remote", ClientIP(r)),
				slog.String("user_agent", r.UserAgent()),
				slog.String("proto", r.Proto),
			)
			if p != nil {
				if p == http.ErrAbortHandler { //nolint:errorlint // net/http compares by identity
					attrs = append(attrs, slog.Bool("aborted", true))
				} else {
					attrs = append(attrs, slog.Bool("panic", true))
				}
			}
			log.LogAttrs(ctx, slog.LevelDebug, "http request", attrs...)
			if p != nil {
				panic(p)
			}
		}()
		next.ServeHTTP(rw, r)
	})
}

// ClientIP returns the client IP (no port) for r. X-Forwarded-For and
// X-Real-IP are honoured only when the direct peer is a loopback address (the
// reverse proxy on localhost). The right-most X-Forwarded-For entry (the one
// the proxy appended; earlier entries are client-controlled) wins, X-Real-IP
// is the fallback. Header values must be valid IPs; IPv6 zones are dropped and
// IPv4-mapped addresses unmapped. Otherwise the peer address is returned.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !peer.Unmap().IsLoopback() {
		return host
	}
	if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
		last := xff[len(xff)-1]
		last = last[strings.LastIndexByte(last, ',')+1:]
		if ip, ok := parseIP(last); ok {
			return ip
		}
	}
	if ip, ok := parseIP(r.Header.Get("X-Real-IP")); ok {
		return ip
	}
	return host
}

func parseIP(s string) (string, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	return ip.Unmap().WithZone("").String(), true
}

// recorder captures status and body size. Hijacker and io.ReaderFrom are not
// implemented here; they stay reachable only through http.ResponseController
// via Unwrap (hijacked connections bypass the recorder, so their status and
// bytes are not tracked).
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *recorder) WriteHeader(code int) {
	r.ResponseWriter.WriteHeader(code) // may panic on an invalid code
	// First final status wins; 1xx other than 101 are interim responses.
	if r.status == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
		r.status = code
	}
}

func (r *recorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytes += int64(n)
	return n, err
}

// Flush implements http.Flusher; it is required for SSE through
// httputil.ReverseProxy. The error is ignored because Flusher has no way to
// report it; a dead client surfaces on the next Write.
func (r *recorder) Flush() {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	_ = http.NewResponseController(r.ResponseWriter).Flush()
}

// Unwrap returns the underlying ResponseWriter for http.ResponseController.
func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
