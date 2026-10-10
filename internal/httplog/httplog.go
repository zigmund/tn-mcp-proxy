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
	"slices"
	"strings"
	"time"
)

// Option configures Middleware.
type Option func(**Resolver)

// WithResolver makes Middleware use rv to determine the logged client IP.
func WithResolver(rv *Resolver) Option {
	return func(p **Resolver) {
		if rv != nil {
			*p = rv
		}
	}
}

// Middleware logs every request handled by next at Debug level. When Debug is
// disabled on log it only calls next. The record is written when the handler
// returns, so a long-lived stream (SSE) is logged only once it closes.
//
// If the handler panics, the record is still written with panic=true (or
// aborted=true for http.ErrAbortHandler), status 0 unless a status was already
// sent, and the panic is re-raised for net/http to handle.
func Middleware(log *slog.Logger, next http.Handler, opts ...Option) http.Handler {
	rv := defaultResolver
	for _, o := range opts {
		o(&rv)
	}
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
				slog.String("remote", rv.ClientIP(r)),
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

// Resolver derives the client IP of a request from the TCP peer and the
// forwarding headers, honouring the headers only for trusted proxies. One
// Resolver is shared by the access log and the rate limiter so both agree.
type Resolver struct {
	trusted []netip.Prefix
}

// DefaultTrusted is the trusted proxy set used when none is given: loopback
// (a reverse proxy on the same host).
func DefaultTrusted() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
}

// NewResolver returns a Resolver trusting the given proxy networks. An empty
// set means DefaultTrusted.
func NewResolver(trusted []netip.Prefix) *Resolver {
	if len(trusted) == 0 {
		trusted = DefaultTrusted()
	}
	return &Resolver{trusted: slices.Clone(trusted)}
}

var defaultResolver = NewResolver(nil)

// ClientIP returns the client IP (no port) for r using the loopback-only
// default trust set. See Resolver.ClientIP.
func ClientIP(r *http.Request) string { return defaultResolver.ClientIP(r) }

func (rv *Resolver) isTrusted(a netip.Addr) bool {
	for _, p := range rv.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP returns the client IP (no port) for r.
//
// If the TCP peer is not a trusted proxy it is the answer and every
// forwarding header is ignored (a client could otherwise spoof its address).
// For a trusted peer the X-Forwarded-For entries (all header lines, comma
// separated) are walked from the right, skipping trusted proxies; the first
// untrusted entry is the client. If every entry is trusted the left-most one
// is used. An entry that is not a valid IP stops the walk and the header is
// treated as unusable. Then X-Real-IP is used if valid, else the peer.
// IPv6 zones are dropped and IPv4-mapped addresses unmapped.
func (rv *Resolver) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = normalize(peer)
	if !rv.isTrusted(peer) {
		return peer.String()
	}
	if ip, ok := rv.fromForwardedFor(r.Header.Values("X-Forwarded-For")); ok {
		return ip.String()
	}
	if ip, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
		return normalize(ip).String()
	}
	return peer.String()
}

// fromForwardedFor walks the entries of the header lines from the right.
func (rv *Resolver) fromForwardedFor(lines []string) (netip.Addr, bool) {
	var leftmost netip.Addr
	for i := len(lines) - 1; i >= 0; i-- {
		parts := strings.Split(lines[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			ip, err := netip.ParseAddr(strings.TrimSpace(parts[j]))
			if err != nil {
				return netip.Addr{}, false
			}
			ip = normalize(ip)
			if !rv.isTrusted(ip) {
				return ip, true
			}
			leftmost = ip
		}
	}
	return leftmost, leftmost.IsValid()
}

func normalize(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

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
