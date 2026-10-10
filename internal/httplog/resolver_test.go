package httplog

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

func TestResolverClientIP(t *testing.T) {
	// Trusted proxies: loopback plus a private proxy tier and a CDN range.
	rv := NewResolver(prefixes(t, "127.0.0.0/8", "::1/128", "10.0.0.0/8", "198.51.100.0/24", "2001:db8:ffff::/48"))
	tests := []struct {
		name, peer string
		xff        []string // one header line each
		realIP     string
		want       string
	}{
		{"untrusted peer ignores xff", "203.0.113.5:1", []string{"9.9.9.9"}, "8.8.8.8", "203.0.113.5"},
		{"untrusted v6 peer ignores headers", "[2001:db8::5]:1", []string{"9.9.9.9"}, "8.8.8.8", "2001:db8::5"},
		{"untrusted mapped peer is unmapped", "[::ffff:203.0.113.5]:1", nil, "", "203.0.113.5"},
		{"trusted peer, single entry", "10.1.2.3:1", []string{"203.0.113.9"}, "", "203.0.113.9"},
		{"multi-hop chain, rightmost untrusted wins", "10.1.2.3:1", []string{"203.0.113.9, 198.51.100.7, 10.9.9.9"}, "", "203.0.113.9"},
		{"spoofed left entries ignored", "10.1.2.3:1", []string{"1.1.1.1, 2.2.2.2, 203.0.113.9, 198.51.100.7"}, "", "203.0.113.9"},
		{"spoofed entry left of a trusted one", "127.0.0.1:1", []string{"6.6.6.6, 10.0.0.1"}, "", "6.6.6.6"},
		{"all trusted, leftmost used", "127.0.0.1:1", []string{"10.0.0.2, 10.0.0.3, 198.51.100.7"}, "", "10.0.0.2"},
		{"multiple header lines combined", "127.0.0.1:1", []string{"6.6.6.6, 7.7.7.7", "203.0.113.9, 10.0.0.1"}, "", "203.0.113.9"},
		{"v6 chain", "[::1]:1", []string{"2001:db8:1::7, 2001:db8:ffff::1"}, "", "2001:db8:1::7"},
		{"invalid rightmost falls to real-ip", "127.0.0.1:1", []string{"203.0.113.9, bad"}, "203.0.113.50", "203.0.113.50"},
		{"invalid after trusted skip falls to real-ip", "127.0.0.1:1", []string{"garbage, 10.0.0.5"}, "203.0.113.50", "203.0.113.50"},
		{"invalid entry stops walk, then peer", "127.0.0.1:1", []string{"203.0.113.9, bad, 10.0.0.1"}, "", "127.0.0.1"},
		{"empty trailing entry is invalid", "127.0.0.1:1", []string{"203.0.113.9,"}, "", "127.0.0.1"},
		{"zone and mapped normalized", "127.0.0.1:1", []string{"::ffff:203.0.113.9"}, "", "203.0.113.9"},
		{"real-ip when no xff", "10.1.2.3:1", nil, "203.0.113.50", "203.0.113.50"},
		{"nothing usable", "10.1.2.3:1", nil, "bad", "10.1.2.3"},
		{"unparsable peer", "weird", []string{"9.9.9.9"}, "", "weird"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.peer
			for _, l := range tt.xff {
				r.Header.Add("X-Forwarded-For", l)
			}
			if tt.realIP != "" {
				r.Header.Set("X-Real-IP", tt.realIP)
			}
			if got := rv.ClientIP(r); got != tt.want {
				t.Fatalf("ClientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolverDefaultTrustsOnlyLoopback(t *testing.T) {
	rv := NewResolver(nil)
	for peer, want := range map[string]string{
		"127.0.0.1:1": "203.0.113.9", "[::1]:1": "203.0.113.9", "10.0.0.1:1": "10.0.0.1",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = peer
		r.Header.Set("X-Forwarded-For", "203.0.113.9")
		if got := rv.ClientIP(r); got != want {
			t.Errorf("peer %s: ClientIP = %q, want %q", peer, got, want)
		}
	}
}

func TestMiddlewareUsesResolver(t *testing.T) {
	log, buf := newLogger(slog.LevelDebug)
	rv := NewResolver(prefixes(t, "10.0.0.0/8"))
	h := Middleware(log, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), WithResolver(rv))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if r := records(t, buf)[0]; r["remote"] != "203.0.113.9" {
		t.Fatalf("remote = %v", r["remote"])
	}
	// Loopback is not trusted by this resolver.
	buf.Reset()
	req = httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if r := records(t, buf)[0]; r["remote"] != "127.0.0.1" {
		t.Fatalf("remote = %v", r["remote"])
	}
}
