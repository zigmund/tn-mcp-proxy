package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

func TestContentEncoding(t *testing.T) {
	tests := []struct {
		name   string
		values []string // one entry per header line; nil sends no header
		want   int
	}{
		{"absent", nil, 200},
		{"identity", []string{"identity"}, 200},
		{"identity upper case", []string{" IDENTITY "}, 200},
		{"empty value", []string{""}, 200},
		{"gzip", []string{"gzip"}, 415},
		{"br", []string{"br"}, 415},
		{"deflate", []string{"deflate"}, 415},
		{"GZIP", []string{"GZIP"}, 415},
		{"padded gzip", []string{"  gzip  "}, 415},
		{"gzip, identity", []string{"gzip, identity"}, 415},
		{"identity, gzip", []string{"identity, gzip"}, 415},
		{"multiple lines", []string{"identity", "gzip"}, 415},
		{"multiple identity lines", []string{"identity", "identity"}, 200},
	}
	for _, withForbid := range []bool{false, true} {
		name := "no forbidden_arguments"
		var mutate func(*config.Upstream)
		if withForbid {
			name, mutate = "forbidden_arguments", forbid
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					e := newEnvUp(t, nil, mutate)
					req, err := http.NewRequest("POST", e.proxy.URL+"/mcp/tn", strings.NewReader(call(`{}`)))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Authorization", "Bearer "+e.access(t, goodCreds()))
					for _, v := range tc.values {
						req.Header.Add("Content-Encoding", v)
					}
					resp, err := http.DefaultClient.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = resp.Body.Close() }()
					if resp.StatusCode != tc.want {
						t.Fatalf("status %d, want %d", resp.StatusCode, tc.want)
					}
					reqs := e.requests()
					if tc.want == 415 {
						if len(reqs) != 0 {
							t.Fatalf("%d requests reached the upstream", len(reqs))
						}
						if strings.Contains(e.logs.String(), "gzip") {
							t.Errorf("log mentions the header value: %s", e.logs.String())
						}
					} else if len(reqs) != 1 {
						t.Fatalf("upstream saw %d requests, want 1", len(reqs))
					}
				})
			}
		})
	}
}

func TestContentEncodingBody(t *testing.T) {
	e := newEnv(t, nil)
	resp := e.do(t, "POST", "/mcp/tn", "Bearer "+e.access(t, goodCreds()), map[string]string{"Content-Encoding": "gzip"}, "\x1f\x8b junk")
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status %d", resp.StatusCode)
	}
	b := make([]byte, 128)
	n, _ := resp.Body.Read(b)
	if got := strings.TrimSpace(string(b[:n])); got != "content-encoding not supported" {
		t.Errorf("body %q", got)
	}
}

func TestContentEncodingRefundsIP(t *testing.T) {
	cfg := offLimits()
	cfg.IP = config.Limit{PerMinute: 60, Burst: 2}
	e, _, _ := limitsEnv(t, cfg, nil)
	a := e.tokFor(t, "a")
	for range 5 {
		if r := e.do(t, "POST", "/mcp/tn", "Bearer "+a, map[string]string{"Content-Encoding": "gzip"}, `{}`); r.StatusCode != http.StatusUnsupportedMediaType {
			t.Fatalf("status %d", r.StatusCode)
		}
	}
	for range 2 {
		if r := status(e, t, a); r.StatusCode != 200 {
			t.Errorf("IP tokens not refunded: %d", r.StatusCode)
		}
	}
}
