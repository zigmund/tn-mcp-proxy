package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

func TestWarnNoAllowList(t *testing.T) {
	cfg := &config.Config{Upstreams: []config.Upstream{
		{Name: "open1", Credentials: []config.Credential{{Header: "X-A"}}},
		{Name: "closed", Credentials: []config.Credential{{Header: "X-A", AllowedValues: []string{"SECRET-VALUE"}}}},
		{Name: "open2", Credentials: []config.Credential{{Header: "X-A"}, {Header: "X-B"}}},
	}}
	var buf bytes.Buffer
	warnNoAllowList(slog.New(slog.NewTextHandler(&buf, nil)), cfg)
	out := buf.String()
	if n := strings.Count(out, "level=WARN"); n != 2 {
		t.Fatalf("got %d warnings, want 2:\n%s", n, out)
	}
	for _, want := range []string{"upstream=open1", "upstream=open2", "allowed_values"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "closed") || strings.Contains(out, "SECRET-VALUE") {
		t.Errorf("unexpected content:\n%s", out)
	}
}
