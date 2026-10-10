package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

func TestWarnAllowListWithoutForbiddenArguments(t *testing.T) {
	cfg := &config.Config{Upstreams: []config.Upstream{
		{Name: "listed", Credentials: []config.Credential{{Header: "X-A", AllowedValues: []string{"SECRET-VALUE"}}}},
		{Name: "covered", ForbiddenArguments: []string{"api_key"}, Credentials: []config.Credential{{Header: "X-A", AllowedValues: []string{"SECRET-VALUE"}}}},
	}}
	var buf bytes.Buffer
	warnNoAllowList(slog.New(slog.NewTextHandler(&buf, nil)), cfg)
	out := buf.String()
	if n := strings.Count(out, "level=WARN"); n != 1 {
		t.Fatalf("got %d warnings, want 1:\n%s", n, out)
	}
	for _, want := range []string{"upstream=listed", "forbidden_arguments"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "covered") || strings.Contains(out, "SECRET-VALUE") {
		t.Errorf("unexpected content:\n%s", out)
	}
}
