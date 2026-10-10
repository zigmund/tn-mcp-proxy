package config

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPublicURLNormalization(t *testing.T) {
	tests := map[string]string{
		"https://MCP.Example.COM":          "https://mcp.example.com",
		"HTTPS://mcp.example.com/":         "https://mcp.example.com",
		"https://mcp.example.com:443":      "https://mcp.example.com",
		"http://mcp.example.com:80/":       "http://mcp.example.com",
		"https://mcp.example.com:8443":     "https://mcp.example.com:8443",
		"http://mcp.example.com:443":       "http://mcp.example.com:443",
		"https://mcp.example.com:80":       "https://mcp.example.com:80",
		"https://mcp.example.com/p/q///":   "https://mcp.example.com/p/q",
		"https://Mcp.Example.com:443/Base": "https://mcp.example.com/Base",
		"https://[::1]:443/":               "https://[::1]",
		"http://[::1]:8080":                "http://[::1]:8080",
	}
	for in, want := range tests {
		y := strings.Replace(base(), "https://mcp.example.com/", in, 1)
		cfg, err := Parse([]byte(y), ".")
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if cfg.PublicURL != want {
			t.Errorf("%s: got %q, want %q", in, cfg.PublicURL, want)
		}
	}
}

func TestDecodeErrorDoesNotLeakKey(t *testing.T) {
	// token_keys given as a scalar: yaml echoes the value in its error.
	y := "public_url: https://mcp.example.com\nsecrets:\n  token_keys: " + key1 + "\n" + upstreamYAML
	_, err := Parse([]byte(y), ".")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), key1[:8]) {
		t.Fatalf("key prefix leaked: %v", err)
	}
	if !strings.Contains(err.Error(), "decoding yaml") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTLSPathsResolved(t *testing.T) {
	dir := t.TempDir()
	y := base() + "tls: {cert_file: certs/c.pem, key_file: /abs/k.pem}\n"
	cfg, err := Parse([]byte(y), dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLS.CertFile != filepath.Join(dir, "certs", "c.pem") {
		t.Errorf("cert_file: %s", cfg.TLS.CertFile)
	}
	if cfg.TLS.KeyFile != "/abs/k.pem" {
		t.Errorf("key_file: %s", cfg.TLS.KeyFile)
	}
	if !cfg.TLSEnabled() {
		t.Error("tls should be enabled")
	}
}

func TestTokenKeysClearedAfterParse(t *testing.T) {
	cfg, err := Parse([]byte(base()), ".")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Secrets.TokenKeys != nil || len(cfg.Secrets.Keys) != 1 {
		t.Fatalf("TokenKeys=%v Keys=%d", cfg.Secrets.TokenKeys, len(cfg.Secrets.Keys))
	}
}

func TestSerializationRedacted(t *testing.T) {
	cfg, err := Parse([]byte(base()), ".")
	if err != nil {
		t.Fatal(err)
	}
	raw := string(bytes.Repeat([]byte{1}, 32))

	var outs []string
	j, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	outs = append(outs, string(j))
	if !strings.Contains(string(j), "[redacted]") {
		t.Errorf("json: %s", j)
	}

	yb, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	outs = append(outs, string(yb))

	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, nil))
	l.Info("cfg", "secrets", cfg.Secrets, "config", cfg)
	outs = append(outs, buf.String())
	if !strings.Contains(buf.String(), "[redacted]") {
		t.Errorf("slog: %s", buf.String())
	}

	for _, o := range outs {
		if strings.Contains(o, key1) || strings.Contains(o, raw) {
			t.Errorf("key leaked: %s", o)
		}
	}
}
