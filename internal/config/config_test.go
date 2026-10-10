package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var (
	key1 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	key2 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
)

const upstreamYAML = `
upstreams:
  - name: tn
    path: /tn/mcp
    url: https://tradernet.com/mcp/tn
    credentials:
      - { header: X-TN-API-Key }
`

func base() string {
	return "public_url: https://mcp.example.com/\nsecrets:\n  token_keys: [\"" + key1 + "\"]\n" + upstreamYAML
}

func TestDefaultRedirectURIs(t *testing.T) {
	got := DefaultRedirectURIs()
	for _, want := range []string{
		"https://claude.ai/api/mcp/auth_callback",
		"https://claude.com/api/mcp/auth_callback",
		"https://chatgpt.com/connector_platform_oauth_redirect",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("default redirect URIs lack %s: %v", want, got)
		}
	}
}

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse([]byte(base()), ".")
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name      string
		got, want any
	}{
		{"listen", cfg.Listen, DefaultListen},
		{"public_url", cfg.PublicURL, "https://mcp.example.com"},
		{"log.level", cfg.Log.Level, "info"},
		{"log.format", cfg.Log.Format, "json"},
		{"access ttl", cfg.OAuth.AccessTokenTTL, time.Hour},
		{"refresh ttl", cfg.OAuth.RefreshTokenTTL, 720 * time.Hour},
		{"code ttl", cfg.OAuth.CodeTTL, 5 * time.Minute},
		{"redirects", strings.Join(cfg.OAuth.AllowedRedirectURIs, ","), strings.Join(DefaultRedirectURIs(), ",")},
		{"title", cfg.Upstreams[0].Title, "tn"},
		{"label", cfg.Upstreams[0].Credentials[0].Label, "X-TN-API-Key"},
		{"tls enabled", cfg.TLSEnabled(), false},
		{"reload", cfg.TLS.ReloadInterval, time.Duration(0)},
		{"slog", cfg.Log.SlogLevel(), slog.LevelInfo},
		{"keys", len(cfg.Secrets.Keys), 1},
		{"key len", len(cfg.Secrets.Keys[0]), 32},
		{"resource", cfg.Upstreams[0].ResourceURL(cfg.PublicURL), "https://mcp.example.com/tn/mcp"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestParseExplicitValues(t *testing.T) {
	y := `
listen: 0.0.0.0:9000
public_url: http://localhost:9000
log: { level: DEBUG, format: text }
secrets: { token_keys: ["` + key1 + `", "` + key2 + `"] }
oauth:
  access_token_ttl: 30m
  refresh_token_ttl: 24h
  code_ttl: 1m
  allowed_redirect_uris: ["https://example.com/cb"]
tls: { cert_file: c.pem, key_file: k.pem }
upstreams:
  - name: a-1
    title: Alpha
    path: /a
    url: http://up:8080/mcp?x=1
    credentials:
      - { header: X-A, label: Aaa, secret: true }
      - { header: X-B, optional: true }
`
	cfg, err := Parse([]byte(y), ".")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log.SlogLevel() != slog.LevelDebug || cfg.Log.Level != "debug" {
		t.Errorf("log level: %+v", cfg.Log)
	}
	if cfg.OAuth.AccessTokenTTL != 30*time.Minute || cfg.OAuth.CodeTTL != time.Minute {
		t.Errorf("oauth: %+v", cfg.OAuth)
	}
	if !cfg.TLSEnabled() || cfg.TLS.ReloadInterval != time.Minute {
		t.Errorf("tls: %+v", cfg.TLS)
	}
	if len(cfg.Secrets.Keys) != 2 || cfg.Secrets.Keys[0][0] != 1 || cfg.Secrets.Keys[1][0] != 2 {
		t.Errorf("keys order wrong")
	}
	u := cfg.Upstreams[0]
	if u.Title != "Alpha" || !u.Credentials[0].Secret || !u.Credentials[1].Optional {
		t.Errorf("upstream: %+v", u)
	}
}

func TestSecretsRedacted(t *testing.T) {
	cfg, err := Parse([]byte(base()), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg.Secrets)} {
		if strings.Contains(s, key1) {
			t.Errorf("key leaked: %s", s)
		}
	}
}

func TestValidation(t *testing.T) {
	keys := "secrets: { token_keys: [\"" + key1 + "\"] }\n"
	pub := "public_url: https://mcp.example.com\n"
	up := func(name, p, url, creds string) string {
		return fmt.Sprintf("  - name: %s\n    path: %s\n    url: %s\n    credentials: %s\n", name, p, url, creds)
	}
	okCreds := "[{header: X-A}]"
	okUp := "upstreams:\n" + up("tn", "/tn", "https://u.example/mcp", okCreds)

	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"missing public_url", keys + okUp, "public_url: required"},
		{"public_url relative", "public_url: mcp.example.com\n" + keys + okUp, "public_url"},
		{"public_url ftp", "public_url: ftp://x\n" + keys + okUp, "public_url"},
		{"public_url query", "public_url: https://x?a=b\n" + keys + okUp, "must not contain a query"},
		{"public_url path", "public_url: https://x.example/mcp-proxy\n" + keys + okUp, "public_url: must be an origin without a path"},
		{"public_url path slash", "public_url: https://x.example/a/b/\n" + keys + okUp, "public_url: must be an origin without a path"},
		{"public_url fragment", "public_url: https://x#f\n" + keys + okUp, "must not contain a fragment"},
		{"bad log level", pub + "log: {level: trace}\n" + keys + okUp, "log.level"},
		{"bad log format", pub + "log: {format: xml}\n" + keys + okUp, "log.format"},
		{"negative ttl", pub + "oauth: {code_ttl: -1m}\n" + keys + okUp, "oauth.code_ttl"},
		{"bad redirect", pub + "oauth: {allowed_redirect_uris: [\"/cb\"]}\n" + keys + okUp, "oauth.allowed_redirect_uris[0]"},
		{"no keys", pub + okUp, "got neither"},
		{"both key sources", pub + "secrets: {token_keys: [\"" + key1 + "\"], token_keys_file: x}\n" + okUp, "got both"},
		{"bad base64", pub + "secrets: {token_keys: [\"!!!\"]}\n" + okUp, "secrets.token_keys[0]: not valid"},
		{"short key", pub + "secrets: {token_keys: [\"" + base64.StdEncoding.EncodeToString([]byte("short")) + "\"]}\n" + okUp, "decoded length is 5"},
		{"no upstreams", pub + keys, "upstreams: at least one"},
		{"name missing", pub + keys + "upstreams:\n" + up(`""`, "/a", "https://u", okCreds), "upstreams[0].name: required"},
		{"name uppercase", pub + keys + "upstreams:\n" + up("TN", "/a", "https://u", okCreds), "upstreams[0].name"},
		{"name duplicate", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", okCreds) + up("a", "/b", "https://u", okCreds), "upstreams[1].name"},
		{"path missing", pub + keys + "upstreams:\n" + up("a", `""`, "https://u", okCreds), "upstreams[0].path: required"},
		{"path no slash", pub + keys + "upstreams:\n" + up("a", "a", "https://u", okCreds), "must start with '/'"},
		{"path trailing slash", pub + keys + "upstreams:\n" + up("a", "/a/", "https://u", okCreds), "must not end with '/'"},
		{"path duplicate", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", okCreds) + up("b", "/a", "https://u", okCreds), "upstreams[1].path"},
		{"path reserved oauth", pub + keys + "upstreams:\n" + up("a", "/oauth", "https://u", okCreds), "reserved path /oauth"},
		{"path under oauth", pub + keys + "upstreams:\n" + up("a", "/oauth/x", "https://u", okCreds), "reserved path /oauth"},
		{"path well-known", pub + keys + "upstreams:\n" + up("a", "/.well-known/x", "https://u", okCreds), "reserved path /.well-known"},
		{"path healthz", pub + keys + "upstreams:\n" + up("a", "/healthz", "https://u", okCreds), "reserved path /healthz"},
		{"path prefix of other", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", okCreds) + up("b", "/a/b", "https://u", okCreds), "overlaps"},
		{"path unclean", pub + keys + "upstreams:\n" + up("a", "/a//b", "https://u", okCreds), "literal segments"},
		{"path wildcard var", pub + keys + "upstreams:\n" + up("a", `"/a/{x}"`, "https://u", okCreds), "literal segments"},
		{"path wildcard star", pub + keys + "upstreams:\n" + up("a", `"/a/*"`, "https://u", okCreds), "literal segments"},
		{"path colon", pub + keys + "upstreams:\n" + up("a", `"/a:b"`, "https://u", okCreds), "literal segments"},
		{"path non-ascii", pub + keys + "upstreams:\n" + up("a", `"/é"`, "https://u", okCreds), "literal segments"},
		{"path dotdot", pub + keys + "upstreams:\n" + up("a", `"/a/../b"`, "https://u", okCreds), "literal segments"},
		{"path dot", pub + keys + "upstreams:\n" + up("a", `"/a/./b"`, "https://u", okCreds), "literal segments"},
		{"path dotdot only", pub + keys + "upstreams:\n" + up("a", `"/.."`, "https://u", okCreds), "literal segments"},
		{"public_url userinfo", "public_url: https://u:p@x.example\n" + keys + okUp, "public_url: must not contain userinfo"},
		{"upstream url userinfo", pub + keys + "upstreams:\n" + up("a", "/a", "https://u:p@x.example", okCreds), "upstreams[0].url: must not contain userinfo"},
		{"listen no port", pub + "listen: localhost\n" + keys + okUp, "listen"},
		{"listen big port", pub + "listen: \"127.0.0.1:70000\"\n" + keys + okUp, "port"},
		{"listen text port", pub + "listen: \"127.0.0.1:http\"\n" + keys + okUp, "port"},
		{"header Content-Type", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[{header: content-type}]"), "is not allowed"},
		{"header Mcp-Session-Id", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[{header: Mcp-Session-Id}]"), "is not allowed"},
		{"header Proxy-Authorization", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[{header: Proxy-Authorization}]"), "is not allowed"},
		{"header X-Forwarded-Host", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[{header: X-Forwarded-Host}]"), "is not allowed"},
		{"header Forwarded", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[{header: Forwarded}]"), "is not allowed"},
		{"header X-Real-IP", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[{header: X-Real-IP}]"), "is not allowed"},
		{"header TE", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[{header: TE}]"), "is not allowed"},
		{"duplicate token_keys", pub + "secrets: {token_keys: [\"" + key1 + "\", \"" + key2 + "\", \"" + key1 + "\"]}\n" + okUp, "secrets.token_keys[2]: duplicates secrets.token_keys[0]"},
		{"duplicate redirect", pub + "oauth: {allowed_redirect_uris: [\"https://a/cb\", \"https://a/cb\"]}\n" + keys + okUp, "allowed_redirect_uris[1]: duplicates [0]"},
		{"multi document", base() + "---\nlisten: x\n", "multiple documents"},
		{"url missing", pub + keys + "upstreams:\n" + up("a", "/a", `""`, okCreds), "upstreams[0].url: required"},
		{"url relative", pub + keys + "upstreams:\n" + up("a", "/a", "/mcp", okCreds), "upstreams[0].url"},
		{"no credentials", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[]"), "at least one non-optional"},
		{"only optional creds", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[{header: X-A, optional: true}]"), "at least one non-optional"},
		{"header missing", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[{label: x}]"), "credentials[0].header: required"},
		{"header invalid", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[{header: \"X A\"}]"), "not a valid HTTP header"},
		{"header Authorization", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[{header: authorization}]"), "is not allowed"},
		{"header Cookie", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[{header: Cookie}]"), "is not allowed"},
		{"header Host", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[{header: HOST}]"), "is not allowed"},
		{"header duplicate ci", pub + keys + "upstreams:\n" + up("a", "/a", "https://u", "[{header: X-A}, {header: x-a}]"), "credentials[1].header"},
		{"tls cert only", pub + keys + okUp + "tls: {cert_file: c.pem}\n", "set together"},
		{"tls key only", pub + keys + okUp + "tls: {key_file: k.pem}\n", "set together"},
		{"tls negative reload", pub + keys + okUp + "tls: {reload_interval: -1s}\n", "tls.reload_interval"},
		{"unknown field", pub + keys + okUp + "bogus: 1\n", "bogus"},
		{"unknown nested field", pub + "secrets: {token_keys: [\"" + key1 + "\"], nope: 1}\n" + okUp, "nope"},
		{"bad duration", pub + "oauth: {code_ttl: soon}\n" + keys + okUp, "into time.Duration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml), ".")
			if err == nil {
				t.Fatalf("expected error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestValidationReportsAllProblems(t *testing.T) {
	_, err := Parse([]byte("log: {level: x}\nupstreams: [{name: A}]\n"), ".")
	if err == nil {
		t.Fatal("expected error")
	}
	for _, w := range []string{"public_url", "log.level", "upstreams[0].name", "upstreams[0].path", "upstreams[0].url", "got neither"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("missing %q in %v", w, err)
		}
	}
}

func TestEmptyDocument(t *testing.T) {
	if _, err := Parse(nil, "."); err == nil {
		t.Fatal("expected validation error for empty config")
	}
}

func TestKeysFile(t *testing.T) {
	dir := t.TempDir()
	keysPath := filepath.Join(dir, "keys")
	content := "# primary\n" + key1 + "\n\n  # old\n  " + key2 + "  \n"
	if err := os.WriteFile(keysPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	y := "public_url: https://mcp.example.com\nsecrets: {token_keys_file: keys}\n" + upstreamYAML
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath) // relative path resolves against config dir
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Secrets.Keys) != 2 || cfg.Secrets.Keys[0][0] != 1 || cfg.Secrets.Keys[1][0] != 2 {
		t.Fatalf("keys: %d", len(cfg.Secrets.Keys))
	}

	// Absolute path works regardless of baseDir.
	y = strings.Replace(y, "keys}", keysPath+"}", 1)
	if _, err := Parse([]byte(y), "/nonexistent"); err != nil {
		t.Fatal(err)
	}
}

func TestKeysFileErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("empty", "# nothing\n\n")
	write("bad", key1+"\nnot-base64!\n")
	write("dup", key1+"\n"+key1+"\n")
	tests := []struct{ file, want string }{
		{"missing", "reading keys file"},
		{"empty", "contains no keys"},
		{"bad", "token_keys_file line 2"},
		{"dup", "line 2: duplicates secrets.token_keys_file line 1"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			y := "public_url: https://mcp.example.com\nsecrets: {token_keys_file: " + tt.file + "}\n" + upstreamYAML
			_, err := Parse([]byte(y), dir)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error")
	}
}

func TestExampleConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "deploy", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Upstreams) != 1 || cfg.Upstreams[0].Name != "tn" || len(cfg.Upstreams[0].Credentials) != 3 {
		t.Errorf("unexpected upstreams: %+v", cfg.Upstreams)
	}
	if cfg.TLSEnabled() {
		t.Error("tls should be disabled in example")
	}
}

func TestSlogLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{
		"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError, "": slog.LevelInfo,
	} {
		if got := (Log{Level: in}).SlogLevel(); got != want {
			t.Errorf("%q: got %v want %v", in, got, want)
		}
	}
}
