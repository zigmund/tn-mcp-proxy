package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// transportCfg is urlCase plus an optional extra top-level snippet.
func transportCfg(field, v, extra string) string { return extra + urlCase(field, v) }

func TestHTTPSRequired(t *testing.T) {
	fields := map[string]string{
		"public_url": "public_url",
		"url":        "upstreams[0].url",
		"redirect":   "oauth.allowed_redirect_uris[0]",
	}
	const msg = "must use https (http is allowed only for loopback hosts or with allow_insecure_http)"
	for field, path := range fields {
		for _, in := range []string{"http://mcp.example.com", "http://192.0.2.1", "http://[2001:db8::1]:80", "HTTP://mcp.example.com", "http://localhost.example.com"} {
			_, err := Parse([]byte(transportCfg(field, in, "")), ".")
			if err == nil || !strings.Contains(err.Error(), path+": "+msg) {
				t.Errorf("%s %s: err = %v", field, in, err)
			}
			if err != nil && strings.Contains(err.Error(), "mcp.example.com") {
				t.Errorf("%s %s: error echoes the URL: %v", field, in, err)
			}
			// The escape hatch accepts it.
			if _, err := Parse([]byte(transportCfg(field, in, "allow_insecure_http: true\n")), "."); err != nil {
				t.Errorf("%s %s with allow_insecure_http: %v", field, in, err)
			}
		}
		for _, in := range []string{"http://localhost", "http://LOCALHOST:8080", "http://127.0.0.1:9", "http://127.9.9.9", "http://[::1]:8080"} {
			if _, err := Parse([]byte(transportCfg(field, in, "")), "."); err != nil {
				t.Errorf("%s %s: loopback should be allowed: %v", field, in, err)
			}
		}
	}
}

func TestInsecureKeyRejected(t *testing.T) {
	seq := func(start, step byte) []byte {
		b := make([]byte, KeySize)
		for i := range b {
			b[i] = start + step*byte(i)
		}
		return b
	}
	good := base64.StdEncoding.DecodeString
	random, _ := good(testKey("random"))
	ex, _ := good(exampleKey)
	cases := []struct {
		name string
		key  []byte
		bad  bool
	}{
		{"example", ex, true},
		{"zero", make([]byte, KeySize), true},
		{"same byte", bytes.Repeat([]byte{0x41}, KeySize), true},
		{"incrementing", seq(0, 1), true},
		{"incrementing from 7", seq(7, 1), true},
		{"decrementing", seq(31, 255), true},
		{"random", random, false},
		{"almost incrementing", append(seq(0, 1)[:31], 0x99), false},
	}
	for _, c := range cases {
		enc := base64.StdEncoding.EncodeToString(c.key)
		y := "public_url: https://mcp.example.com\nsecrets: { token_keys: [\"" + enc + "\"] }\n" + upstreamYAML
		_, err := Parse([]byte(y), ".")
		switch {
		case c.bad && (err == nil || !strings.Contains(err.Error(), "secrets.token_keys[0]: is a known insecure key")):
			t.Errorf("%s: err = %v", c.name, err)
		case !c.bad && err != nil:
			t.Errorf("%s: %v", c.name, err)
		}
		if err != nil && strings.Contains(err.Error(), enc) {
			t.Errorf("%s: error prints the key", c.name)
		}
	}
}
