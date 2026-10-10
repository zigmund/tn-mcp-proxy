package config

import (
	"strings"
	"testing"
)

// urlCase builds a config with the given value injected into one URL field.
func urlCase(field, v string) string {
	pub, up, redir := "https://mcp.example.com", "https://tradernet.com/mcp/tn", "https://claude.ai/cb"
	switch field {
	case "public_url":
		pub = v
	case "url":
		up = v
	case "redirect":
		redir = v
	}
	return "public_url: \"" + pub + "\"\n" +
		"secrets: { token_keys: [\"" + key1 + "\"] }\n" +
		"oauth: { allowed_redirect_uris: [\"" + redir + "\"] }\n" +
		"upstreams:\n  - name: tn\n    path: /tn\n    url: \"" + up + "\"\n    credentials: [{header: X-A}]\n"
}

func TestURLErrorsNeverEchoInput(t *testing.T) {
	wants := map[string]string{
		"public_url": "public_url: must be an absolute http(s) URL",
		"url":        "upstreams[0].url: must be an absolute http(s) URL",
		"redirect":   "oauth.allowed_redirect_uris[0]: must be an absolute http(s) URL",
	}
	inputs := []string{
		"user:pw@host:80/x",             // parses as scheme "user"
		"https://u:pw@host/x",           // userinfo
		"https://host/x?token=pw",       // query (rejected for public_url only)
		"https://host/x#pw",             // fragment
		"https://host:pw/x",             // bad port
		"https://host:99999/pw",         // port range
		"https://ho st/pw",              // invalid host
		"http://%zz-pw",                 // parse failure
		"https:///pw",                   // no host
		"ftp://host/pw",                 // scheme
		"/relative/pw",                  // not absolute
		"https://host:/pw",              // empty port
		"https://[::1]:0/pw",            // zero port
		"https://u:pw@[::1]:99999/path", // several problems
	}
	for field, want := range wants {
		for _, in := range inputs {
			_, err := Parse([]byte(urlCase(field, in)), ".")
			if err == nil {
				continue // some inputs are valid for some fields (e.g. query)
			}
			if strings.Contains(err.Error(), "pw") {
				t.Errorf("%s %q: error echoes input: %v", field, in, err)
			}
		}
		_, err := Parse([]byte(urlCase(field, "user:pw@host:80/x")), ".")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", field, err, want)
		}
	}
}

func TestURLPorts(t *testing.T) {
	tests := []struct {
		in string
		ok bool
	}{
		{"https://h:1/x", true},
		{"https://h:65535/x", true},
		{"https://[::1]:8443/x", true},
		{"https://h/x", true},
		{"https://h:/x", false},
		{"https://h:0/x", false},
		{"https://h:65536/x", false},
		{"https://h:99999999999/x", false},
		{"https://[::1]:/x", false},
	}
	for _, field := range []string{"public_url", "url", "redirect"} {
		for _, tt := range tests {
			in := tt.in
			if field == "public_url" {
				in = strings.TrimSuffix(in, "/x") // public_url must not have a path
			}
			_, err := Parse([]byte(urlCase(field, in)), ".")
			if (err == nil) != tt.ok {
				t.Errorf("%s %q: ok=%v err=%v", field, tt.in, tt.ok, err)
			}
			if err != nil && strings.Contains(err.Error(), tt.in) {
				t.Errorf("%s %q: error echoes input", field, tt.in)
			}
		}
	}
}

func TestValidateDoesNotMutate(t *testing.T) {
	cfg := &Config{PublicURL: "HTTPS://Mcp.Example.com:443/"}
	_ = cfg.validate()
	if cfg.PublicURL != "HTTPS://Mcp.Example.com:443/" {
		t.Fatalf("validate mutated PublicURL: %s", cfg.PublicURL)
	}
}
