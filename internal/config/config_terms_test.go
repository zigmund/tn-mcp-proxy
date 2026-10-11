package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeFiles writes name -> content into a fresh dir and returns it.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func termsYAML(body string) string {
	return pageYAML("oauth:\n  page:\n" + body)
}

func TestTermsValidation(t *testing.T) {
	long := strings.Repeat("a", MaxTermsTextLen)
	const ref = "    terms_file: terms.txt\n"
	tests := []struct {
		name    string
		content *string
		yaml    string
		wantErr string
	}{
		{"ok", ptr("Free.\n\nAs is."), ref, ""},
		{"absent", nil, "    contact: \"mailto:ops@example.org\"\n", ""},
		{"blank path is off", nil, "    terms_file: \"  \"\n", ""},
		{"old text key", ptr("x"), "    terms:\n      text: { en: terms.txt }\n", "field terms not found"},
		{"missing file", nil, ref, "oauth.page.terms_file: reading file"},
		{"empty file", ptr(" \n\n"), ref, "file must not be empty"},
		{"size max", ptr(long), ref, ""},
		{"size cap", ptr(long + "a"), ref, "file is longer than 32768 bytes"},
		{"control char", ptr("a\x07b"), ref, "without control or format"},
		{"bare CR", ptr("a\rb"), ref, "without control or format"},
		{"bidi", ptr("a\u202eb"), ref, "without control or format"},
		{"invalid utf8", ptr("a\xffb"), ref, "valid UTF-8"},
		{"tab newline crlf ok", ptr("a\tb\r\n\r\nc"), ref, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{}
			if tt.content != nil {
				files["terms.txt"] = *tt.content
			}
			_, err := Parse([]byte(termsYAML(tt.yaml)), writeFiles(t, files))
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func ptr(s string) *string { return &s }

func TestTermsErrorDoesNotEchoContent(t *testing.T) {
	dir := writeFiles(t, map[string]string{"terms.txt": "sekret-clause \x07"})
	_, err := Parse([]byte(termsYAML("    terms_file: terms.txt\n")), dir)
	if err == nil || strings.Contains(err.Error(), "sekret-clause") {
		t.Fatalf("err = %v", err)
	}
}

func TestTermsLoad(t *testing.T) {
	dir := writeFiles(t, map[string]string{"terms.txt": "One.\r\n\r\nTwo.\r\n"})
	cfg, err := Parse([]byte(termsYAML("    terms_file: terms.txt\n")), dir)
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.OAuth.Page
	if !p.TermsEnabled() {
		t.Fatal("terms not enabled")
	}
	if want := filepath.Join(dir, "terms.txt"); p.TermsFile != want {
		t.Errorf("path = %q, want %q (relative to the config dir)", p.TermsFile, want)
	}
	if got, want := p.TermsParagraphs(), []string{"One.", "Two."}; !reflect.DeepEqual(got, want) {
		t.Errorf("paragraphs = %q, want %q", got, want)
	}

	// An absolute path is kept as is.
	abs := filepath.Join(dir, "terms.txt")
	cfg, err = Parse([]byte(termsYAML("    terms_file: "+abs+"\n")), t.TempDir())
	if err != nil || cfg.OAuth.Page.TermsFile != abs {
		t.Errorf("absolute: %q, %v", cfg.OAuth.Page.TermsFile, err)
	}

	if (Page{}).TermsEnabled() || len((Page{}).TermsParagraphs()) != 0 {
		t.Error("empty page must have no terms")
	}
}

func credsYAML(creds string) string {
	return "public_url: https://mcp.example.com/\nsecrets:\n  token_keys: [\"" + key1 + "\"]\n" +
		"upstreams:\n  - name: tn\n    path: /tn/mcp\n    url: https://tradernet.com/mcp/tn\n    credentials:\n" + creds
}

func TestLabelValidation(t *testing.T) {
	tests := []struct {
		name, cred, wantErr string
	}{
		{"ok", "      - { header: X-A, label: API key }\n", ""},
		{"no label", "      - { header: X-A }\n", ""},
		{"labels key rejected", "      - { header: X-A, label: A, labels: { en: A } }\n", "field labels not found"},
		{"too long", "      - { header: X-A, label: " + strings.Repeat("a", MaxCredentialLabelLen+1) + " }\n", "longer than 128 characters"},
		{"max", "      - { header: X-A, label: " + strings.Repeat("я", MaxCredentialLabelLen) + " }\n", ""},
		{"control", "      - { header: X-A, label: \"a\\u0007\" }\n", "printable text without control or format"},
		{"newline", "      - { header: X-A, label: \"a\\nb\" }\n", "printable text without control or format"},
		{"bidi", "      - { header: X-A, label: \"a\\u202eb\" }\n", "printable text without control or format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(credsYAML(tt.cred)), ".")
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLabelDefaults(t *testing.T) {
	cfg, err := Parse([]byte(credsYAML("      - { header: X-A, label: API key, audit: true }\n      - { header: X-B }\n")), ".")
	if err != nil {
		t.Fatal(err)
	}
	a, b := cfg.Upstreams[0].Credentials[0], cfg.Upstreams[0].Credentials[1]
	if a.Label != "API key" || b.Label != "X-B" {
		t.Errorf("labels = %q, %q; want the label, else the header", a.Label, b.Label)
	}
	if got := (Credential{Header: "X-C"}).DisplayLabel(); got != "X-C" {
		t.Errorf("hand-built label = %q", got)
	}
	up := Upstream{Credentials: []Credential{{Header: "X-A", Label: "A", Audit: true}, {Header: "X-B", Label: "B"}}}
	if got := up.AuditedLabels(); !reflect.DeepEqual(got, []string{"A"}) {
		t.Errorf("AuditedLabels = %q", got)
	}
	if got := up.NeverLoggedLabels(); !reflect.DeepEqual(got, []string{"B"}) {
		t.Errorf("NeverLoggedLabels = %q", got)
	}
}

// A directory (or a FIFO, device, ...) is refused before it is opened.
func TestTermsNotRegularFile(t *testing.T) {
	dir := writeFiles(t, nil)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub", filepath.Join(dir, "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	for _, p := range []string{"sub", "link"} {
		_, err := Parse([]byte(termsYAML("    terms_file: "+p+"\n")), dir)
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("%s: err = %v", p, err)
		}
	}
}
