package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func auditYAML(audit, creds, log string) string {
	return "public_url: https://mcp.example.com/\nsecrets:\n  token_keys: [\"" + key1 + "\"]\n" + audit + log +
		"upstreams:\n  - name: tn\n    path: /tn/mcp\n    url: https://tradernet.com/mcp/tn\n    credentials:\n" + creds
}

const auditCreds = "      - { header: X-TN-API-Key, label: API key, audit: true }\n" +
	"      - { header: X-TN-API-Secret, label: API secret, secret: true }\n" +
	"      - { header: X-TN-SID, label: SID, optional: true }\n"

func TestAuditValidation(t *testing.T) {
	tests := []struct {
		name, audit, creds, log, wantErr string
	}{
		{"enabled", "audit: { enabled: true, retention: \"12 months\" }\n", auditCreds, "", ""},
		{"disabled needs nothing", "", auditCreds, "", ""},
		{"disabled with retention", "audit: { retention: \"1 year\" }\n", auditCreds, "", ""},
		{"retention required", "audit: { enabled: true }\n", auditCreds, "", "audit.retention: required"},
		{"retention blank", "audit: { enabled: true, retention: \"   \" }\n", auditCreds, "", "audit.retention: required"},
		{"max length", "audit: { enabled: true, retention: \"" + strings.Repeat("я", MaxAuditRetentionLen) + "\" }\n", auditCreds, "", ""},
		{"too long", "audit: { enabled: true, retention: \"" + strings.Repeat("a", MaxAuditRetentionLen+1) + "\" }\n", auditCreds, "", "longer than 64"},
		{"newline", "audit: { enabled: true, retention: \"a\\nb\" }\n", auditCreds, "", "printable"},
		{"tab", "audit: { enabled: true, retention: \"a\\tb\" }\n", auditCreds, "", "printable"},
		{"control", "audit: { enabled: true, retention: \"a\\u0007b\" }\n", auditCreds, "", "printable"},
		{"line separator", "audit: { enabled: true, retention: \"a\\u2028b\" }\n", auditCreds, "", "printable"},
		{"too long when disabled", "audit: { retention: \"" + strings.Repeat("a", 65) + "\" }\n", auditCreds, "", "longer than 64"},
		{"audit with secret", "audit: { enabled: true, retention: x }\n",
			"      - { header: X-TN-API-Key, secret: true, audit: true }\n", "", "credentials[0].audit: not allowed together with secret"},
		{"audit with secret, audit off", "", "      - { header: X-TN-API-Key, secret: true, audit: true }\n", "", "credentials[0].audit: not allowed together with secret"},
		{"log level warn", "audit: { enabled: true, retention: x }\n", auditCreds, "log: { level: warn }\n", "audit.enabled: needs log.level"},
		{"log level debug", "audit: { enabled: true, retention: x }\n", auditCreds, "log: { level: debug }\n", ""},
		{"unknown key", "audit: { enabled: true, retention: x, path: /x }\n", auditCreds, "", "field path not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(auditYAML(tt.audit, tt.creds, tt.log)), ".")
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestAuditAccessors(t *testing.T) {
	cfg, err := Parse([]byte(auditYAML("audit: { enabled: true, retention: \"  12 months \" }\n", auditCreds, "")), ".")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Audit.Enabled || cfg.Audit.Retention != "12 months" {
		t.Errorf("Audit = %+v", cfg.Audit)
	}
	up := cfg.Upstreams[0]
	if got := labelTexts(up.AuditedLabels("en")); !slices.Equal(got, []string{"API key"}) {
		t.Errorf("AuditedLabels = %v", got)
	}
	if got := up.AuditedCredentials(); len(got) != 1 || got[0].Header != "X-TN-API-Key" {
		t.Errorf("AuditedCredentials = %v", got)
	}
	// Label defaults to the header; a secret is never audited even if built by hand.
	u := Upstream{Credentials: []Credential{{Header: "X-A", Audit: true}, {Header: "X-B", Audit: true, Secret: true}}}
	if got := labelTexts(u.AuditedLabels("en")); !slices.Equal(got, []string{"X-A"}) {
		t.Errorf("AuditedLabels(hand-built) = %v", got)
	}
}

// The audit snippet of the example config must stay valid when uncommented.
func TestExampleConfigAuditBlock(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, r := range [][2]string{
		{"token_keys_file: /run/credentials/tn-mcp-proxy.service/keys", "token_keys_file: keys"},
		{"# audit:\n#   enabled: true\n#   retention: \"12 months\"\n", "audit:\n  enabled: true\n  retention: \"12 months\"\n"},
		{"      - { header: X-TN-API-Key,    label: API key }\n", "      - { header: X-TN-API-Key, label: API key, audit: true }\n"},
	} {
		if !strings.Contains(s, r[0]) {
			t.Fatalf("example config lacks %q; update this test", r[0])
		}
		s = strings.Replace(s, r[0], r[1], 1)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keys"), []byte(key1+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]byte(s), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Audit.Enabled || cfg.Audit.Retention != "12 months" {
		t.Errorf("Audit = %+v", cfg.Audit)
	}
	if got := labelTexts(cfg.Upstreams[0].AuditedLabels("en")); !slices.Equal(got, []string{"API key"}) {
		t.Errorf("AuditedLabels = %v", got)
	}
}

// labelTexts is the text of each label, for assertions.
func labelTexts(lts []LangText) []string {
	out := make([]string, len(lts))
	for i, lt := range lts {
		out[i] = lt.Text
	}
	return out
}
