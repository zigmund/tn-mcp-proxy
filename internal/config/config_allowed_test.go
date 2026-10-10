package config

import (
	"strings"
	"testing"
)

func allowedYAML(cred string) string {
	return "public_url: https://mcp.example.com/\nsecrets:\n  token_keys: [\"" + key1 + "\"]\n" +
		"upstreams:\n  - name: tn\n    path: /tn/mcp\n    url: https://tradernet.com/mcp/tn\n    credentials:\n      - " + cred + "\n    validate: { tool: get_auth_info }\n"
}

func TestAllowedValuesValidation(t *testing.T) {
	tests := []struct {
		name, cred, wantErr string
	}{
		{"ok", `{ header: X-TN-API-Key, allowed_values: [ "REPLACE_WITH_YOUR_API_KEY", " other-key " ] }`, ""},
		{"unset", `{ header: X-TN-API-Key }`, ""},
		{"empty list", `{ header: X-TN-API-Key, allowed_values: [] }`, ""},
		{"secret", `{ header: X-TN-API-Key, secret: true, allowed_values: [ "REPLACE_WITH_YOUR_API_KEY" ] }`, "secret credential"},
		{"empty value", `{ header: X-TN-API-Key, allowed_values: [ "" ] }`, "allowed_values[0]: must not be empty"},
		{"blank value", `{ header: X-TN-API-Key, allowed_values: [ "a1", "   " ] }`, "allowed_values[1]: must not be empty"},
		{"duplicate", `{ header: X-TN-API-Key, allowed_values: [ "dupvalue1", "dupvalue1" ] }`, "allowed_values[1]: duplicates allowed_values[0]"},
		{"duplicate after trim", `{ header: X-TN-API-Key, allowed_values: [ "dupvalue1", " dupvalue1 " ] }`, "duplicates"},
		{"LF", `{ header: X-TN-API-Key, allowed_values: [ "a\nb" ] }`, "allowed_values[0]: contains control"},
		{"CR", `{ header: X-TN-API-Key, allowed_values: [ "a\rb" ] }`, "allowed_values[0]: contains control"},
		{"leading LF", `{ header: X-TN-API-Key, allowed_values: [ "\nab" ] }`, "control"},
		{"duplicate a and spaced a", `{ header: X-TN-API-Key, allowed_values: [ "a", " a " ] }`, "allowed_values[1]: duplicates allowed_values[0]"},
		{"trailing LF", `{ header: X-TN-API-Key, allowed_values: [ "ab\n" ] }`, "control"},
		{"too long", `{ header: X-TN-API-Key, allowed_values: [ "` + strings.Repeat("a", MaxCredentialValueLen+1) + `" ] }`, "longer than"},
		{"max length", `{ header: X-TN-API-Key, allowed_values: [ "` + strings.Repeat("a", MaxCredentialValueLen) + `" ] }`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(allowedYAML(tt.cred)), ".")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			for _, leak := range []string{"REPLACE_WITH_YOUR_API_KEY", "dupvalue1", "a\nb", "a\rb"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("error leaks a value %q: %v", leak, err)
				}
			}
		})
	}
}

func TestCredsAllowed(t *testing.T) {
	up := Upstream{Credentials: []Credential{
		{Header: "x-tn-api-key", AllowedValues: []string{"key-a", " key-b "}},
		{Header: "X-TN-User", AllowedValues: []string{"alice"}},
		{Header: "X-TN-Free"},
	}}
	if !up.HasAllowList() || (Upstream{Credentials: []Credential{{Header: "X-A"}}}).HasAllowList() {
		t.Fatal("HasAllowList wrong")
	}
	tests := []struct {
		name  string
		creds map[string]string
		want  bool
	}{
		{"all match", map[string]string{"X-Tn-Api-Key": "key-a", "X-Tn-User": "alice"}, true},
		{"second entry, trimmed", map[string]string{"X-Tn-Api-Key": " key-b", "X-Tn-User": "alice", "X-Tn-Free": "x"}, true},
		{"foreign key", map[string]string{"X-Tn-Api-Key": "key-c", "X-Tn-User": "alice"}, false},
		{"one list fails", map[string]string{"X-Tn-Api-Key": "key-a", "X-Tn-User": "bob"}, false},
		{"missing", map[string]string{"X-Tn-Api-Key": "key-a"}, false},
		{"case sensitive", map[string]string{"X-Tn-Api-Key": "KEY-A", "X-Tn-User": "alice"}, false},
		{"prefix", map[string]string{"X-Tn-Api-Key": "key-", "X-Tn-User": "alice"}, false},
	}
	for _, tt := range tests {
		if got := up.CredsAllowed(tt.creds); got != tt.want {
			t.Errorf("%s: CredsAllowed = %v, want %v", tt.name, got, tt.want)
		}
	}
	if !(Upstream{Credentials: []Credential{{Header: "X-A"}}}).CredsAllowed(nil) {
		t.Error("no list must allow anything")
	}
}
