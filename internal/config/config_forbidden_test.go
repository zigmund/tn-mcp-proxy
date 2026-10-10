package config

import (
	"strings"
	"testing"
)

func forbiddenYAML(extra string) string {
	return "public_url: https://mcp.example.com/\nsecrets:\n  token_keys: [\"" + key1 + "\"]\n" +
		"upstreams:\n  - name: tn\n    path: /tn/mcp\n    url: https://tradernet.com/mcp/tn\n" +
		"    credentials:\n      - { header: X-TN-API-Key }\n" + extra
}

func TestAllowedValuesRequireValidate(t *testing.T) {
	y := "public_url: https://mcp.example.com/\nsecrets:\n  token_keys: [\"" + key1 + "\"]\n" +
		"upstreams:\n  - name: tn\n    path: /tn/mcp\n    url: https://tradernet.com/mcp/tn\n" +
		"    credentials:\n      - { header: X-TN-API-Key, allowed_values: [ \"REPLACE_WITH_YOUR_API_KEY\" ] }\n"
	_, err := Parse([]byte(y), ".")
	if err == nil || !strings.Contains(err.Error(), "allowed_values requires validate") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "REPLACE_WITH_YOUR_API_KEY") {
		t.Errorf("error leaks a value: %v", err)
	}
	if _, err := Parse([]byte(y+"    validate: { tool: get_auth_info }\n"), "."); err != nil {
		t.Fatalf("with validate: %v", err)
	}
}

func TestForbiddenArgumentsValidation(t *testing.T) {
	tests := []struct {
		name, extra, wantErr string
	}{
		{"ok", "    forbidden_arguments: [api_key, api_secret]\n", ""},
		{"unset", "", ""},
		{"empty list", "    forbidden_arguments: []\n", ""},
		{"empty name", "    forbidden_arguments: [api_key, \"\"]\n", "forbidden_arguments[1]: must not be empty"},
		{"duplicate", "    forbidden_arguments: [api_key, api_secret, api_key]\n", "forbidden_arguments[2]: duplicates forbidden_arguments[0]"},
		{"leading space", "    forbidden_arguments: [\" api_key\"]\n", "whitespace"},
		{"control char", "    forbidden_arguments: [\"api\\u0001key\"]\n", "control characters"},
		{"duplicate case", "    forbidden_arguments: [api_key, API_KEY]\n", "duplicates"},
		{"too long", "    forbidden_arguments: [" + strings.Repeat("a", MaxForbiddenArgumentLen+1) + "]\n", "longer than"},
		{"too many", "    forbidden_arguments: [" + manyNames(MaxForbiddenArguments+1) + "]\n", "at most"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(forbiddenYAML(tt.extra)), ".")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func manyNames(n int) string {
	var b strings.Builder
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("n")
		b.WriteString(strings.Repeat("x", i)) // distinct names
	}
	return b.String()
}
