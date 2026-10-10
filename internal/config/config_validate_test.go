package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// validateCase appends a validate block (indented under the upstream) to base().
func validateCase(block string) string {
	return base() + "    validate:\n" + block
}

func TestValidateParsed(t *testing.T) {
	cfg, err := Parse([]byte(validateCase(`
      tool: get_auth_info
      arguments: {limit: 3, nested: {a: [1, "x", {b: true}]}}
      timeout: 5s
`)), ".")
	if err != nil {
		t.Fatal(err)
	}
	v := cfg.Upstreams[0].Validate
	if v == nil || v.Tool != "get_auth_info" || v.Timeout != 5*time.Second {
		t.Fatalf("validate = %+v", v)
	}
	b, err := json.Marshal(v.Arguments)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"limit":3,"nested":{"a":[1,"x",{"b":true}]}}`; string(b) != want {
		t.Errorf("arguments = %s, want %s", b, want)
	}
}

func TestValidateDefaults(t *testing.T) {
	cfg, err := Parse([]byte(validateCase("      tool: ping\n")), ".")
	if err != nil {
		t.Fatal(err)
	}
	if v := cfg.Upstreams[0].Validate; v.Timeout != DefaultValidateTimeout || v.Arguments != nil {
		t.Errorf("validate = %+v, want default timeout and no arguments", v)
	}
	cfg, err = Parse([]byte(base()), ".")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstreams[0].Validate != nil {
		t.Error("validate must stay nil when absent")
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name, block, want string
	}{
		{"missing tool", "      timeout: 5s\n", "upstreams[0].validate.tool: required"},
		{"empty tool", "      tool: \"\"\n", "upstreams[0].validate.tool: required"},
		{"bad tool chars", "      tool: \"a b\"\n", `upstreams[0].validate.tool: "a b" must match`},
		{"tool with newline", "      tool: \"a\\nb\"\n", "upstreams[0].validate.tool:"},
		{"tool too long", "      tool: " + strings.Repeat("a", 129) + "\n", "upstreams[0].validate.tool:"},
		{"negative timeout", "      tool: t\n      timeout: -1s\n", "upstreams[0].validate.timeout: must be between"},
		{"timeout too large", "      tool: t\n      timeout: 61s\n", "upstreams[0].validate.timeout: must be between"},
		{"non-marshalable argument", "      tool: t\n      arguments: {a: {b: .nan}}\n", "upstreams[0].validate.arguments:"},
		{"unknown field", "      tool: t\n      bogus: 1\n", "decoding yaml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(validateCase(tt.block)), ".")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateTimeoutBounds(t *testing.T) {
	for _, d := range []string{"1ms", "60s"} {
		if _, err := Parse([]byte(validateCase("      tool: t\n      timeout: "+d+"\n")), "."); err != nil {
			t.Errorf("timeout %s: %v", d, err)
		}
	}
}

func TestValidateErrorsNeverEchoArguments(t *testing.T) {
	_, err := Parse([]byte(validateCase("      tool: t\n      arguments: {token: pw-secret, a: .inf}\n")), ".")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "pw-secret") {
		t.Errorf("error echoes argument values: %v", err)
	}
}
