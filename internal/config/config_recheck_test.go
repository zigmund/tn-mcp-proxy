package config

import "testing"

func TestRecheckOnToolError(t *testing.T) {
	cfg, err := Parse([]byte(validateCase("      tool: get_auth_info\n      recheck_on_tool_error: true\n")), ".")
	if err != nil {
		t.Fatal(err)
	}
	if v := cfg.Upstreams[0].Validate; !v.RecheckOnToolError {
		t.Errorf("validate = %+v, want recheck_on_tool_error", v)
	}

	// Off unless asked for.
	cfg, err = Parse([]byte(validateCase("      tool: get_auth_info\n")), ".")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstreams[0].Validate.RecheckOnToolError {
		t.Error("recheck_on_tool_error must default to false")
	}

	// The old text-matching block no longer exists.
	if _, err := Parse([]byte(base()+"    reauth_on_tool_error:\n      contains: [a]\n"), "."); err == nil {
		t.Error("reauth_on_tool_error must be rejected as an unknown field")
	}
}
