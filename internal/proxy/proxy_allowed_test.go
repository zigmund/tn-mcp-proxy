package proxy

import (
	"strings"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

func allowKey(up *config.Upstream) {
	up.Credentials[0].AllowedValues = []string{"key-123", "key-456"}
}

func TestAllowedValuesProxy(t *testing.T) {
	e := newEnvUp(t, nil, allowKey)

	foreign := goodCreds()
	foreign["X-Tn-Api-Key"] = "attacker-key"
	resp := e.do(t, "POST", "/mcp/tn", "Bearer "+e.access(t, foreign), nil, "{}")
	if resp.StatusCode != 401 {
		t.Fatalf("foreign key: status %d, want 401", resp.StatusCode)
	}
	if h := resp.Header.Get("WWW-Authenticate"); !strings.Contains(h, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate = %q", h)
	}
	if n := len(e.requests()); n != 0 {
		t.Fatalf("foreign key reached the upstream (%d requests)", n)
	}
	if strings.Contains(e.logs.String(), "attacker-key") {
		t.Error("log leaks the credential value")
	}

	for _, k := range []string{"key-123", "key-456"} {
		c := goodCreds()
		c["X-Tn-Api-Key"] = k
		if resp := e.do(t, "POST", "/mcp/tn", "Bearer "+e.access(t, c), nil, "{}"); resp.StatusCode != 200 {
			t.Errorf("allowed key %s: status %d", k, resp.StatusCode)
		}
	}
}

func TestNoAllowListUnchanged(t *testing.T) {
	e := newEnv(t, nil)
	c := goodCreds()
	c["X-Tn-Api-Key"] = "anything"
	if resp := e.do(t, "POST", "/mcp/tn", "Bearer "+e.access(t, c), nil, "{}"); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
