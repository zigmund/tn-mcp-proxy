package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

func TestForbiddenArgumentsOffByDefault(t *testing.T) {
	e := newEnv(t, nil)
	for _, body := range []string{call(`{"api_key":"K"}`), "not json at all"} {
		resp := e.do(t, "POST", "/mcp/tn", "Bearer "+e.access(t, goodCreds()), nil, body)
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
	if reqs := e.requests(); len(reqs) != 2 || reqs[0].body != call(`{"api_key":"K"}`) {
		t.Fatalf("upstream saw %+v", reqs)
	}
}

func TestForbiddenArgumentsBodyCap(t *testing.T) {
	e := newEnvUp(t, nil, forbid)
	big := call(`{"q":"` + strings.Repeat("a", int(config.DefaultMaxRequestBody)) + `"}`)
	resp := e.do(t, "POST", "/mcp/tn", "Bearer "+e.access(t, goodCreds()), nil, big)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", resp.StatusCode)
	}
	if n := len(e.requests()); n != 0 {
		t.Fatalf("%d requests reached the upstream", n)
	}
}

func TestForbiddenArgumentsOnlyPost(t *testing.T) {
	e := newEnvUp(t, nil, forbid)
	for _, m := range []string{"GET", "DELETE"} {
		resp := e.do(t, m, "/mcp/tn", "Bearer "+e.access(t, goodCreds()), nil, "")
		if resp.StatusCode != 200 {
			t.Errorf("%s: status %d", m, resp.StatusCode)
		}
	}
}
