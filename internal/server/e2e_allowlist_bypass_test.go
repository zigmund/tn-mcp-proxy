package server_test

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/server"
)

const (
	bypassOwnerKey    = "REPLACE_WITH_YOUR_API_KEY"
	bypassOwnerSecret = "owner-secret"
)

// bypassConfig is a Tradernet-style two-credential upstream: the API key is
// non-secret and allow-listed, the secret is not.
func bypassConfig(upstreamURL, extra string) string {
	return fmt.Sprintf(`
public_url: %s
secrets:
  token_keys: ["`+testKey("bypass")+`"]
oauth:
  allowed_redirect_uris: ["%s"]
upstreams:
  - name: fake
    title: Fake MCP
    path: /fake/mcp
    url: %s/mcp
    credentials:
      - { header: X-Api-Key, label: API key, allowed_values: ["%s"] }
      - { header: X-Api-Secret, label: API secret, secret: true }
%s`, e2ePublicURL, e2eRedirectURI, upstreamURL, bypassOwnerKey, extra)
}

// TestAllowListBypassViaToolArguments: an
// allow-list on the API key alone ties a token to nothing but knowledge of that
// key, and tool arguments can carry credentials around the injected headers.
// Both halves are closed: such a config is refused at load, and the supported
// config (validate + forbidden_arguments) neither issues a token for a wrong
// secret nor relays credential-named tool arguments.
func TestAllowListBypassViaToolArguments(t *testing.T) {
	var mu sync.Mutex
	var bodies []string // probe_tool calls (not the credential check)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(b, &m)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(m.Method, "notifications/"):
			w.WriteHeader(http.StatusAccepted)
		case m.Method == "tools/call" && r.Header.Get("X-Api-Secret") != bypassOwnerSecret:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"Invalid api key provided"}],"isError":true}}`, m.ID)
		default:
			if m.Method == "tools/call" && strings.Contains(string(b), `"probe_tool"`) {
				mu.Lock()
				bodies = append(bodies, string(b))
				mu.Unlock()
			}
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"fake"},"content":[{"type":"text","text":"{}"}]}}`, m.ID)
		}
	}))
	t.Cleanup(up.Close)

	// 1. The vulnerable configuration no longer loads.
	_, err := config.Parse([]byte(bypassConfig(up.URL, "")), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "allowed_values requires validate") {
		t.Fatalf("allowed_values without validate: err = %v", err)
	}

	// 2. The supported configuration.
	cfg, err := config.Parse([]byte(bypassConfig(up.URL, `    validate: { tool: get_auth_info }
    forbidden_arguments: [api_key, api_secret]
`)), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(cfg.Secrets.Keys)
	if err != nil {
		t.Fatal(err)
	}
	h, err := server.Handler(cfg, sealer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	rec := do(t, h, func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, e2ePublicURL+"/oauth/register",
			strings.NewReader(`{"client_name":"E2E","redirect_uris":["`+e2eRedirectURI+`"],"token_endpoint_auth_method":"none"}`))
		r.Header.Set("Content-Type", "application/json")
		return r
	}())
	mustStatus(t, rec, http.StatusCreated, "register")
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reg); err != nil || reg.ClientID == "" {
		t.Fatalf("register response: %v: %s", err, rec.Body)
	}
	aq := url.Values{
		"response_type":         {"code"},
		"client_id":             {reg.ClientID},
		"redirect_uri":          {e2eRedirectURI},
		"state":                 {"st"},
		"code_challenge":        {challengeFor(e2eVerifier)},
		"code_challenge_method": {"S256"},
		"resource":              {e2ePublicURL + "/fake/mcp"},
	}
	rec = do(t, h, httptest.NewRequest(http.MethodGet, e2ePublicURL+"/oauth/authorize?"+aq.Encode(), nil))
	mustStatus(t, rec, http.StatusOK, "GET authorize")
	form := url.Values{}
	for _, hm := range hiddenRe.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(hm[1], html.UnescapeString(hm[2]))
	}

	// The attacker knows the owner's API key but not the secret: no code.
	form.Set("cred_0", bypassOwnerKey)
	form.Set("cred_1", "attacker-chosen-secret")
	rec = postForm(t, h, "/oauth/authorize", form)
	mustStatus(t, rec, http.StatusBadRequest, "owner key with a wrong secret")
	if rec.Header().Get("Location") != "" {
		t.Fatalf("a wrong secret was redirected to %q", rec.Header().Get("Location"))
	}

	// The owner gets a token.
	form.Set("cred_1", bypassOwnerSecret)
	rec = postForm(t, h, "/oauth/authorize", form)
	mustStatus(t, rec, http.StatusSeeOther, "owner credentials")
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	tp := decodeTokens(t, postForm(t, h, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"redirect_uri":  {e2eRedirectURI},
		"code_verifier": {e2eVerifier},
		"client_id":     {reg.ClientID},
		"resource":      {e2ePublicURL + "/fake/mcp"},
	}))

	mcp := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, e2ePublicURL+"/fake/mcp", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Authorization", "Bearer "+tp.AccessToken)
		return do(t, h, r)
	}

	// Credential-named arguments are refused before reaching the upstream.
	bad := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"probe_tool","arguments":{"api_key":"OTHER-KEY","api_secret":"OTHER-SECRET"}}}`
	rec = mcp(bad)
	mustStatus(t, rec, http.StatusBadRequest, "credential arguments")
	if got := rec.Body.String(); !strings.Contains(got, `"id":7`) || !strings.Contains(got, "argument not allowed") {
		t.Errorf("rejection body: %s", got)
	}
	mu.Lock()
	n := len(bodies)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("a credential-argument call reached the upstream: %v", bodies)
	}

	// A normal call still works and reaches the upstream unchanged.
	good := `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"probe_tool","arguments":{"q":"x"}}}`
	mustStatus(t, mcp(good), http.StatusOK, "clean call")
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 || bodies[0] != good {
		t.Fatalf("upstream bodies = %v, want the clean call byte for byte", bodies)
	}
}
