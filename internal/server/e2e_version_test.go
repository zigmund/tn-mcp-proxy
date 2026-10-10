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
	"sync/atomic"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/server"
)

// TestE2EVersionReachesCredentialCheck checks that server.WithVersion carries
// the binary version into both the OAuth authorize credential check and the
// proxy re-check after a tool error.
func TestE2EVersionReachesCredentialCheck(t *testing.T) {
	var mu sync.Mutex
	var agents []string
	var failing atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m struct {
			Method string `json:"method"`
			ID     any    `json:"id"`
		}
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		agents = append(agents, r.Header.Get("User-Agent"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch m.Method {
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/call":
			if failing.Load() {
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"content":[{"type":"text","text":"Invalid api key"}],"isError":true}}`, m.ID)
				return
			}
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"content":[{"type":"text","text":"{}"}]}}`, m.ID)
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"protocolVersion":"2025-06-18"}}`, m.ID)
		}
	}))
	t.Cleanup(upstream.Close)

	cfg, err := config.Parse([]byte(fmt.Sprintf(`
public_url: %s
secrets:
  token_keys: ["`+testKey("e2e")+`"]
oauth:
  allowed_redirect_uris: ["%s"]
upstreams:
  - name: fake
    title: Fake MCP
    path: /fake/mcp
    url: %s/mcp
    credentials:
      - { header: X-Api-Key, label: API key, secret: true }
    validate:
      tool: get_auth_info
      recheck_on_tool_error: true
`, e2ePublicURL, e2eRedirectURI, upstream.URL)), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := seal.New(cfg.Secrets.Keys)
	if err != nil {
		t.Fatal(err)
	}
	h, err := server.Handler(cfg, sealer, slog.New(slog.NewTextHandler(io.Discard, nil)), server.WithVersion("v9.9.9"))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, e2ePublicURL+"/oauth/register",
		strings.NewReader(`{"client_name":"E2E","redirect_uris":["`+e2eRedirectURI+`"],"token_endpoint_auth_method":"none"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := do(t, h, req)
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
	form.Set("cred_0", "any-key")
	rec = postForm(t, h, "/oauth/authorize", form)
	mustStatus(t, rec, http.StatusSeeOther, "POST authorize")

	check := func(what string) {
		t.Helper()
		mu.Lock()
		defer mu.Unlock()
		if len(agents) == 0 {
			t.Fatalf("%s: upstream was not contacted", what)
		}
		for _, ua := range agents {
			if ua != "tn-mcp-proxy/v9.9.9" {
				t.Errorf("%s: User-Agent = %q", what, ua)
			}
		}
		agents = nil
	}
	check("authorize")

	tp := decodeTokens(t, postForm(t, h, "/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {mustCode(t, rec)},
		"redirect_uri": {e2eRedirectURI}, "code_verifier": {e2eVerifier},
		"client_id": {reg.ClientID}, "resource": {e2ePublicURL + "/fake/mcp"},
	}))

	// A proxied tool error triggers a re-check. The client's own User-Agent
	// is forwarded on the proxied request, so a tn-mcp-proxy one can only
	// come from the re-check.
	failing.Store(true)
	call := httptest.NewRequest(http.MethodPost, e2ePublicURL+"/fake/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"portfolio_get","arguments":{}}}`))
	call.Header.Set("Content-Type", "application/json")
	call.Header.Set("Accept", "application/json, text/event-stream")
	call.Header.Set("Authorization", "Bearer "+tp.AccessToken)
	call.Header.Set("User-Agent", "client/1")
	mustStatus(t, do(t, h, call), http.StatusUnauthorized, "tool call with rejected key")
	mu.Lock()
	var proxied, rechecks int
	for _, ua := range agents {
		switch ua {
		case "client/1":
			proxied++
		case "tn-mcp-proxy/v9.9.9":
			rechecks++
		default:
			t.Errorf("unexpected User-Agent %q", ua)
		}
	}
	mu.Unlock()
	if proxied != 1 || rechecks == 0 {
		t.Errorf("proxied = %d, rechecks = %d", proxied, rechecks)
	}
}

func mustCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("redirect %q: %v", rec.Header().Get("Location"), err)
	}
	return loc.Query().Get("code")
}
