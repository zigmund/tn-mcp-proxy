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
	"sync/atomic"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/server"
)

// With the real wiring, a tool error whose re-check confirms the credentials
// as rejected also stops the refresh grant (invalid_grant), so a client that
// refreshes after the 401 must run the authorization flow again.
func TestE2ERefreshRefusedAfterConfirmedRejection(t *testing.T) {
	var revoked atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m struct {
			Method string `json:"method"`
			ID     any    `json:"id"`
		}
		_ = json.Unmarshal(b, &m)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case m.Method == "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case m.Method == "tools/call" && revoked.Load():
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"content":[{"type":"text","text":"Invalid api key provided"}],"isError":true}}`, m.ID)
		case m.Method == "tools/call":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"content":[{"type":"text","text":"{}"}]}}`, m.ID)
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"fake"}}}`, m.ID)
		}
	}))
	t.Cleanup(upstream.Close)

	cfg, err := config.Parse([]byte(fmt.Sprintf(`
public_url: %s
secrets:
  token_keys: ["`+testKey("e2e-refresh")+`"]
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
	h, err := server.Handler(cfg, sealer, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
		"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {e2eRedirectURI},
		"state": {"st"}, "code_challenge": {challengeFor(e2eVerifier)}, "code_challenge_method": {"S256"},
		"resource": {e2ePublicURL + "/fake/mcp"},
	}
	rec = do(t, h, httptest.NewRequest(http.MethodGet, e2ePublicURL+"/oauth/authorize?"+aq.Encode(), nil))
	mustStatus(t, rec, http.StatusOK, "GET authorize")
	form := url.Values{}
	for _, hm := range hiddenRe.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(hm[1], html.UnescapeString(hm[2]))
	}
	form.Set("cred_0", "some-key")
	rec = postForm(t, h, "/oauth/authorize", form)
	mustStatus(t, rec, http.StatusSeeOther, "POST authorize")
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("redirect %q: %v", rec.Header().Get("Location"), err)
	}
	tp := decodeTokens(t, postForm(t, h, "/oauth/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {e2eRedirectURI}, "code_verifier": {e2eVerifier},
		"client_id": {reg.ClientID}, "resource": {e2ePublicURL + "/fake/mcp"},
	}))

	refresh := func(rt string) *httptest.ResponseRecorder {
		return postForm(t, h, "/oauth/token", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {reg.ClientID},
			"resource": {e2ePublicURL + "/fake/mcp"},
		})
	}
	// No verdict yet: refresh works.
	tp = decodeTokens(t, refresh(tp.RefreshToken))

	// The key is revoked upstream; a proxied tool call fails, the re-check
	// confirms the rejection and the proxy answers 401.
	revoked.Store(true)
	call := httptest.NewRequest(http.MethodPost, e2ePublicURL+"/fake/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"portfolio_get","arguments":{}}}`))
	call.Header.Set("Content-Type", "application/json")
	call.Header.Set("Accept", "application/json, text/event-stream")
	call.Header.Set("Authorization", "Bearer "+tp.AccessToken)
	mustStatus(t, do(t, h, call), http.StatusUnauthorized, "tool call with revoked key")

	rec = refresh(tp.RefreshToken)
	mustStatus(t, rec, http.StatusBadRequest, "refresh after confirmed rejection")
	if !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("refresh body: %s", rec.Body)
	}
}
