package server_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/server"
)

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestE2EValidatedAuthorize runs register -> authorize -> token -> proxied call
// against an upstream that only accepts one API key: a rejected key yields no
// code, the accepted one does, and the proxied call uses the stored credentials.
func TestE2EValidatedAuthorize(t *testing.T) {
	const goodKey = "good-key-123"

	var mu sync.Mutex
	var calls []string // "<jsonrpc method> <X-Api-Key>"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m struct {
			Method string `json:"method"`
			ID     any    `json:"id"`
		}
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		calls = append(calls, m.Method+" "+r.Header.Get("X-Api-Key"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case m.Method == "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case m.Method == "tools/call" && r.Header.Get("X-Api-Key") != goodKey:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"content":[{"type":"text","text":"Invalid api key provided"}],"isError":true}}`, m.ID)
		case m.Method == "tools/call":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"content":[{"type":"text","text":"{}"}]}}`, m.ID)
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"fake"}}}`, m.ID)
		}
	}))
	t.Cleanup(upstream.Close)
	snapshot := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), calls...)
	}

	cfg, err := config.Parse([]byte(fmt.Sprintf(`
public_url: %s
secrets:
  token_keys: ["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]
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

	// Register a public client and open the form.
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
	if n := len(snapshot()); n != 0 {
		t.Fatalf("GET authorize contacted the upstream (%d calls)", n)
	}
	form := url.Values{}
	for _, hm := range hiddenRe.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(hm[1], html.UnescapeString(hm[2]))
	}

	// A key the upstream rejects: the form comes back, no code is issued.
	form.Set("cred_0", "bad-key")
	rec = postForm(t, h, "/oauth/authorize", form)
	mustStatus(t, rec, http.StatusBadRequest, "POST authorize with a bad key")
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("a rejected key was redirected to %q", loc)
	}
	if body := rec.Body.String(); !strings.Contains(body, "Fake MCP rejected these credentials.") || strings.Contains(body, "bad-key") {
		t.Fatalf("rejection page: %s", body)
	}
	want := []string{"initialize bad-key", "notifications/initialized bad-key", "tools/call bad-key"}
	if got := snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("upstream calls = %v, want %v", got, want)
	}

	// The accepted key issues a code, which redeems for working tokens.
	form.Set("cred_0", goodKey)
	rec = postForm(t, h, "/oauth/authorize", form)
	mustStatus(t, rec, http.StatusSeeOther, "POST authorize with a good key")
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Query().Get("code") == "" || loc.Query().Get("state") != "st" {
		t.Fatalf("redirect %q: %v", rec.Header().Get("Location"), err)
	}
	tp := decodeTokens(t, postForm(t, h, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"redirect_uri":  {e2eRedirectURI},
		"code_verifier": {e2eVerifier},
		"client_id":     {reg.ClientID},
		"resource":      {e2ePublicURL + "/fake/mcp"},
	}))

	// Token redemption does not touch the upstream; the proxied call carries
	// the validated credentials.
	if n := len(snapshot()); n != 6 {
		t.Fatalf("upstream calls after authorize = %v, want 6", snapshot())
	}
	rec = callUpstream(t, h, "/fake/mcp", tp.AccessToken)
	mustStatus(t, rec, http.StatusOK, "proxied initialize")
	got := snapshot()
	if len(got) != 7 || got[6] != "initialize "+goodKey {
		t.Fatalf("upstream calls = %v, want the proxied initialize with the good key last", got)
	}
}
