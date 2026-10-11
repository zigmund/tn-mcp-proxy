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
	"strings"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/server"
)

// TestE2EAllowedValues walks register -> authorize -> token -> proxied call
// with an allow-list: a foreign key is refused at the form (and never reaches
// the upstream), the allowed key gets a working token.
func TestE2EAllowedValues(t *testing.T) {
	up := newFakeUpstream(t)
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
listen: 127.0.0.1:0
public_url: %s
secrets:
  token_keys: ["`+testKey("e2e-allowed")+`"]
oauth:
  allowed_redirect_uris: ["%s"]
upstreams:
  - name: fake
    title: Fake MCP
    path: /fake/mcp
    url: %s/mcp
    credentials:
      - { header: X-Api-Key, label: API key, allowed_values: ["REPLACE_WITH_YOUR_API_KEY"] }
    validate:
      tool: get_auth_info
`, e2ePublicURL, e2eRedirectURI, up.srv.URL)), t.TempDir())
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

	regBody := `{"client_name":"E2E","redirect_uris":["` + e2eRedirectURI + `"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}`
	req := httptest.NewRequest(http.MethodPost, e2ePublicURL+"/oauth/register", strings.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	rec := do(t, h, req)
	mustStatus(t, rec, http.StatusCreated, "register")
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reg); err != nil || reg.ClientID == "" {
		t.Fatalf("register response: %v: %s", err, rec.Body.String())
	}

	sum := sha256.Sum256([]byte(e2eVerifier))
	aq := url.Values{
		"response_type":         {"code"},
		"client_id":             {reg.ClientID},
		"redirect_uri":          {e2eRedirectURI},
		"state":                 {"st"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
		"resource":              {e2ePublicURL + "/fake/mcp"},
	}
	rec = do(t, h, httptest.NewRequest(http.MethodGet, e2ePublicURL+"/oauth/authorize?"+aq.Encode(), nil))
	mustStatus(t, rec, http.StatusOK, "GET authorize")
	form := url.Values{}
	for _, hm := range hiddenRe.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(hm[1], html.UnescapeString(hm[2]))
	}

	form.Set("cred_0", "someone-elses-key")
	rec = postForm(t, h, "/oauth/authorize", form)
	mustStatus(t, rec, http.StatusBadRequest, "foreign key")
	if body := rec.Body.String(); !strings.Contains(body, "are not allowed on this server") || strings.Contains(body, "rejected these credentials") {
		t.Errorf("form lacks the explicit not-allowed message:\n%s", body)
	}
	if n, _, _ := up.snapshot(); n != 0 {
		t.Fatalf("foreign key reached the upstream (%d calls)", n)
	}

	form.Set("cred_0", " REPLACE_WITH_YOUR_API_KEY ")
	rec = postForm(t, h, "/oauth/authorize", form)
	mustStatus(t, rec, http.StatusSeeOther, "allowed key")
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	rec = postForm(t, h, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"redirect_uri":  {e2eRedirectURI},
		"code_verifier": {e2eVerifier},
		"client_id":     {reg.ClientID},
	})
	tp := decodeTokens(t, rec)

	before, _, _ := up.snapshot() // the credential check already contacted the upstream
	rec = callUpstream(t, h, "/fake/mcp", tp.AccessToken)
	mustStatus(t, rec, http.StatusOK, "proxied call")
	if n, hdr, _ := up.snapshot(); n != before+1 || hdr.Get("X-Api-Key") != "REPLACE_WITH_YOUR_API_KEY" {
		t.Fatalf("upstream calls = %d (before %d), key = %q", n, before, hdr.Get("X-Api-Key"))
	}
}
