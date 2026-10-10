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
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/server"
)

const (
	e2ePublicURL   = "https://mcp.example.com"
	e2eRedirectURI = "https://client.example.com/callback"
	e2eVerifier    = "e2e-code-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
)

// fakeUpstream is an MCP upstream that records the last request it received.
type fakeUpstream struct {
	srv *httptest.Server

	mu    sync.Mutex
	calls int
	last  http.Header
	body  string
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("fake upstream reading body: %v", err)
		}
		u.mu.Lock()
		u.calls++
		u.last = r.Header.Clone()
		u.body = string(b)
		u.mu.Unlock()
		// Enough MCP for the credential check: echo the request id, accept
		// notifications.
		var m struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(b, &m)
		if len(m.ID) == 0 {
			m.ID = json.RawMessage("1")
		}
		if strings.HasPrefix(m.Method, "notifications/") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"fake"},"content":[{"type":"text","text":"{}"}]}}`, m.ID)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *fakeUpstream) snapshot() (calls int, hdr http.Header, body string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls, u.last, u.body
}

// do sends req to h and returns the recorded response.
func do(t *testing.T, h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func mustStatus(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("%s: status %d, want %d; body: %s", what, rec.Code, want, rec.Body.String())
	}
}

// pathOf returns the path (and query) of an absolute URL on the public origin,
// so discovered endpoints can be fed back to the in-process handler.
func pathOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil || u.Host != "mcp.example.com" {
		t.Fatalf("URL %q is not on the public origin (err=%v)", raw, err)
	}
	return u.RequestURI()
}

func getJSON(t *testing.T, h http.Handler, path string, v any) {
	t.Helper()
	rec := do(t, h, httptest.NewRequest(http.MethodGet, e2ePublicURL+path, nil))
	mustStatus(t, rec, http.StatusOK, "GET "+path)
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
}

func postForm(t *testing.T, h http.Handler, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, e2ePublicURL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return do(t, h, req)
}

type tokenPair struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

func decodeTokens(t *testing.T, rec *httptest.ResponseRecorder) tokenPair {
	t.Helper()
	mustStatus(t, rec, http.StatusOK, "token endpoint")
	var tp tokenPair
	if err := json.Unmarshal(rec.Body.Bytes(), &tp); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(tp.TokenType, "Bearer") || tp.AccessToken == "" || tp.RefreshToken == "" || tp.ExpiresIn <= 0 {
		t.Fatalf("incomplete token response: %+v", tp)
	}
	return tp
}

var (
	labelRe     = regexp.MustCompile(`<label for="([^"]+)">([^<]*)</label>`)
	hiddenRe    = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)
	inputTypeRe = regexp.MustCompile(`<input id="([^"]+)" name="[^"]+" type="([^"]+)"`)
)

const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}`

// callUpstream POSTs an MCP initialize through the proxy with the bearer token.
func callUpstream(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, e2ePublicURL+path, strings.NewReader(initializeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	return do(t, h, req)
}

func TestE2EOAuthFlow(t *testing.T) {
	up := newFakeUpstream(t)

	cfg, err := config.Parse([]byte(fmt.Sprintf(`
listen: 127.0.0.1:0
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
      - { header: X-Api-Secret, label: API secret, secret: true }
      - { header: X-Account, label: Account, optional: true }
      - { header: X-Unused, label: Unused, optional: true }
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
	const upstreamPath = "/fake/mcp"

	// 1. Unauthenticated request -> challenge -> metadata discovery.
	rec := do(t, h, httptest.NewRequest(http.MethodPost, e2ePublicURL+upstreamPath, strings.NewReader(initializeBody)))
	mustStatus(t, rec, http.StatusUnauthorized, "unauthenticated upstream call")
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	m := regexp.MustCompile(`resource_metadata="([^"]+)"`).FindStringSubmatch(wwwAuth)
	if m == nil || !strings.HasPrefix(wwwAuth, "Bearer ") {
		t.Fatalf("WWW-Authenticate = %q, want Bearer challenge with resource_metadata", wwwAuth)
	}
	if n, _, _ := up.snapshot(); n != 0 {
		t.Fatalf("unauthenticated request reached the upstream (%d calls)", n)
	}

	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	getJSON(t, h, pathOf(t, m[1]), &prm)
	if prm.Resource != e2ePublicURL+upstreamPath || len(prm.AuthorizationServers) != 1 {
		t.Fatalf("protected resource metadata = %+v", prm)
	}

	var asm struct {
		Issuer                string   `json:"issuer"`
		AuthorizationEndpoint string   `json:"authorization_endpoint"`
		TokenEndpoint         string   `json:"token_endpoint"`
		RegistrationEndpoint  string   `json:"registration_endpoint"`
		CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
		IssParam              bool     `json:"authorization_response_iss_parameter_supported"`
	}
	getJSON(t, h, "/.well-known/oauth-authorization-server", &asm)
	if asm.Issuer != prm.AuthorizationServers[0] {
		t.Fatalf("issuer %q != advertised authorization server %q", asm.Issuer, prm.AuthorizationServers[0])
	}
	if !asm.IssParam || len(asm.CodeChallengeMethods) != 1 || asm.CodeChallengeMethods[0] != "S256" {
		t.Fatalf("authorization server metadata = %+v", asm)
	}
	registerPath, authorizePath, tokenPath := pathOf(t, asm.RegistrationEndpoint), pathOf(t, asm.AuthorizationEndpoint), pathOf(t, asm.TokenEndpoint)

	// 2. Dynamic client registration (confidential client, client_secret_post).
	regBody, err := json.Marshal(map[string]any{
		"client_name":                "E2E client",
		"redirect_uris":              []string{e2eRedirectURI},
		"token_endpoint_auth_method": "client_secret_post",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, e2ePublicURL+registerPath, strings.NewReader(string(regBody)))
	req.Header.Set("Content-Type", "application/json")
	rec = do(t, h, req)
	mustStatus(t, rec, http.StatusCreated, "register")
	var reg struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reg); err != nil || reg.ClientID == "" || reg.ClientSecret == "" {
		t.Fatalf("register response: %v: %s", err, rec.Body.String())
	}

	// 3. Authorization request with PKCE S256 -> credentials form.
	sum := sha256.Sum256([]byte(e2eVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	const state = "e2e-state-xyz"
	aq := url.Values{
		"response_type":         {"code"},
		"client_id":             {reg.ClientID},
		"redirect_uri":          {e2eRedirectURI},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"resource":              {prm.Resource},
	}
	rec = do(t, h, httptest.NewRequest(http.MethodGet, e2ePublicURL+authorizePath+"?"+aq.Encode(), nil))
	mustStatus(t, rec, http.StatusOK, "GET authorize")
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("authorize Content-Type = %q", ct)
	}
	page := rec.Body.String()

	// 4. Parse the form: hidden fields are echoed back, credential fields are
	// found by label.
	form := url.Values{}
	for _, hm := range hiddenRe.FindAllStringSubmatch(page, -1) {
		form.Set(hm[1], html.UnescapeString(hm[2]))
	}
	if form.Get("request") == "" {
		t.Fatalf("form has no hidden request field:\n%s", page)
	}
	fieldByLabel := map[string]string{}
	for _, lm := range labelRe.FindAllStringSubmatch(page, -1) {
		fieldByLabel[strings.TrimSuffix(strings.TrimSpace(lm[2]), " (optional)")] = lm[1]
	}
	inputType := map[string]string{}
	for _, im := range inputTypeRe.FindAllStringSubmatch(page, -1) {
		inputType[im[1]] = im[2]
	}
	for _, label := range []string{"API key", "API secret", "Account", "Unused"} {
		if fieldByLabel[label] == "" {
			t.Fatalf("form lacks field %q; found %v", label, fieldByLabel)
		}
	}
	if inputType[fieldByLabel["API key"]] != "password" || inputType[fieldByLabel["Account"]] != "text" {
		t.Fatalf("input types = %v, want secret fields masked", inputType)
	}
	const (
		apiKey    = "key-AAA-111"
		apiSecret = "secret-BBB-222"
		account   = "acct-777"
	)
	form.Set(fieldByLabel["API key"], apiKey)
	form.Set(fieldByLabel["API secret"], apiSecret)
	form.Set(fieldByLabel["Account"], account)
	// "Unused" (optional) is left empty on purpose.

	issueCode := func() string {
		t.Helper()
		rec := postForm(t, h, authorizePath, form)
		// 303 after a POST so the browser never re-sends the credentials.
		mustStatus(t, rec, http.StatusSeeOther, "POST authorize")
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if loc.Scheme+"://"+loc.Host+loc.Path != e2eRedirectURI {
			t.Fatalf("redirect to %q, want %q", rec.Header().Get("Location"), e2eRedirectURI)
		}
		lq := loc.Query()
		if lq.Get("error") != "" || lq.Get("state") != state || lq.Get("iss") != e2ePublicURL || lq.Get("code") == "" {
			t.Fatalf("redirect query = %v", lq)
		}
		return lq.Get("code")
	}
	code := issueCode()

	// 5. Authorization code grant.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {e2eRedirectURI},
		"code_verifier": {e2eVerifier},
		"client_id":     {reg.ClientID},
		"client_secret": {reg.ClientSecret},
		"resource":      {prm.Resource},
	}
	// PKCE negatives on a second code: a wrong or missing verifier is refused
	// without consuming the code (checked before the single-use claim), so the
	// legitimate client can still redeem it afterwards.
	pkceForm := func(verifier string) url.Values {
		f := url.Values{}
		for k, v := range tokenForm {
			f[k] = v
		}
		f.Set("code", issueCode())
		if verifier == "" {
			f.Del("code_verifier")
		} else {
			f.Set("code_verifier", verifier)
		}
		return f
	}
	wrong := pkceForm("wrong-verifier-0123456789-abcdefghijklmnopqrstuvwxyz")
	if rec := postForm(t, h, tokenPath, wrong); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"invalid_grant"`) {
		t.Fatalf("wrong code_verifier: status %d body %s, want 400 invalid_grant", rec.Code, rec.Body.String())
	}
	missing := pkceForm("")
	if rec := postForm(t, h, tokenPath, missing); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"invalid_request"`) {
		t.Fatalf("missing code_verifier: status %d body %s, want 400 invalid_request", rec.Code, rec.Body.String())
	}
	// The failed attempts did not burn the codes.
	wrong.Set("code_verifier", e2eVerifier)
	decodeTokens(t, postForm(t, h, tokenPath, wrong))
	missing.Set("code_verifier", e2eVerifier)
	decodeTokens(t, postForm(t, h, tokenPath, missing))

	tp := decodeTokens(t, postForm(t, h, tokenPath, tokenForm))

	// A code is single-use.
	if rec := postForm(t, h, tokenPath, tokenForm); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("code replay: status %d body %s, want 400 invalid_grant", rec.Code, rec.Body.String())
	}

	// Access tokens are sealed and stateless: by design they cannot be revoked
	// (neither by code replay, refresh rotation nor family revocation) and are
	// bounded only by oauth.access_token_ttl. The assertions below pin that.

	// 6. Proxied call: credentials injected, bearer token not forwarded.
	wantCalls := 0
	assertUpstreamCall := func(token string) {
		t.Helper()
		wantCalls++
		rec := callUpstream(t, h, upstreamPath, token)
		mustStatus(t, rec, http.StatusOK, "proxied initialize")
		if !strings.Contains(rec.Body.String(), `"serverInfo"`) {
			t.Fatalf("unexpected proxied body: %s", rec.Body.String())
		}
		calls, hdr, body := up.snapshot()
		if calls != wantCalls {
			t.Fatalf("upstream calls = %d, want %d", calls, wantCalls)
		}
		if body != initializeBody {
			t.Errorf("upstream body = %q", body)
		}
		for k, want := range map[string]string{"X-Api-Key": apiKey, "X-Api-Secret": apiSecret, "X-Account": account} {
			if got := hdr.Get(k); got != want {
				t.Errorf("upstream header %s = %q, want %q", k, got, want)
			}
		}
		if _, ok := hdr["X-Unused"]; ok {
			t.Errorf("empty optional credential was forwarded: %v", hdr["X-Unused"])
		}
		if got := hdr.Get("Authorization"); got != "" {
			t.Errorf("upstream received Authorization %q; the bearer token must not be forwarded", got)
		}
		for k, v := range hdr {
			if strings.Contains(strings.Join(v, ","), token) {
				t.Errorf("upstream header %s leaks the access token", k)
			}
		}
	}
	assertUpstreamCall(tp.AccessToken)

	// Invalid bearer: a tampered token gets an invalid_token challenge and
	// never reaches the upstream.
	tampered := []byte(tp.AccessToken)
	i := len(tampered) / 2
	if tampered[i] == 'A' {
		tampered[i] = 'B'
	} else {
		tampered[i] = 'A'
	}
	rec = callUpstream(t, h, upstreamPath, string(tampered))
	mustStatus(t, rec, http.StatusUnauthorized, "tampered access token")
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_token"`) || !strings.Contains(got, "resource_metadata=") {
		t.Fatalf("tampered token WWW-Authenticate = %q", got)
	}
	if n, _, _ := up.snapshot(); n != wantCalls {
		t.Fatalf("invalid bearer reached the upstream (%d calls, want %d)", n, wantCalls)
	}

	// 7. Refresh grant: rotation, new access token works, old refresh is dead.
	refreshForm := func(rt string) url.Values {
		return url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {rt},
			"client_id":     {reg.ClientID},
			"client_secret": {reg.ClientSecret},
			"resource":      {prm.Resource},
		}
	}
	tp2 := decodeTokens(t, postForm(t, h, tokenPath, refreshForm(tp.RefreshToken)))
	if tp2.AccessToken == tp.AccessToken || tp2.RefreshToken == tp.RefreshToken {
		t.Fatal("refresh did not rotate the tokens")
	}
	assertUpstreamCall(tp2.AccessToken)
	assertUpstreamCall(tp.AccessToken) // the old access token is still valid

	// Reuse of the spent refresh token is rejected and revokes the family.
	rec = postForm(t, h, tokenPath, refreshForm(tp.RefreshToken))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("refresh reuse: status %d body %s, want 400 invalid_grant", rec.Code, rec.Body.String())
	}
	rec = postForm(t, h, tokenPath, refreshForm(tp2.RefreshToken))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("successor after reuse: status %d body %s, want family revoked (400 invalid_grant)", rec.Code, rec.Body.String())
	}
	assertUpstreamCall(tp.AccessToken)
	assertUpstreamCall(tp2.AccessToken) // still valid after family revocation
}

// testKey derives a deterministic, non-patterned 32-byte key from seed, so no
// key literal lives in the repository.
func testKey(seed string) string {
	h := sha256.Sum256([]byte(seed))
	return base64.StdEncoding.EncodeToString(h[:])
}
