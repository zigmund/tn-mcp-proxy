package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/tokens"
)

const (
	azPublic = "https://mcp.example.com"
	azRes    = "https://mcp.example.com/tn"
)

var azChallenge = func() string {
	sum := sha256.Sum256([]byte("verifier"))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}()

type azEnv struct {
	srv      *Server
	mux      *http.ServeMux
	clientID string
}

func newAZ(t *testing.T, ups ...config.Upstream) *azEnv {
	t.Helper()
	if len(ups) == 0 {
		ups = []config.Upstream{{
			Name: "tn", Title: "Tradernet", Path: "/tn", URL: "https://upstream.example.com/mcp",
			Credentials: []config.Credential{
				{Header: "x-api-key", Label: "API key", Secret: true},
				{Header: "x-user", Label: "User"},
				{Header: "x-extra", Label: "Extra", Optional: true},
			},
		}}
	}
	cfg := &config.Config{
		PublicURL: azPublic,
		OAuth: config.OAuth{
			AllowedRedirectURIs: []string{cbClaudeAI, cbClaudeCom},
			CodeTTL:             5 * time.Minute,
		},
		Upstreams: ups,
	}
	srv := New(cfg, testSealer(t, 0), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.now = func() time.Time { return fixedNow }
	mux := http.NewServeMux()
	srv.Register(mux)
	id, err := srv.sealer.Seal(seal.KindClient, client{
		RedirectURIs: []string{cbClaudeAI}, Name: "<b>Evil</b> App", AuthMethod: authNone, IssuedAt: 1,
	}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return &azEnv{srv: srv, mux: mux, clientID: id}
}

func (e *azEnv) query(mod func(url.Values)) url.Values {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.clientID},
		"redirect_uri":          {cbClaudeAI},
		"code_challenge":        {azChallenge},
		"code_challenge_method": {"S256"},
		"state":                 {"st&te 1"},
		"resource":              {azRes},
	}
	if mod != nil {
		mod(q)
	}
	return q
}

func (e *azEnv) get(q url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, PathAuthorize+"?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func (e *azEnv) post(form url.Values, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, PathAuthorize, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

// hidden extracts the sealed request from a rendered form.
func hidden(t *testing.T, body string) string {
	t.Helper()
	const marker = `name="request" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no hidden request field in:\n%s", body)
	}
	rest := body[i+len(marker):]
	return rest[:strings.Index(rest, `"`)]
}

func goodForm(sealed string) url.Values {
	return url.Values{requestField: {sealed}, "cred_0": {"sekret"}, "cred_1": {" alice "}}
}

func mustRedirect(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body: %s", rec.Code, rec.Body)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mustSeeOther(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body: %s", rec.Code, rec.Body)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mustPage(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, status, rec.Body)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("must not redirect, Location = %q", loc)
	}
}

func TestAuthorizeFormRenders(t *testing.T) {
	e := newAZ(t)
	rec := e.get(e.query(nil))
	mustPage(t, rec, http.StatusOK)
	body := rec.Body.String()

	for _, want := range []string{
		"Connect Tradernet",
		`type="password"`, `name="cred_0"`, "API key",
		`name="cred_1"`, "User",
		"Extra (optional)",
		"unverified",
		"claude.ai",
		`action="/oauth/authorize"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("form lacks %q", want)
		}
	}
	if strings.Contains(body, "<b>Evil</b>") || !strings.Contains(body, "&lt;b&gt;Evil&lt;/b&gt; App") {
		t.Error("client name not HTML-escaped")
	}
	if strings.Contains(body, "<script") {
		t.Error("form contains a script")
	}
	h := rec.Header()
	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"frame-ancestors 'none'", "form-action 'self' https://claude.ai", "default-src 'none'", "style-src 'sha256-"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if strings.Contains(csp, "unsafe") {
		t.Errorf("CSP must not use unsafe: %q", csp)
	}
	for k, want := range map[string]string{
		"Cache-Control": "no-store", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
		"Content-Type": "text/html; charset=utf-8",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if h.Get("Access-Control-Allow-Origin") != "" {
		t.Error("authorize must not set CORS headers")
	}

	// The hidden field opens to the validated request.
	req, err := seal.OpenAs[authRequest](e.srv.sealer, seal.KindAuthRequest, hidden(t, body))
	if err != nil {
		t.Fatal(err)
	}
	want := authRequest{ClientID: e.clientID, RedirectURI: cbClaudeAI, CodeChallenge: azChallenge, State: "st&te 1", Upstream: "tn"}
	if req != want {
		t.Errorf("request = %+v, want %+v", req, want)
	}
}

func TestAuthorizeFormResourceOptionalWithOneUpstream(t *testing.T) {
	e := newAZ(t)
	mustPage(t, e.get(e.query(func(q url.Values) { q.Del("resource") })), http.StatusOK)
}

func TestAuthorizeErrorPagesNeverRedirect(t *testing.T) {
	e := newAZ(t)
	foreign, _ := e.srv.sealer.Seal(seal.KindCode, client{RedirectURIs: []string{cbClaudeAI}}, time.Time{})
	// A server with a different key stands in for a rotated-away key.
	rotated := New(e.srv.cfg, testSealer(t, 1), nil)
	rotated.now = e.srv.now
	rmux := http.NewServeMux()
	rotated.Register(rmux)

	tests := []struct {
		name string
		mux  *http.ServeMux
		mod  func(url.Values)
	}{
		{"missing client_id", e.mux, func(q url.Values) { q.Del("client_id") }},
		{"garbage client_id", e.mux, func(q url.Values) { q.Set("client_id", "garbage") }},
		{"foreign-kind client_id", e.mux, func(q url.Values) { q.Set("client_id", foreign) }},
		{"duplicate client_id", e.mux, func(q url.Values) { q.Add("client_id", e.clientID) }},
		{"rotated-away key", rmux, nil},
		{"missing redirect_uri", e.mux, func(q url.Values) { q.Del("redirect_uri") }},
		{"unregistered redirect_uri", e.mux, func(q url.Values) { q.Set("redirect_uri", cbClaudeCom) }},
		{"foreign redirect_uri", e.mux, func(q url.Values) { q.Set("redirect_uri", "https://evil.example.com/cb") }},
		{"redirect_uri with suffix", e.mux, func(q url.Values) { q.Set("redirect_uri", cbClaudeAI+"/") }},
		{"duplicate redirect_uri", e.mux, func(q url.Values) { q.Add("redirect_uri", cbClaudeAI) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, PathAuthorize+"?"+e.query(tt.mod).Encode(), nil)
			rec := httptest.NewRecorder()
			tt.mux.ServeHTTP(rec, req)
			mustPage(t, rec, http.StatusBadRequest)
			if !strings.Contains(rec.Body.String(), "Authorization error") {
				t.Error("no error page")
			}
			if rec.Header().Get("X-Frame-Options") != "DENY" {
				t.Error("error page lacks security headers")
			}
		})
	}
}

func TestAuthorizeRedirectedErrors(t *testing.T) {
	two := []config.Upstream{
		{Name: "a", Path: "/a", URL: "https://a.example.com/mcp", Credentials: []config.Credential{{Header: "X-A"}}},
		{Name: "b", Path: "/b", URL: "https://b.example.com/mcp", Credentials: []config.Credential{{Header: "X-B"}}},
	}
	tests := []struct {
		name string
		ups  []config.Upstream
		mod  func(url.Values)
		code string
	}{
		{"missing PKCE", nil, func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") }, "invalid_request"},
		{"challenge without method", nil, func(q url.Values) { q.Del("code_challenge_method") }, "invalid_request"},
		{"plain method", nil, func(q url.Values) { q.Set("code_challenge_method", "plain") }, "invalid_request"},
		{"method without challenge", nil, func(q url.Values) { q.Del("code_challenge") }, "invalid_request"},
		{"short challenge", nil, func(q url.Values) { q.Set("code_challenge", "abc") }, "invalid_request"},
		{"response_type token", nil, func(q url.Values) { q.Set("response_type", "token") }, "unsupported_response_type"},
		{"missing response_type", nil, func(q url.Values) { q.Del("response_type") }, "unsupported_response_type"},
		{"unknown resource", nil, func(q url.Values) { q.Set("resource", "https://mcp.example.com/other") }, "invalid_target"},
		{"repeated resource", nil, func(q url.Values) { q.Add("resource", azRes) }, "invalid_target"},
		{"ambiguous resource", two, func(q url.Values) { q.Del("resource") }, "invalid_target"},
		{"oversized state", nil, func(q url.Values) { q.Set("state", strings.Repeat("x", maxStateLen+1)) }, "invalid_request"},
		{"duplicate state", nil, func(q url.Values) { q.Add("state", "again") }, "invalid_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newAZ(t, tt.ups...)
			rec := e.get(e.query(tt.mod))
			u := mustRedirect(t, rec)
			if got := u.Scheme + "://" + u.Host + u.Path; got != cbClaudeAI {
				t.Fatalf("redirected to %s", got)
			}
			q := u.Query()
			if q.Get("error") != tt.code {
				t.Errorf("error = %q, want %q", q.Get("error"), tt.code)
			}
			if q.Get("iss") != azPublic {
				t.Errorf("iss = %q", q.Get("iss"))
			}
			if q.Get("code") != "" {
				t.Error("error redirect carries a code")
			}
			if tt.name == "oversized state" || tt.name == "duplicate state" {
				if q.Has("state") {
					t.Errorf("invalid state echoed: %q", q.Get("state"))
				}
			} else if q.Get("state") != "st&te 1" {
				t.Errorf("state = %q", q.Get("state"))
			}
		})
	}
}

// TestAuthorizeSubmitErrorRedirectsCarryIss covers the POST error redirect:
// RFC 9207 requires iss in error responses too (ChatGPT checks it).
func TestAuthorizeSubmitErrorRedirectsCarryIss(t *testing.T) {
	e := newAZ(t)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	e.srv.cfg.Upstreams = []config.Upstream{{Name: "other", Path: "/o"}}
	u := mustSeeOther(t, e.post(goodForm(sealed)))
	q := u.Query()
	if q.Get("error") != "invalid_target" || q.Get("iss") != azPublic || q.Get("state") != "st&te 1" {
		t.Errorf("query = %v", q)
	}
	if q.Get("code") != "" {
		t.Error("error redirect carries a code")
	}
}

func TestAuthorizeSubmitIssuesCode(t *testing.T) {
	e := newAZ(t)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	rec := e.post(goodForm(sealed), "Sec-Fetch-Site", "same-origin")
	u := mustSeeOther(t, rec)
	if got := u.Scheme + "://" + u.Host + u.Path; got != cbClaudeAI {
		t.Fatalf("redirected to %s", got)
	}
	q := u.Query()
	if q.Get("state") != "st&te 1" || q.Get("iss") != azPublic || q.Get("error") != "" {
		t.Errorf("query = %v", q)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("redirect not no-store")
	}

	code, err := seal.OpenAs[tokens.Code](e.srv.sealer, seal.KindCode, q.Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	if code.JTI == "" {
		t.Error("empty jti")
	}
	want := tokens.Code{
		ClientID: e.clientID, RedirectURI: cbClaudeAI, CodeChallenge: azChallenge, Upstream: "tn",
		Creds: map[string]string{"X-Api-Key": "sekret", "X-User": "alice"}, JTI: code.JTI,
	}
	if code.ClientID != want.ClientID || code.RedirectURI != want.RedirectURI || code.CodeChallenge != want.CodeChallenge ||
		code.Upstream != want.Upstream || len(code.Creds) != 2 || code.Creds["X-Api-Key"] != "sekret" || code.Creds["X-User"] != "alice" {
		t.Errorf("code = %#v (creds redacted), want fields of %#v", code, want)
	}

	// Expiry is code_ttl from now; a code is not an access token.
	if _, err := seal.OpenAs[tokens.Code](e.srv.sealer, seal.KindAccess, q.Get("code")); err == nil {
		t.Error("code opened as access token")
	}
	// A second submission yields a different jti.
	q2 := mustSeeOther(t, e.post(goodForm(sealed))).Query()
	c2, _ := seal.OpenAs[tokens.Code](e.srv.sealer, seal.KindCode, q2.Get("code"))
	if c2.JTI == code.JTI {
		t.Error("jti repeated")
	}
}

func TestAuthorizeSubmitCodeExpires(t *testing.T) {
	e := newAZ(t)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	q := mustSeeOther(t, e.post(goodForm(sealed))).Query()
	// Re-open with a clock past code_ttl.
	late, err := seal.New([][]byte{[]byte(strings.Repeat("a", 32))}, seal.WithClock(func() time.Time {
		return fixedNow.Add(5*time.Minute + time.Second)
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seal.OpenAs[tokens.Code](late, seal.KindCode, q.Get("code")); err == nil {
		t.Error("code still valid after code_ttl")
	}
}

func TestAuthorizeSubmitCredentialErrors(t *testing.T) {
	e := newAZ(t)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	tests := []struct {
		name string
		mod  func(url.Values)
		msg  string
	}{
		{"empty required secret", func(f url.Values) { f.Set("cred_0", "") }, "API key is required"},
		{"blank required", func(f url.Values) { f.Set("cred_1", "   ") }, "User is required"},
		{"missing field", func(f url.Values) { f.Del("cred_0") }, "API key is required"},
		{"newline", func(f url.Values) { f.Set("cred_0", "a\r\nX-Evil: 1") }, "invalid characters"},
		{"too long", func(f url.Values) { f.Set("cred_0", strings.Repeat("a", maxCredLen+1)) }, "too long"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := goodForm(sealed)
			tt.mod(f)
			rec := e.post(f)
			mustPage(t, rec, http.StatusBadRequest)
			body := rec.Body.String()
			if !strings.Contains(body, tt.msg) {
				t.Errorf("body lacks %q", tt.msg)
			}
			if !strings.Contains(body, `name="request"`) {
				t.Error("form not re-rendered")
			}
			if strings.Contains(body, "sekret") || strings.Contains(body, "X-Evil") {
				t.Error("secret value echoed")
			}
		})
	}
}

func TestAuthorizeSubmitRejects(t *testing.T) {
	e := newAZ(t)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())

	t.Run("tampered hidden field", func(t *testing.T) {
		b := []byte(sealed)
		b[len(b)/2] ^= 0x01 // flips a base64 character
		mustPage(t, e.post(goodForm(string(b))), http.StatusBadRequest)
	})
	t.Run("missing hidden field", func(t *testing.T) {
		f := goodForm("")
		f.Del(requestField)
		mustPage(t, e.post(f), http.StatusBadRequest)
	})
	t.Run("client id as request", func(t *testing.T) {
		mustPage(t, e.post(goodForm(e.clientID)), http.StatusBadRequest)
	})
	t.Run("params smuggled in the form are ignored", func(t *testing.T) {
		f := goodForm(sealed)
		f.Set("redirect_uri", "https://evil.example.com/cb")
		f.Set("client_id", "x")
		u := mustSeeOther(t, e.post(f))
		if got := u.Scheme + "://" + u.Host + u.Path; got != cbClaudeAI {
			t.Errorf("redirected to %s", got)
		}
	})
	t.Run("cross-site", func(t *testing.T) {
		mustPage(t, e.post(goodForm(sealed), "Sec-Fetch-Site", "cross-site"), http.StatusForbidden)
	})
	t.Run("oversized body", func(t *testing.T) {
		f := goodForm(sealed)
		f.Set("junk", strings.Repeat("a", maxAuthorizeBody))
		mustPage(t, e.post(f), http.StatusRequestEntityTooLarge)
	})
	t.Run("expired form", func(t *testing.T) {
		e.srv.sealer, _ = seal.New([][]byte{[]byte(strings.Repeat("a", 32))}, seal.WithClock(func() time.Time {
			return fixedNow.Add(formTTL + time.Second)
		}))
		defer func() { e.srv.sealer = testSealer(t, 0) }()
		mustPage(t, e.post(goodForm(sealed)), http.StatusBadRequest)
	})
	t.Run("redirect revoked in config", func(t *testing.T) {
		saved := e.srv.cfg.OAuth.AllowedRedirectURIs
		e.srv.cfg.OAuth.AllowedRedirectURIs = []string{cbClaudeCom}
		defer func() { e.srv.cfg.OAuth.AllowedRedirectURIs = saved }()
		mustPage(t, e.post(goodForm(sealed)), http.StatusBadRequest)
	})
	t.Run("upstream removed from config", func(t *testing.T) {
		saved := e.srv.cfg.Upstreams
		e.srv.cfg.Upstreams = []config.Upstream{{Name: "other", Path: "/o"}}
		defer func() { e.srv.cfg.Upstreams = saved }()
		u := mustSeeOther(t, e.post(goodForm(sealed)))
		if u.Query().Get("error") != "invalid_target" {
			t.Errorf("query = %v", u.Query())
		}
	})
}

func TestAuthorizeMethods(t *testing.T) {
	e := newAZ(t)
	for _, m := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		req := httptest.NewRequest(m, PathAuthorize, nil)
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", m, rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s: CORS header set", m)
		}
	}
}

func TestAuthorizeNilSealer(t *testing.T) {
	e := newAZ(t)
	e.srv.sealer = nil
	mustPage(t, e.get(e.query(nil)), http.StatusInternalServerError)
}

func TestAuthorizeNoCredentialsInLogs(t *testing.T) {
	e := newAZ(t)
	var buf strings.Builder
	e.srv.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	f := goodForm(sealed)
	f.Set("cred_0", "topsecret")
	mustSeeOther(t, e.post(f))
	f.Set("cred_1", "")
	e.post(f)
	if strings.Contains(buf.String(), "topsecret") {
		t.Errorf("credentials logged: %s", buf.String())
	}
}

func TestAuthorizeCSPHashMatchesStyle(t *testing.T) {
	e := newAZ(t)
	rec := e.get(e.query(nil))
	m := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("no inline style")
	}
	sum := sha256.Sum256([]byte(m[1]))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "style-src "+want+";") {
		t.Errorf("CSP %q does not carry hash %s of the rendered style", csp, want)
	}
}

func TestAuthorizeSecretNotRerendered(t *testing.T) {
	e := newAZ(t)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	f := goodForm(sealed)
	f.Set("cred_0", "topsecret")
	f.Set("cred_1", "") // forces a 400 re-render
	rec := e.post(f)
	mustPage(t, rec, http.StatusBadRequest)
	body := rec.Body.String()
	if strings.Contains(body, "topsecret") {
		t.Error("secret re-rendered")
	}
	if !regexp.MustCompile(`name="cred_0"[^>]*type="password"|type="password"[^>]*name="cred_0"`).MatchString(body) ||
		strings.Contains(body, `name="cred_0" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" required value=`) {
		t.Error("secret field not a value-less password input")
	}
}

func TestAuthorizeRedirectURIWithQuery(t *testing.T) {
	const cb = "https://claude.ai/api/mcp/auth_callback?app=x&state=stale&iss=stale&error=stale&code=stale&error_description=stale"
	e := newAZ(t)
	e.srv.cfg.OAuth.AllowedRedirectURIs = []string{cb}
	id, err := e.srv.sealer.Seal(seal.KindClient, client{RedirectURIs: []string{cb}, AuthMethod: authNone, IssuedAt: 1}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	e.clientID = id
	check := func(t *testing.T, u *url.URL, wantState string) {
		t.Helper()
		q := u.Query()
		if q.Get("app") != "x" {
			t.Errorf("unrelated param lost: %v", q)
		}
		if q.Get("iss") != azPublic || q.Get("state") != wantState {
			t.Errorf("stale iss/state survived: %v", q)
		}
		for _, k := range []string{"code", "error", "error_description"} {
			if len(q[k]) > 1 || q.Get(k) == "stale" {
				t.Errorf("stale %s survived: %v", k, q)
			}
		}
	}
	// Error path (GET).
	q := e.query(func(q url.Values) { q.Set("redirect_uri", cb); q.Set("response_type", "token") })
	u := mustRedirect(t, e.get(q))
	check(t, u, "st&te 1")
	if u.Query().Get("error") != "unsupported_response_type" || u.Query().Has("code") {
		t.Errorf("query = %v", u.Query())
	}
	// Success path (POST).
	rec := e.get(e.query(func(q url.Values) { q.Set("redirect_uri", cb) }))
	mustPage(t, rec, http.StatusOK)
	u = mustSeeOther(t, e.post(goodForm(hidden(t, rec.Body.String()))))
	check(t, u, "st&te 1")
	if u.Query().Has("error") || u.Query().Has("error_description") || u.Query().Get("code") == "stale" || u.Query().Get("code") == "" {
		t.Errorf("query = %v", u.Query())
	}
}
