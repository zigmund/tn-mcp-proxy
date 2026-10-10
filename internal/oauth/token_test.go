package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/proxy"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/tokens"
)

const (
	tkVerifier = "verifier-verifier-verifier-verifier-verifier-0123"
	tkRedirect = cbClaudeAI
)

type tkEnv struct {
	srv  *Server
	mux  *http.ServeMux
	now  *atomic.Int64 // unix seconds, shared by the sealer and the server
	none string        // client ids
	post string
	bas  string
	up   config.Upstream
	cfg  *config.Config
}

func newTK(t *testing.T) *tkEnv {
	t.Helper()
	e := &tkEnv{now: new(atomic.Int64)}
	e.now.Store(fixedNow.Unix())
	clock := func() time.Time { return time.Unix(e.now.Load(), 0) }
	sealer, err := seal.New([][]byte{[]byte(strings.Repeat("a", 32))}, seal.WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	e.up = config.Upstream{
		Name: "tn", Title: "Tradernet", Path: "/tn", URL: "https://upstream.example.com/mcp",
		Credentials: []config.Credential{{Header: "x-api-key", Label: "API key", Secret: true}},
	}
	e.cfg = &config.Config{
		PublicURL: azPublic,
		OAuth: config.OAuth{
			AllowedRedirectURIs: []string{cbClaudeAI, cbClaudeCom},
			AccessTokenTTL:      time.Hour, RefreshTokenTTL: 720 * time.Hour, CodeTTL: 5 * time.Minute,
		},
		Upstreams: []config.Upstream{e.up},
	}
	e.srv = New(e.cfg, sealer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.srv.now = clock
	e.mux = http.NewServeMux()
	e.srv.Register(e.mux)
	mk := func(method string) string {
		id, err := sealer.Seal(seal.KindClient, client{RedirectURIs: []string{cbClaudeAI}, AuthMethod: method, IssuedAt: 1}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	e.none, e.post, e.bas = mk(authNone), mk(authClientSecretPost), mk(authClientSecretBasic)
	return e
}

var jtiSeq atomic.Int64

// code issues an authorization code for clientID, valid for the default TTL.
func (e *tkEnv) code(t *testing.T, clientID string, mod func(*tokens.Code)) string {
	t.Helper()
	sum := sha256.Sum256([]byte(tkVerifier))
	exp := time.Unix(e.now.Load(), 0).Add(5 * time.Minute)
	c := tokens.Code{
		ClientID: clientID, RedirectURI: tkRedirect, CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		Upstream: "tn", Creds: map[string]string{"X-Api-Key": "sekret"},
		JTI: "jti-" + string(rune('a'+jtiSeq.Add(1)%26)) + base64.RawURLEncoding.EncodeToString([]byte(time.Now().String())), Exp: exp.Unix(),
	}
	if mod != nil {
		mod(&c)
	}
	s, err := e.srv.sealer.Seal(seal.KindCode, c, exp)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (e *tkEnv) codeForm(clientID, code string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {tkRedirect},
		"code_verifier": {tkVerifier}, "client_id": {clientID},
	}
}

func (e *tkEnv) do(form url.Values, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func checkHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	h := rec.Header()
	if h.Get("Cache-Control") != "no-store" || h.Get("Pragma") != "no-cache" {
		t.Errorf("cache headers = %v", h)
	}
	if h.Get("Content-Type") != "application/json" {
		t.Errorf("content type = %q", h.Get("Content-Type"))
	}
	if h.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("unexpected CORS header")
	}
}

func decodeTK(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	return m
}

func (e *tkEnv) wantErr(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	checkHeaders(t, rec)
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, status, rec.Body)
	}
	if got := decodeTK(t, rec)["error"]; got != code {
		t.Fatalf("error = %v, want %s; body %s", got, code, rec.Body)
	}
	for _, secret := range []string{tkVerifier, "sekret"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("error body leaks %q", secret)
		}
	}
}

func (e *tkEnv) wantOK(t *testing.T, rec *httptest.ResponseRecorder) (access, refresh string) {
	t.Helper()
	checkHeaders(t, rec)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body %s", rec.Code, rec.Body)
	}
	m := decodeTK(t, rec)
	if m["token_type"] != "Bearer" || m["expires_in"] != float64(3600) {
		t.Errorf("response = %v", m)
	}
	if _, ok := m["scope"]; ok {
		t.Errorf("scope must be omitted")
	}
	access, _ = m["access_token"].(string)
	refresh, _ = m["refresh_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("missing tokens: %v", m)
	}
	return access, refresh
}

func (e *tkEnv) refreshForm(clientID, rt string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {clientID}}
}

func basicHdr(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
}

func TestTokenCodeExchangeClients(t *testing.T) {
	e := newTK(t)
	t.Run("none", func(t *testing.T) {
		e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	})
	t.Run("post", func(t *testing.T) {
		f := e.codeForm(e.post, e.code(t, e.post, nil))
		f.Set("client_secret", e.srv.clientSecret(e.post))
		e.wantOK(t, e.do(f))
	})
	t.Run("basic", func(t *testing.T) {
		f := e.codeForm(e.bas, e.code(t, e.bas, nil))
		f.Del("client_id")
		e.wantOK(t, e.do(f, "Authorization", basicHdr(e.bas, e.srv.clientSecret(e.bas))))
	})
}

func TestTokenIssuedAccessWorksInProxy(t *testing.T) {
	e := newTK(t)
	var gotKey atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey.Store(r.Header.Get("X-Api-Key"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	up := e.up
	up.URL = upstream.URL
	h, err := proxy.New(up, azPublic, e.srv.sealer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	access, refresh := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))

	acc, err := seal.OpenAs[tokens.Access](e.srv.sealer, seal.KindAccess, access)
	if err != nil || acc.Upstream != "tn" || acc.ClientID != e.none || acc.Creds["X-Api-Key"] != "sekret" {
		t.Fatalf("access = %v, err %v", acc, err)
	}
	call := func(tok string) int {
		req := httptest.NewRequest(http.MethodPost, "/tn", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := call(access); c != http.StatusNoContent || gotKey.Load() != "sekret" {
		t.Fatalf("proxy status = %d, key = %v", c, gotKey.Load())
	}
	// A refresh token is not an access token.
	if c := call(refresh); c != http.StatusUnauthorized {
		t.Errorf("refresh as access: status = %d", c)
	}
	// The refreshed access token works too.
	access2, _ := e.wantOK(t, e.do(e.refreshForm(e.none, refresh)))
	if c := call(access2); c != http.StatusNoContent {
		t.Errorf("refreshed access: status = %d", c)
	}
}

func TestTokenCodeRejections(t *testing.T) {
	e := newTK(t)
	tests := []struct {
		name   string
		code   func(t *testing.T) string
		mod    func(url.Values)
		status int
		err    string
	}{
		{"missing verifier", nil, func(f url.Values) { f.Del("code_verifier") }, 400, "invalid_request"},
		{"missing code", nil, func(f url.Values) { f.Del("code") }, 400, "invalid_request"},
		{"missing redirect", nil, func(f url.Values) { f.Del("redirect_uri") }, 400, "invalid_request"},
		{"short verifier", nil, func(f url.Values) { f.Set("code_verifier", "short") }, 400, "invalid_grant"},
		{"long verifier", nil, func(f url.Values) { f.Set("code_verifier", strings.Repeat("a", 129)) }, 400, "invalid_grant"},
		{"bad chars verifier", nil, func(f url.Values) { f.Set("code_verifier", strings.Repeat("a", 42)+"!") }, 400, "invalid_grant"},
		{"wrong verifier", nil, func(f url.Values) { f.Set("code_verifier", strings.Repeat("b", 43)) }, 400, "invalid_grant"},
		{"wrong redirect", nil, func(f url.Values) { f.Set("redirect_uri", cbClaudeCom) }, 400, "invalid_grant"},
		{"garbage code", nil, func(f url.Values) { f.Set("code", "garbage") }, 400, "invalid_grant"},
		{"duplicate param", nil, func(f url.Values) { f.Add("redirect_uri", tkRedirect) }, 400, "invalid_request"},
		{"resource mismatch", nil, func(f url.Values) { f.Set("resource", "https://mcp.example.com/other") }, 400, "invalid_target"},
		{"empty jti", func(t *testing.T) string { return e.code(t, e.none, func(c *tokens.Code) { c.JTI = "" }) }, nil, 400, "invalid_grant"},
		{"foreign client", func(t *testing.T) string { return e.code(t, e.post, nil) }, nil, 400, "invalid_grant"},
		{"upstream removed", func(t *testing.T) string {
			return e.code(t, e.none, func(c *tokens.Code) { c.Upstream = "gone" })
		}, nil, 400, "invalid_grant"},
		{"kind confusion", func(t *testing.T) string {
			s, err := e.srv.sealer.Seal(seal.KindRefresh, tokens.Refresh{Upstream: "tn", ClientID: e.none, Family: "x", Exp: 1}, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			return s
		}, nil, 400, "invalid_grant"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code := ""
			if tc.code != nil {
				code = tc.code(t)
			} else {
				code = e.code(t, e.none, nil)
			}
			f := e.codeForm(e.none, code)
			if tc.mod != nil {
				tc.mod(f)
			}
			e.wantErr(t, e.do(f), tc.status, tc.err)
		})
	}
}

func TestTokenResourceMatchAccepted(t *testing.T) {
	e := newTK(t)
	f := e.codeForm(e.none, e.code(t, e.none, nil))
	f.Set("resource", azRes)
	e.wantOK(t, e.do(f))
}

func TestTokenFailedValidationDoesNotBurnCode(t *testing.T) {
	e := newTK(t)
	code := e.code(t, e.none, nil)
	bad := e.codeForm(e.none, code)
	bad.Set("code_verifier", strings.Repeat("b", 43))
	e.wantErr(t, e.do(bad), 400, "invalid_grant")
	e.wantOK(t, e.do(e.codeForm(e.none, code)))
}

func TestTokenCodeReplay(t *testing.T) {
	e := newTK(t)
	code := e.code(t, e.none, nil)
	e.wantOK(t, e.do(e.codeForm(e.none, code)))
	e.wantErr(t, e.do(e.codeForm(e.none, code)), 400, "invalid_grant")
}

func TestTokenExpiredCode(t *testing.T) {
	e := newTK(t)
	code := e.code(t, e.none, nil)
	e.now.Add(int64(5 * 60)) // exactly code_ttl: expired
	e.wantErr(t, e.do(e.codeForm(e.none, code)), 400, "invalid_grant")
}

func TestTokenRedirectRevokedInConfig(t *testing.T) {
	e := newTK(t)
	code := e.code(t, e.none, nil)
	e.cfg.OAuth.AllowedRedirectURIs = []string{cbClaudeCom}
	e.wantErr(t, e.do(e.codeForm(e.none, code)), 400, "invalid_grant")
}

func TestTokenUpstreamRemovedFromConfig(t *testing.T) {
	e := newTK(t)
	code := e.code(t, e.none, nil)
	e.cfg.Upstreams = nil
	e.wantErr(t, e.do(e.codeForm(e.none, code)), 400, "invalid_grant")
}

func TestTokenCodeCacheOverflow(t *testing.T) {
	e := newTK(t)
	e.srv.codes = newReplayCache(2)
	for range 2 {
		e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	}
	rec := e.do(e.codeForm(e.none, e.code(t, e.none, nil)))
	e.wantErr(t, rec, http.StatusServiceUnavailable, "server_error")
	if rec.Header().Get("Retry-After") != "" {
		t.Error("Retry-After must not be set")
	}
	// Once the entries expire (and the sweep interval passed), exchanges resume.
	e.now.Add(int64(6 * 60))
	e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
}

func TestTokenRefresh(t *testing.T) {
	e := newTK(t)
	_, rt := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))

	e.now.Add(int64(10 * 60))
	access, rt2 := e.wantOK(t, e.do(e.refreshForm(e.none, rt)))
	if rt2 == rt {
		t.Error("refresh token not rotated")
	}
	if _, err := seal.OpenAs[tokens.Access](e.srv.sealer, seal.KindAccess, access); err != nil {
		t.Error(err)
	}
	// Sliding expiry: the new token outlives the old one's original expiry.
	e.now.Add(int64(719 * 3600))
	e.wantOK(t, e.do(e.refreshForm(e.none, rt2)))
}

// chainRefresh returns the family id and generation of a refresh token.
func (e *tkEnv) chainRefresh(t *testing.T, rt string) (string, int64) {
	t.Helper()
	r, err := seal.OpenAs[tokens.Refresh](e.srv.sealer, seal.KindRefresh, rt)
	if err != nil {
		t.Fatal(err)
	}
	return r.Family, r.Gen
}

func TestTokenRefreshChain(t *testing.T) {
	e := newTK(t)
	_, g0 := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	_, g1 := e.wantOK(t, e.do(e.refreshForm(e.none, g0)))
	_, g2 := e.wantOK(t, e.do(e.refreshForm(e.none, g1)))
	f0, n0 := e.chainRefresh(t, g0)
	f2, n2 := e.chainRefresh(t, g2)
	if f0 != f2 || n0 != 0 || n2 != 2 {
		t.Errorf("chain = (%s,%d) -> (%s,%d)", f0, n0, f2, n2)
	}
	e.wantOK(t, e.do(e.refreshForm(e.none, g2)))
}

func TestTokenRefreshReuseRevokesFamily(t *testing.T) {
	e := newTK(t)
	_, g0 := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	_, g1 := e.wantOK(t, e.do(e.refreshForm(e.none, g0)))
	// Replaying G0 after G1 was issued is a reuse ...
	e.wantErr(t, e.do(e.refreshForm(e.none, g0)), 400, "invalid_grant")
	// ... and revokes the whole family, including the legitimate successor.
	e.wantErr(t, e.do(e.refreshForm(e.none, g1)), 400, "invalid_grant")
	e.wantErr(t, e.do(e.refreshForm(e.none, g0)), 400, "invalid_grant")
}

func TestTokenRefreshFamiliesIndependent(t *testing.T) {
	e := newTK(t)
	_, a0 := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	_, b0 := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	e.wantOK(t, e.do(e.refreshForm(e.none, a0)))
	e.wantErr(t, e.do(e.refreshForm(e.none, a0)), 400, "invalid_grant")
	e.wantOK(t, e.do(e.refreshForm(e.none, b0)))
	// a is revoked (kept in the revocation set), b is active.
	if len(e.srv.families.seen) != 1 || len(e.srv.families.revs.exp) != 1 {
		t.Errorf("active = %d, revoked = %d, want 1 and 1", len(e.srv.families.seen), len(e.srv.families.revs.exp))
	}
}

func TestTokenRefreshLoopOneEntry(t *testing.T) {
	e := newTK(t)
	_, rt := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	for range 20 {
		_, rt = e.wantOK(t, e.do(e.refreshForm(e.none, rt)))
	}
	if n := len(e.srv.families.seen); n != 1 {
		t.Errorf("family entries = %d, want 1", n)
	}
}

func TestTokenRefreshAfterRestart(t *testing.T) {
	e := newTK(t)
	_, g0 := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	e.wantOK(t, e.do(e.refreshForm(e.none, g0)))
	e.srv.families = newFamilyCache(maxFamilyEntries) // process restart
	// Documented window: the spent token is accepted once more.
	e.wantOK(t, e.do(e.refreshForm(e.none, g0)))
}

func TestTokenCodeConcurrent(t *testing.T) {
	e := newTK(t)
	code := e.code(t, e.none, nil)
	if ok, rejected := e.race(16, e.codeForm(e.none, code)); ok != 1 || rejected != 15 {
		t.Fatalf("ok = %d, rejected = %d", ok, rejected)
	}
}

// race fires n identical requests at once and counts 200s and 400s.
func (e *tkEnv) race(n int, form url.Values) (ok, rejected int32) {
	var okN, badN atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			switch e.do(form).Code {
			case http.StatusOK:
				okN.Add(1)
			case http.StatusBadRequest:
				badN.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	return okN.Load(), badN.Load()
}

func TestTokenRefreshConcurrent(t *testing.T) {
	e := newTK(t)
	_, rt := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	if ok, rejected := e.race(16, e.refreshForm(e.none, rt)); ok != 1 || rejected != 15 {
		t.Fatalf("ok = %d, rejected = %d", ok, rejected)
	}
}

func TestTokenRefreshCacheOverflow(t *testing.T) {
	e := newTK(t)
	e.srv.families = newFamilyCache(1)
	_, a0 := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	_, b0 := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	_, a1 := e.wantOK(t, e.do(e.refreshForm(e.none, a0))) // family A takes the only slot
	// A full cache evicts instead of failing: B is accepted, A is evicted.
	_, b1 := e.wantOK(t, e.do(e.refreshForm(e.none, b0)))
	e.wantOK(t, e.do(e.refreshForm(e.none, b1)))
	// Documented trade-off: evicted A is accepted again as a new family.
	e.wantOK(t, e.do(e.refreshForm(e.none, a1)))
}

func TestTokenRefreshRejections(t *testing.T) {
	e := newTK(t)
	_, rt := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	seed := func(mod func(*tokens.Refresh)) string {
		now := time.Unix(e.now.Load(), 0)
		r := tokens.Refresh{Upstream: "tn", ClientID: e.none, Creds: map[string]string{"X-Api-Key": "sekret"}, Family: "seed", Exp: now.Add(time.Hour).Unix()}
		mod(&r)
		s, err := e.srv.sealer.Seal(seal.KindRefresh, r, time.Unix(r.Exp, 0))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Run("foreign client", func(t *testing.T) {
		f := e.refreshForm(e.post, rt)
		f.Set("client_secret", e.srv.clientSecret(e.post))
		e.wantErr(t, e.do(f), 400, "invalid_grant")
	})
	t.Run("no family", func(t *testing.T) {
		e.wantErr(t, e.do(e.refreshForm(e.none, seed(func(r *tokens.Refresh) { r.Family = "" }))), 400, "invalid_grant")
	})
	t.Run("upstream removed", func(t *testing.T) {
		e.wantErr(t, e.do(e.refreshForm(e.none, seed(func(r *tokens.Refresh) { r.Upstream = "gone" }))), 400, "invalid_grant")
	})
	t.Run("resource mismatch", func(t *testing.T) {
		f := e.refreshForm(e.none, seed(func(r *tokens.Refresh) { r.Family = "res" }))
		f.Set("resource", "https://mcp.example.com/other")
		e.wantErr(t, e.do(f), 400, "invalid_target")
	})
	t.Run("missing token", func(t *testing.T) {
		f := e.refreshForm(e.none, rt)
		f.Del("refresh_token")
		e.wantErr(t, e.do(f), 400, "invalid_request")
	})
	t.Run("code used as refresh", func(t *testing.T) {
		e.wantErr(t, e.do(e.refreshForm(e.none, e.code(t, e.none, nil))), 400, "invalid_grant")
	})
	t.Run("access used as refresh", func(t *testing.T) {
		acc, _ := e.wantOK(t, e.do(e.refreshForm(e.none, seed(func(r *tokens.Refresh) { r.Family = "acc" }))))
		e.wantErr(t, e.do(e.refreshForm(e.none, acc)), 400, "invalid_grant")
	})
	t.Run("expired", func(t *testing.T) {
		old := seed(func(r *tokens.Refresh) { r.Family = "exp" })
		e.now.Add(2 * 3600)
		e.wantErr(t, e.do(e.refreshForm(e.none, old)), 400, "invalid_grant")
	})
}

func TestTokenRequestErrors(t *testing.T) {
	e := newTK(t)
	t.Run("unsupported grant", func(t *testing.T) {
		f := e.codeForm(e.none, "x")
		f.Set("grant_type", "password")
		e.wantErr(t, e.do(f), 400, "unsupported_grant_type")
	})
	t.Run("missing grant", func(t *testing.T) {
		e.wantErr(t, e.do(url.Values{"client_id": {e.none}}), 400, "invalid_request")
	})
	t.Run("duplicate grant_type", func(t *testing.T) {
		f := e.codeForm(e.none, "x")
		f.Add("grant_type", "refresh_token")
		e.wantErr(t, e.do(f), 400, "invalid_request")
	})
	t.Run("invalid client", func(t *testing.T) {
		rec := e.do(e.codeForm("bogus", "x"))
		e.wantErr(t, rec, 401, "invalid_client")
		if rec.Header().Get("WWW-Authenticate") != "" {
			t.Error("unexpected WWW-Authenticate")
		}
	})
	t.Run("invalid client basic", func(t *testing.T) {
		f := e.codeForm(e.bas, "x")
		f.Del("client_id")
		rec := e.do(f, "Authorization", basicHdr(e.bas, "wrong"))
		e.wantErr(t, rec, 401, "invalid_client")
		if !strings.HasPrefix(rec.Header().Get("WWW-Authenticate"), "Basic") {
			t.Errorf("WWW-Authenticate = %q", rec.Header().Get("WWW-Authenticate"))
		}
	})
	t.Run("secret client without secret", func(t *testing.T) {
		e.wantErr(t, e.do(e.codeForm(e.post, "x")), 401, "invalid_client")
	})
	t.Run("wrong content type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, PathToken, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, req)
		e.wantErr(t, rec, 400, "invalid_request")
	})
	t.Run("oversized body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, PathToken, strings.NewReader("a="+strings.Repeat("x", maxTokenBody)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, req)
		e.wantErr(t, rec, 413, "invalid_request")
	})
	t.Run("query params ignored", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, PathToken+"?client_id="+url.QueryEscape(e.none)+"&grant_type=refresh_token", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, req)
		e.wantErr(t, rec, 401, "invalid_client")
	})
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodOptions} {
		t.Run("method "+m, func(t *testing.T) {
			req := httptest.NewRequest(m, PathToken, nil)
			rec := httptest.NewRecorder()
			e.mux.ServeHTTP(rec, req)
			e.wantErr(t, rec, 405, "invalid_request")
			if rec.Header().Get("Allow") != "POST" {
				t.Errorf("Allow = %q", rec.Header().Get("Allow"))
			}
		})
	}
}

func TestReplayCacheSweep(t *testing.T) {
	c := newReplayCache(2)
	now := fixedNow
	exp := now.Add(time.Minute)
	if err := c.claim("a", exp, now); err != nil {
		t.Fatal(err)
	}
	if err := c.claim("a", exp, now); err != errReplayed {
		t.Fatalf("err = %v", err)
	}
	if err := c.claim("b", exp, now); err != nil {
		t.Fatal(err)
	}
	if err := c.claim("c", exp, now); err != errReplayCacheFull {
		t.Fatalf("err = %v", err)
	}
	// Boundary: an entry is dead exactly when the seal envelope starts
	// rejecting the token (now >= exp), so the id may be claimed again then.
	if err := c.claim("a", exp, exp.Add(-time.Second)); err != errReplayed {
		t.Fatalf("before exp: err = %v", err)
	}
	if err := c.claim("a", exp.Add(time.Minute), exp); err != nil {
		t.Fatalf("at exp: err = %v", err)
	}
	// After expiry the old ids are evicted and a reused id is accepted again
	// (its token is expired, so the seal envelope rejects it anyway).
	later := now.Add(2 * time.Minute)
	if err := c.claim("c", later.Add(time.Minute), later); err != nil {
		t.Fatal(err)
	}
	if err := c.claim("a", later.Add(time.Minute), later); err != nil {
		t.Fatal(err)
	}
}

func TestFamilyCacheBoundary(t *testing.T) {
	c := newFamilyCache(1)
	now := fixedNow
	exp := now.Add(time.Hour)
	if _, err := c.use("f", 0, exp, now); err != nil {
		t.Fatal(err)
	}
	// At now == exp the family is dead (its newest token is expired too), so
	// its slot is free and the same generation counts as new.
	if _, err := c.use("f", 0, exp.Add(time.Hour), exp); err != nil {
		t.Fatalf("at exp: err = %v", err)
	}
	if _, err := c.use("g", 0, exp.Add(time.Hour), exp); err != nil {
		t.Fatalf("at exp: err = %v", err)
	}
	if reuse, err := c.use("g", 0, exp.Add(time.Hour), exp); !reuse || err != errFamilyRevoked {
		t.Fatalf("reuse = %v, err = %v", reuse, err)
	}
	if reuse, err := c.use("g", 5, exp.Add(time.Hour), exp); reuse || err != errFamilyRevoked {
		t.Fatalf("revoked: reuse = %v, err = %v", reuse, err)
	}
}

func TestFamilyExpiryNeverShortens(t *testing.T) {
	c := newFamilyCache(10)
	now := fixedNow
	long, short := now.Add(10*time.Hour), now.Add(time.Hour)
	if _, err := c.use("f", 0, long, now); err != nil {
		t.Fatal(err)
	}
	if _, err := c.use("f", 1, short, now); err != nil { // TTL lowered
		t.Fatal(err)
	}
	if got := c.seen["f"].exp; !got.Equal(long) {
		t.Fatalf("exp = %v, want %v", got, long)
	}
	// The old token is still within its lifetime: reuse must be detected.
	if reuse, err := c.use("f", 0, short, now.Add(2*time.Hour)); !reuse || err != errFamilyRevoked {
		t.Fatalf("reuse = %v, err = %v", reuse, err)
	}
}

func TestTokenRefreshTTLLoweredKeepsEntry(t *testing.T) {
	e := newTK(t)
	_, g0 := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	e.cfg.OAuth.RefreshTokenTTL = time.Hour
	_, g1 := e.wantOK(t, e.do(e.refreshForm(e.none, g0)))
	e.now.Add(2 * 3600) // past the new TTL, g0 still valid (30d)
	e.wantErr(t, e.do(e.refreshForm(e.none, g0)), 400, "invalid_grant")
	e.wantErr(t, e.do(e.refreshForm(e.none, g1)), 400, "invalid_grant") // expired anyway or revoked
}

// A full revocation set refuses unknown families with 503, never a token.
func TestTokenRefreshRevocationSetFull(t *testing.T) {
	e := newTK(t)
	_, g0 := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	e.srv.families.revs = newRevocationSet(1)
	e.srv.families.revs.add(1, fixedNow.Add(24*time.Hour), fixedNow)
	e.wantErr(t, e.do(e.refreshForm(e.none, g0)), 503, "server_error")
}

// refreshPayload opens a refresh token issued by e.
func (e *tkEnv) refreshPayload(t *testing.T, rt string) tokens.Refresh {
	t.Helper()
	r, err := seal.OpenAs[tokens.Refresh](e.srv.sealer, seal.KindRefresh, rt)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTokenSessionStartPreserved(t *testing.T) {
	e := newTK(t)
	_, rt := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	start := e.refreshPayload(t, rt).Start
	if start != fixedNow.Unix() {
		t.Fatalf("Start = %d, want %d", start, fixedNow.Unix())
	}
	for i := 0; i < 3; i++ {
		e.now.Add(int64(24 * 3600))
		_, rt = e.wantOK(t, e.do(e.refreshForm(e.none, rt)))
		if got := e.refreshPayload(t, rt).Start; got != start {
			t.Fatalf("rotation %d: Start = %d, want %d", i, got, start)
		}
	}
}

func TestTokenSessionLifetimeExceeded(t *testing.T) {
	e := newTK(t)
	e.cfg.OAuth.MaxSessionTTL = 100 * time.Hour
	_, rt := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	// Slide the chain forward within the window.
	e.now.Add(int64(90 * 3600))
	_, rt = e.wantOK(t, e.do(e.refreshForm(e.none, rt)))
	// Exactly at session end: rejected, though refresh_token_ttl (720h) is not.
	e.now.Add(int64(10 * 3600))
	e.wantErr(t, e.do(e.refreshForm(e.none, rt)), 400, "invalid_grant")
}

func TestTokenSessionExpiryCapped(t *testing.T) {
	e := newTK(t)
	e.cfg.OAuth.MaxSessionTTL = 100 * time.Hour
	_, rt := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	end := fixedNow.Unix() + 100*3600

	// 99.5h in: 30 minutes of session left, less than the 1h access TTL.
	e.now.Add(int64(99*3600 + 1800))
	rec := e.do(e.refreshForm(e.none, rt))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body %s", rec.Code, rec.Body)
	}
	m := decodeTK(t, rec)
	if m["expires_in"] != float64(1800) {
		t.Errorf("expires_in = %v, want 1800", m["expires_in"])
	}
	rt2, _ := m["refresh_token"].(string)
	r := e.refreshPayload(t, rt2)
	if r.Exp != end {
		t.Errorf("refresh Exp = %d, want session end %d", r.Exp, end)
	}
	// The seal envelope expires with the session as well.
	e.now.Add(1800)
	e.wantErr(t, e.do(e.refreshForm(e.none, rt2)), 400, "invalid_grant")
	acc, _ := m["access_token"].(string)
	e.now.Store(end - 1)
	if _, err := seal.OpenAs[tokens.Access](e.srv.sealer, seal.KindAccess, acc); err != nil {
		t.Errorf("access token must be valid until session end: %v", err)
	}
	e.now.Store(end)
	if _, err := seal.OpenAs[tokens.Access](e.srv.sealer, seal.KindAccess, acc); err == nil {
		t.Error("access token must expire at session end")
	}
}

func TestTokenSessionLegacyRefreshMigrates(t *testing.T) {
	e := newTK(t)
	e.cfg.OAuth.MaxSessionTTL = 100 * time.Hour
	exp := time.Unix(e.now.Load(), 0).Add(time.Hour)
	legacy, err := e.srv.sealer.Seal(seal.KindRefresh, tokens.Refresh{
		Upstream: "tn", ClientID: e.none, Creds: map[string]string{"X-Api-Key": "sekret"},
		Family: "legacy", Exp: exp.Unix(), // no Start
	}, exp)
	if err != nil {
		t.Fatal(err)
	}
	_, rt := e.wantOK(t, e.do(e.refreshForm(e.none, legacy)))
	if got := e.refreshPayload(t, rt).Start; got != fixedNow.Unix() {
		t.Fatalf("migrated Start = %d, want now (%d)", got, fixedNow.Unix())
	}
	// The migrated chain is now bounded.
	e.now.Add(int64(100 * 3600))
	e.wantErr(t, e.do(e.refreshForm(e.none, rt)), 400, "invalid_grant")
}

func TestTokenSessionNegativeStartRejected(t *testing.T) {
	e := newTK(t)
	exp := time.Unix(e.now.Load(), 0).Add(time.Hour)
	bad, err := e.srv.sealer.Seal(seal.KindRefresh, tokens.Refresh{
		Upstream: "tn", ClientID: e.none, Creds: map[string]string{"X-Api-Key": "sekret"},
		Family: "neg", Exp: exp.Unix(), Start: -5,
	}, exp)
	if err != nil {
		t.Fatal(err)
	}
	e.wantErr(t, e.do(e.refreshForm(e.none, bad)), 400, "invalid_grant")
}

// sealRefresh seals r as a refresh token expiring at r.Exp.
func (e *tkEnv) sealRefresh(t *testing.T, r tokens.Refresh) string {
	t.Helper()
	s, err := e.srv.sealer.Seal(seal.KindRefresh, r, time.Unix(r.Exp, 0))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTokenSessionSubSecondEnd(t *testing.T) {
	e := newTK(t)
	e.cfg.OAuth.MaxSessionTTL = 100 * time.Hour
	_, rt := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	end := fixedNow.Unix() + 100*3600
	// The server clock carries sub-second precision, the sealer's does not.
	e.srv.now = func() time.Time { return time.Unix(end-1, 500_000_000) }
	e.now.Store(end - 1)
	rec := e.do(e.refreshForm(e.none, rt))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body %s", rec.Code, rec.Body)
	}
	if got, _ := decodeTK(t, rec)["expires_in"].(float64); got < 1 {
		t.Errorf("expires_in = %v, want >= 1", got)
	}
}

func TestTokenSessionBoundary(t *testing.T) {
	e := newTK(t)
	e.cfg.OAuth.MaxSessionTTL = 100 * time.Hour
	_, rt := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	e.now.Add(100*3600 - 1) // one second before the session end
	rec := e.do(e.refreshForm(e.none, rt))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body %s", rec.Code, rec.Body)
	}
	if got := decodeTK(t, rec)["expires_in"]; got != float64(1) {
		t.Errorf("expires_in = %v, want 1", got)
	}
}

func TestTokenSessionStartRange(t *testing.T) {
	e := newTK(t)
	now := e.now.Load()
	seed := func(fam string, start int64) string {
		return e.sealRefresh(t, tokens.Refresh{
			Upstream: "tn", ClientID: e.none, Creds: map[string]string{"X-Api-Key": "sekret"},
			Family: fam, Exp: now + 3600, Start: start,
		})
	}
	e.wantErr(t, e.do(e.refreshForm(e.none, seed("far", now+6*60))), 400, "invalid_grant")
	e.wantErr(t, e.do(e.refreshForm(e.none, seed("max", math.MaxInt64-10))), 400, "invalid_grant")
	_, rt := e.wantOK(t, e.do(e.refreshForm(e.none, seed("skew", now+4*60))))
	if got := e.refreshPayload(t, rt).Start; got != now+4*60 {
		t.Errorf("Start = %d, want it preserved", got)
	}
}

func TestTokenSessionKeepsLongerCacheEntry(t *testing.T) {
	e := newTK(t)
	e.cfg.OAuth.MaxSessionTTL = 100 * time.Hour
	now := e.now.Load()
	oldExp := now + 500*3600 // as if refresh_token_ttl was larger when issued
	rt := e.sealRefresh(t, tokens.Refresh{
		Upstream: "tn", ClientID: e.none, Creds: map[string]string{"X-Api-Key": "sekret"},
		Family: "longer", Exp: oldExp, Start: now,
	})
	_, rt2 := e.wantOK(t, e.do(e.refreshForm(e.none, rt)))
	if got := e.refreshPayload(t, rt2).Exp; got != now+100*3600 {
		t.Fatalf("new token Exp = %d, want capped %d", got, now+100*3600)
	}
	c := e.srv.families
	c.mu.Lock()
	f := c.seen["longer"]
	c.mu.Unlock()
	if f == nil || f.exp.Unix() != oldExp {
		t.Errorf("cache entry exp = %v, want the old Exp %d", f, oldExp)
	}
}

func TestTokenSessionLegacyReplayRevokes(t *testing.T) {
	e := newTK(t)
	now := e.now.Load()
	legacy := e.sealRefresh(t, tokens.Refresh{
		Upstream: "tn", ClientID: e.none, Creds: map[string]string{"X-Api-Key": "sekret"},
		Family: "legacy-replay", Exp: now + 3600,
	})
	_, rt := e.wantOK(t, e.do(e.refreshForm(e.none, legacy)))
	e.wantErr(t, e.do(e.refreshForm(e.none, legacy)), 400, "invalid_grant")
	// Reuse revoked the whole family, including the migrated chain.
	e.wantErr(t, e.do(e.refreshForm(e.none, rt)), 400, "invalid_grant")
}
