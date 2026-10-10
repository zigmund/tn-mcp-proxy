package oauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
)

const (
	cbClaudeAI  = "https://claude.ai/api/mcp/auth_callback"
	cbClaudeCom = "https://claude.com/api/mcp/auth_callback"
)

var fixedNow = time.Unix(1_800_000_000, 0)

func testSealer(t *testing.T, secrets ...byte) *seal.Sealer {
	t.Helper()
	var keys [][]byte
	for _, b := range secrets {
		keys = append(keys, []byte(strings.Repeat(string(rune('a'+b)), 32)))
	}
	s, err := seal.New(keys)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testServer(t *testing.T, allowed ...string) (*Server, *http.ServeMux) {
	t.Helper()
	if len(allowed) == 0 {
		allowed = []string{cbClaudeAI, cbClaudeCom}
	}
	cfg := &config.Config{
		PublicURL: "https://mcp.example.com",
		OAuth:     config.OAuth{AllowedRedirectURIs: allowed},
	}
	srv := New(cfg, testSealer(t, 0), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv.now = func() time.Time { return fixedNow }
	mux := http.NewServeMux()
	srv.Register(mux)
	return srv, mux
}

func postJSON(mux *http.ServeMux, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, PathRegister, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestRegisterSuccess(t *testing.T) {
	both := []string{"authorization_code", "refresh_token"}
	tests := []struct {
		name       string
		body       string
		wantMethod string
		wantSecret bool
		wantGrants []string
		wantURIs   []string
		wantName   string
	}{
		{"default method is basic", `{"redirect_uris":["` + cbClaudeAI + `"]}`, authClientSecretBasic, true, both, []string{cbClaudeAI}, ""},
		{"basic explicit", `{"redirect_uris":["` + cbClaudeAI + `"],"token_endpoint_auth_method":"client_secret_basic"}`, authClientSecretBasic, true, both, []string{cbClaudeAI}, ""},
		{"post", `{"redirect_uris":["` + cbClaudeAI + `"],"token_endpoint_auth_method":"client_secret_post"}`, authClientSecretPost, true, both, []string{cbClaudeAI}, ""},
		{"none", `{"redirect_uris":["` + cbClaudeAI + `"],"token_endpoint_auth_method":"none"}`, authNone, false, both, []string{cbClaudeAI}, ""},
		{"subset grants, dup uris, name, unknown fields",
			`{"redirect_uris":["` + cbClaudeAI + `","` + cbClaudeCom + `","` + cbClaudeAI + `"],"grant_types":["authorization_code"],` +
				`"response_types":["code"],"client_name":"  Claude  ","scope":"x y","software_id":"abc","token_endpoint_auth_method":"none"}`,
			authNone, false, []string{"authorization_code"}, []string{cbClaudeAI, cbClaudeCom}, "Claude"},
		{"empty arrays use defaults", `{"redirect_uris":["` + cbClaudeAI + `"],"grant_types":[],"response_types":[]}`, authClientSecretBasic, true, both, []string{cbClaudeAI}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, mux := testServer(t)
			rec := postJSON(mux, "application/json; charset=utf-8", tc.body)
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
			}
			h := rec.Header()
			if h.Get("Cache-Control") != "no-store" || h.Get("Pragma") != "no-cache" ||
				h.Get("Access-Control-Allow-Origin") != "*" || h.Get("Content-Type") != "application/json" {
				t.Errorf("headers = %v", h)
			}
			resp := decode[map[string]any](t, rec)
			id, _ := resp["client_id"].(string)
			c, err := srv.openClient(id)
			if err != nil {
				t.Fatalf("openClient: %v", err)
			}
			want := client{RedirectURIs: tc.wantURIs, Name: tc.wantName, AuthMethod: tc.wantMethod, IssuedAt: fixedNow.Unix()}
			if !reflect.DeepEqual(c, want) {
				t.Errorf("client = %+v, want %+v", c, want)
			}
			secret, hasSecret := resp["client_secret"].(string)
			_, hasExp := resp["client_secret_expires_at"]
			if hasSecret != tc.wantSecret || hasExp != tc.wantSecret {
				t.Errorf("secret present = %v, expires present = %v, want %v", hasSecret, hasExp, tc.wantSecret)
			}
			if hasSecret && (secret != srv.clientSecret(id) || resp["client_secret_expires_at"] != float64(0)) {
				t.Errorf("secret/expiry wrong: %v", resp)
			}
			if resp["client_id_issued_at"] != float64(fixedNow.Unix()) || resp["token_endpoint_auth_method"] != tc.wantMethod {
				t.Errorf("resp = %v", resp)
			}
			if !reflect.DeepEqual(toStrings(resp["grant_types"]), tc.wantGrants) ||
				!reflect.DeepEqual(toStrings(resp["response_types"]), []string{"code"}) ||
				!reflect.DeepEqual(toStrings(resp["redirect_uris"]), tc.wantURIs) {
				t.Errorf("resp = %v", resp)
			}
			if name, _ := resp["client_name"].(string); name != tc.wantName {
				t.Errorf("client_name = %q", name)
			}
		})
	}
}

func toStrings(v any) []string {
	var out []string
	for _, e := range v.([]any) {
		out = append(out, e.(string))
	}
	return out
}

func TestRegisterErrors(t *testing.T) {
	uri := `"` + cbClaudeAI + `"`
	eleven := strings.TrimSuffix(strings.Repeat(uri+",", 11), ",")
	tests := []struct {
		name       string
		ctype      string
		body       string
		wantStatus int
		wantErr    string
	}{
		{"foreign redirect", "application/json", `{"redirect_uris":["https://evil.example/cb"]}`, 400, "invalid_redirect_uri"},
		{"prefix of allowed", "application/json", `{"redirect_uris":["` + cbClaudeAI + `/x"]}`, 400, "invalid_redirect_uri"},
		{"one foreign among valid", "application/json", `{"redirect_uris":[` + uri + `,"https://evil.example/cb"]}`, 400, "invalid_redirect_uri"},
		{"missing redirect_uris", "application/json", `{}`, 400, "invalid_redirect_uri"},
		{"zero redirect_uris", "application/json", `{"redirect_uris":[]}`, 400, "invalid_redirect_uri"},
		// 11 copies of one valid URI: the count limit applies to the raw list, before dedupe.
		{"eleven redirect_uris", "application/json", `{"redirect_uris":[` + eleven + `]}`, 400, "invalid_redirect_uri"},
		{"bad auth method", "application/json", `{"redirect_uris":[` + uri + `],"token_endpoint_auth_method":"private_key_jwt"}`, 400, "invalid_client_metadata"},
		{"empty auth method", "application/json", `{"redirect_uris":[` + uri + `],"token_endpoint_auth_method":""}`, 400, "invalid_client_metadata"},
		{"bad grant type", "application/json", `{"redirect_uris":[` + uri + `],"grant_types":["authorization_code","password"]}`, 400, "invalid_client_metadata"},
		{"code without authorization_code", "application/json", `{"redirect_uris":[` + uri + `],"grant_types":["refresh_token"]}`, 400, "invalid_client_metadata"},
		{"trailing json", "application/json", `{"redirect_uris":[` + uri + `]} {}`, 400, "invalid_client_metadata"},
		{"trailing garbage", "application/json", `{"redirect_uris":[` + uri + `]}x`, 400, "invalid_client_metadata"},
		{"bad response type", "application/json", `{"redirect_uris":[` + uri + `],"response_types":["token"]}`, 400, "invalid_client_metadata"},
		{"wrong type for redirect_uris", "application/json", `{"redirect_uris":"x"}`, 400, "invalid_client_metadata"},
		{"malformed json", "application/json", `{"redirect_uris":[`, 400, "invalid_client_metadata"},
		{"empty body", "application/json", ``, 400, "invalid_client_metadata"},
		{"oversized body", "application/json", `{"client_name":"` + strings.Repeat("a", 70<<10) + `"}`, 400, "invalid_client_metadata"},
		{"form content type", "application/x-www-form-urlencoded", `redirect_uris=x`, 415, "invalid_client_metadata"},
		{"missing content type", "", `{"redirect_uris":[` + uri + `]}`, 415, "invalid_client_metadata"},
		{"garbage content type", "json;;", `{}`, 415, "invalid_client_metadata"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, mux := testServer(t)
			rec := postJSON(mux, tc.ctype, tc.body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.wantStatus, rec.Body)
			}
			got := decode[oauthError](t, rec)
			if got.Error != tc.wantErr || got.Description == "" {
				t.Errorf("error = %+v, want %s", got, tc.wantErr)
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Type") != "application/json" {
				t.Errorf("headers = %v", rec.Header())
			}
		})
	}
}

func TestRegisterMethodNotAllowed(t *testing.T) {
	_, mux := testServer(t)
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(m, PathRegister, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d", m, rec.Code)
		}
	}
}

func TestRegisterPreflight(t *testing.T) {
	_, mux := testServer(t)
	rec := do(mux, http.MethodOptions, PathRegister)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	h := rec.Header()
	if h.Get("Access-Control-Allow-Origin") != "*" ||
		h.Get("Access-Control-Allow-Methods") != "POST, OPTIONS" ||
		!strings.Contains(h.Get("Access-Control-Allow-Headers"), "Content-Type") {
		t.Errorf("headers = %v", h)
	}
	// Metadata preflight must stay GET-only.
	if got := do(mux, http.MethodOptions, PathAuthServerMetadata).Header().Get("Access-Control-Allow-Methods"); got != "GET, HEAD, OPTIONS" {
		t.Errorf("metadata Allow-Methods = %q", got)
	}
}

func TestSanitizeClientName(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"plain", "Claude", "Claude"},
		{"trim", " \t Claude \n", "Claude"},
		{"control chars", "Cla\x00u\x07de\r\nAI", "ClaudeAI"},
		{"bidi and zero width", "a\u202eb\u200bc", "abc"},
		{"html kept for template escaping", "<b>x</b>", "<b>x</b>"},
		{"empty after strip", "\x01\x02", ""},
		{"line separators", "a\u2028b\u2029c\u00a0d\u3000e", "abcde"},
		{"hangul fillers", "a\u3164b\u115fc\u1160d\uffa0e", "abcde"},
		{"collapse spaces", "a   b    c", "a b c"},
		{"only fillers", "\u3164\u3164", ""},
		{"cap runes", strings.Repeat("я", 150), strings.Repeat("я", 100)},
		{"cap then trim", strings.Repeat("a", 99) + " b", strings.Repeat("a", 99)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeClientName(tc.in); got != tc.want {
				t.Errorf("sanitizeClientName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestOpenClient(t *testing.T) {
	srv, mux := testServer(t)
	rec := postJSON(mux, "application/json", `{"redirect_uris":["`+cbClaudeAI+`"]}`)
	id := decode[registerResponse](t, rec).ClientID

	if _, err := srv.openClient(id); err != nil {
		t.Fatalf("openClient: %v", err)
	}
	flipped := []byte(id)
	flipped[len(flipped)/2] ^= 1
	foreign, err := srv.sealer.Seal(seal.KindCode, client{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	other := New(srv.cfg, testSealer(t, 1), nil)
	badPayload, err := srv.sealer.Seal(seal.KindClient, "not an object", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"tampered":     string(flipped),
		"empty":        "",
		"garbage":      "not-a-token",
		"other kind":   foreign,
		"other keys":   id, // opened by the server below
		"truncated":    id[:len(id)-4],
		"extra suffix": id + "AAAA",
	} {
		s := srv
		if name == "other keys" {
			s = other
		}
		if _, err := s.openClient(bad); !errors.Is(err, errInvalidClient) {
			t.Errorf("%s: err = %v, want errInvalidClient", name, err)
		}
	}
	if _, err := srv.openClient(badPayload); err == nil || errors.Is(err, errInvalidClient) || !errors.Is(err, seal.ErrPayload) {
		t.Errorf("bad payload: err = %v, want a server error wrapping ErrPayload", err)
	}
}

func TestRedirectAllowed(t *testing.T) {
	srv, mux := testServer(t)
	rec := postJSON(mux, "application/json", `{"redirect_uris":["`+cbClaudeAI+`"]}`)
	c, err := srv.openClient(decode[registerResponse](t, rec).ClientID)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		uri       string
		recordOK  bool
		allowedOK bool
	}{
		{cbClaudeAI, true, true},
		{cbClaudeCom, false, false}, // allowed by config but not registered
		{cbClaudeAI + "/", false, false},
		{strings.ToUpper(cbClaudeAI), false, false},
		{"", false, false},
	}
	for _, tc := range tests {
		if got := c.allowsRedirect(tc.uri); got != tc.recordOK {
			t.Errorf("allowsRedirect(%q) = %v, want %v", tc.uri, got, tc.recordOK)
		}
		if got := srv.redirectAllowed(c, tc.uri); got != tc.allowedOK {
			t.Errorf("redirectAllowed(%q) = %v, want %v", tc.uri, got, tc.allowedOK)
		}
	}

	// Removing the URI from config revokes it for the existing client.
	srv.cfg.OAuth.AllowedRedirectURIs = []string{cbClaudeCom}
	if !c.allowsRedirect(cbClaudeAI) {
		t.Error("record check must not depend on config")
	}
	if srv.redirectAllowed(c, cbClaudeAI) {
		t.Error("redirect still allowed after config removal")
	}
}

func basicHeader(id, secret string) string {
	cred := url.QueryEscape(id) + ":" + url.QueryEscape(secret)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(cred))
}

func tokenReq(header string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	return req
}

func registerClient(t *testing.T, mux *http.ServeMux, method string) (id, secret string) {
	t.Helper()
	body := `{"redirect_uris":["` + cbClaudeAI + `"],"token_endpoint_auth_method":"` + method + `"}`
	rec := postJSON(mux, "application/json", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	resp := decode[registerResponse](t, rec)
	return resp.ClientID, resp.ClientSecret
}

func TestAuthenticateClient(t *testing.T) {
	srv, mux := testServer(t)
	basicID, basicSecret := registerClient(t, mux, authClientSecretBasic)
	postID, postSecret := registerClient(t, mux, authClientSecretPost)
	noneID, _ := registerClient(t, mux, authNone)
	wrongSecret := base64.RawURLEncoding.EncodeToString(srv.sealer.MAC("client_secret", []byte("other")))

	tests := []struct {
		name      string
		header    string
		form      url.Values
		wantID    string
		wantAuth  string // expected c.AuthMethod on success
		wantErr   bool
		wantBasic bool
	}{
		{"basic ok", basicHeader(basicID, basicSecret), nil, basicID, authClientSecretBasic, false, false},
		{"basic ok with matching form client_id", basicHeader(basicID, basicSecret), url.Values{"client_id": {basicID}}, basicID, authClientSecretBasic, false, false},
		{"basic lowercase scheme", "basic " + strings.TrimPrefix(basicHeader(basicID, basicSecret), "Basic "), nil, basicID, authClientSecretBasic, false, false},
		{"post ok", "", url.Values{"client_id": {postID}, "client_secret": {postSecret}}, postID, authClientSecretPost, false, false},
		{"none ok", "", url.Values{"client_id": {noneID}}, noneID, authNone, false, false},

		{"basic wrong secret", basicHeader(basicID, wrongSecret), nil, "", "", true, true},
		{"basic empty secret", basicHeader(basicID, ""), nil, "", "", true, true},
		{"basic garbage secret", basicHeader(basicID, "!!!"), nil, "", "", true, true},
		{"basic secret of another client", basicHeader(basicID, srv.clientSecret(postID)), nil, "", "", true, true},
		{"basic unknown id", basicHeader("nope", basicSecret), nil, "", "", true, true},
		{"basic form client_id mismatch", basicHeader(basicID, basicSecret), url.Values{"client_id": {postID}}, "", "", true, true},
		{"basic plus form secret", basicHeader(basicID, basicSecret), url.Values{"client_secret": {basicSecret}}, "", "", true, true},
		{"basic plus form secret, none client", basicHeader(noneID, ""), url.Values{"client_secret": {"x"}}, "", "", true, true},
		{"basic not base64", "Basic !!!not-base64", nil, "", "", true, true},
		{"basic no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")), nil, "", "", true, true},
		{"basic bad percent encoding", "Basic " + base64.StdEncoding.EncodeToString([]byte("%zz:abc")), nil, "", "", true, true},
		{"basic no credentials", "Basic", nil, "", "", true, true},
		{"bearer scheme", "Bearer abc", nil, "", "", true, true},

		{"post wrong secret", "", url.Values{"client_id": {postID}, "client_secret": {wrongSecret}}, "", "", true, false},
		{"post empty secret", "", url.Values{"client_id": {postID}, "client_secret": {""}}, "", "", true, false},
		{"post missing secret", "", url.Values{"client_id": {postID}}, "", "", true, false},
		{"post missing client_id", "", url.Values{"client_secret": {postSecret}}, "", "", true, false},

		{"none with secret", "", url.Values{"client_id": {noneID}, "client_secret": {"x"}}, "", "", true, false},
		{"secret client with only id", "", url.Values{"client_id": {basicID}, "client_secret": {""}}, "", "", true, false},
		{"none via basic", basicHeader(noneID, ""), nil, "", "", true, true},
		{"basic client via post", "", url.Values{"client_id": {basicID}, "client_secret": {basicSecret}}, basicID, authClientSecretBasic, false, false},
		{"post client via basic", basicHeader(postID, postSecret), nil, postID, authClientSecretPost, false, false},
		{"basic client via post, wrong secret", "", url.Values{"client_id": {basicID}, "client_secret": {wrongSecret}}, "", "", true, false},
		{"post client via basic, wrong secret", basicHeader(postID, wrongSecret), nil, "", "", true, true},
		{"none client with empty secret", "", url.Values{"client_id": {noneID}, "client_secret": {""}}, noneID, authNone, false, false},
		{"basic with empty form secret", basicHeader(basicID, basicSecret), url.Values{"client_secret": {""}}, basicID, authClientSecretBasic, false, false},
		{"basic client without secret", "", url.Values{"client_id": {basicID}}, "", "", true, false},
		{"no credentials", "", nil, "", "", true, false},
		{"garbage client_id", "", url.Values{"client_id": {"garbage"}}, "", "", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, c, err := srv.authenticateClient(tokenReq(tc.header, tc.form))
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if id != tc.wantID || c.AuthMethod != tc.wantAuth || len(c.RedirectURIs) != 1 {
					t.Errorf("got %q %+v", id, c)
				}
				return
			}
			var cae *clientAuthError
			if !errors.Is(err, errInvalidClient) || !errors.As(err, &cae) {
				t.Fatalf("err = %v, want *clientAuthError matching errInvalidClient", err)
			}
			if cae.Basic != tc.wantBasic || cae.Reason == "" {
				t.Errorf("clientAuthError = %+v, want Basic=%v", cae, tc.wantBasic)
			}
			if id != "" || c.AuthMethod != "" {
				t.Errorf("non-empty result on error: %q %+v", id, c)
			}
		})
	}
}

func TestAuthenticateClientPercentEncodedBasic(t *testing.T) {
	// RFC 6749 §2.3.1: credentials are form-urlencoded before base64, so
	// every byte may arrive as %XX.
	srv, mux := testServer(t)
	id, secret := registerClient(t, mux, authClientSecretBasic)
	pct := func(s string) string {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			fmt.Fprintf(&b, "%%%02X", s[i])
		}
		return b.String()
	}
	raw := base64.StdEncoding.EncodeToString([]byte(pct(id) + ":" + pct(secret)))
	if _, _, err := srv.authenticateClient(tokenReq("Basic "+raw, nil)); err != nil {
		t.Fatalf("percent-encoded credentials rejected: %v", err)
	}
}

func TestAuthenticateClientIgnoresQuerySecret(t *testing.T) {
	srv, mux := testServer(t)
	id, secret := registerClient(t, mux, authClientSecretPost)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token?client_id="+id+"&client_secret="+secret, nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, _, err := srv.authenticateClient(req); !errors.Is(err, errInvalidClient) {
		t.Errorf("err = %v, want errInvalidClient (credentials in URL query must be ignored)", err)
	}
}

func TestAuthenticateClientMalformedBody(t *testing.T) {
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("a=%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, _, err := srv.authenticateClient(req); !errors.Is(err, errMalformedRequest) {
		t.Errorf("err = %v, want errMalformedRequest", err)
	}
}

func TestAuthenticateClientKeyRotation(t *testing.T) {
	srv, mux := testServer(t)
	id, secret := registerClient(t, mux, authClientSecretBasic)
	form := url.Values{}

	// New primary key prepended, old one kept: still valid.
	rotated := New(srv.cfg, testSealer(t, 1, 0), nil)
	if _, _, err := rotated.authenticateClient(tokenReq(basicHeader(id, secret), form)); err != nil {
		t.Errorf("after rotation with old key retained: %v", err)
	}
	// Old key dropped: registered clients are invalid (claude.ai re-registers).
	dropped := New(srv.cfg, testSealer(t, 1), nil)
	if _, _, err := dropped.authenticateClient(tokenReq(basicHeader(id, secret), form)); !errors.Is(err, errInvalidClient) {
		t.Errorf("after dropping old key: err = %v, want errInvalidClient", err)
	}
}

func TestRegisterThenAuthenticate(t *testing.T) {
	srv, mux := testServer(t)
	for _, method := range []string{authClientSecretBasic, authClientSecretPost} {
		t.Run(method, func(t *testing.T) {
			id, secret := registerClient(t, mux, method)
			if secret == "" {
				t.Fatal("no secret issued")
			}
			basic := tokenReq(basicHeader(id, secret), url.Values{"grant_type": {"authorization_code"}})
			form := tokenReq("", url.Values{"client_id": {id}, "client_secret": {secret}})
			for name, req := range map[string]*http.Request{"basic": basic, "form": form} {
				gotID, c, err := srv.authenticateClient(req)
				if err != nil || gotID != id || c.AuthMethod != method {
					t.Errorf("%s: id=%q c=%+v err=%v", name, gotID, c, err)
				}
			}
		})
	}
	id, _ := registerClient(t, mux, authNone)
	if _, _, err := srv.authenticateClient(tokenReq("", url.Values{"client_id": {id}})); err != nil {
		t.Errorf("none client: %v", err)
	}
	if _, _, err := srv.authenticateClient(tokenReq(basicHeader(id, ""), nil)); !errors.Is(err, errInvalidClient) {
		t.Errorf("none client via basic: err = %v, want errInvalidClient", err)
	}
}

func TestClientIDSize(t *testing.T) {
	_, mux := testServer(t)
	name := strings.Repeat("я", 100) // 2 bytes per rune
	body := `{"redirect_uris":["` + cbClaudeAI + `","` + cbClaudeCom + `"],"client_name":"` + name + `"}`
	rec := postJSON(mux, "application/json", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d", rec.Code)
	}
	if n := len(decode[registerResponse](t, rec).ClientID); n >= 1024 {
		t.Errorf("client_id is %d bytes, want < 1024", n)
	}
}

func TestRegisterCORSOnlyOnHandler(t *testing.T) {
	// writeJSON is shared with future endpoints and must not set CORS itself.
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusOK, map[string]string{})
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("writeJSON set Access-Control-Allow-Origin = %q", got)
	}
	_, mux := testServer(t)
	for _, body := range []string{`{"redirect_uris":["` + cbClaudeAI + `"]}`, `{}`} {
		if got := postJSON(mux, "application/json", body).Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("register response ACAO = %q for %s", got, body)
		}
	}
}

func TestRegisterNilSealer(t *testing.T) {
	cfg := &config.Config{OAuth: config.OAuth{AllowedRedirectURIs: []string{cbClaudeAI}}}
	mux := http.NewServeMux()
	New(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil))).Register(mux)
	rec := postJSON(mux, "application/json", `{"redirect_uris":["`+cbClaudeAI+`"]}`)
	if rec.Code != http.StatusInternalServerError || decode[oauthError](t, rec).Error != "server_error" {
		t.Errorf("status = %d body %s", rec.Code, rec.Body)
	}
}
