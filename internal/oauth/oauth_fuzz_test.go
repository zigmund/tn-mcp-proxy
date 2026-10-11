package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/tokens"
)

// Fuzz workers are separate processes, each building its own environment with
// fresh random nonces, so client ids and sealed requests differ between the
// process that holds the corpus and the workers. Raw-input targets therefore
// accept placeholders that are substituted per process (see fzEnv.sub).

const fzVerifier = "verifier-verifier-verifier-verifier-verifier-0123"

type fzEnv struct {
	srv             *Server
	mux             *http.ServeMux
	none, post, bas string // registered client ids (redirect: cbClaudeAI only)
	reqTok          string // genuine sealed authorize request of the none client
	sub             func(string) string
	challenge       string // S256 challenge of fzVerifier
}

func newFZ(tb testing.TB) *fzEnv {
	tb.Helper()
	sealer, err := seal.New([][]byte{[]byte(strings.Repeat("f", 32)), []byte(strings.Repeat("g", 32))},
		seal.WithClock(func() time.Time { return fixedNow }))
	if err != nil {
		tb.Fatal(err)
	}
	cfg := &config.Config{
		PublicURL: azPublic,
		OAuth: config.OAuth{
			AllowedRedirectURIs: []string{cbClaudeAI, cbClaudeCom},
			AccessTokenTTL:      time.Hour, RefreshTokenTTL: 720 * time.Hour, CodeTTL: 5 * time.Minute,
			// Fuzzing sends thousands of requests from one address.
			RateLimit: config.RateLimit{Disabled: true},
		},
		Upstreams: []config.Upstream{{
			Name: "tn", Title: "Tradernet", Path: "/tn", URL: "https://upstream.example.com/mcp",
			Credentials: []config.Credential{
				{Header: "x-api-key", Label: "API key", Secret: true},
				{Header: "x-user", Label: "User"},
				{Header: "x-extra", Label: "Extra", Optional: true},
			},
		}},
	}
	e := &fzEnv{}
	e.srv = New(cfg, sealer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.srv.now = func() time.Time { return fixedNow }
	e.mux = http.NewServeMux()
	e.srv.Register(e.mux)
	mk := func(method string) string {
		id, err := sealer.Seal(seal.KindClient, client{RedirectURIs: []string{cbClaudeAI}, Name: "Fuzz", AuthMethod: method, IssuedAt: 1}, time.Time{})
		if err != nil {
			tb.Fatal(err)
		}
		return id
	}
	e.none, e.post, e.bas = mk(authNone), mk(authClientSecretPost), mk(authClientSecretBasic)
	sum := sha256.Sum256([]byte(fzVerifier))
	e.challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	e.reqTok, err = sealer.Seal(seal.KindAuthRequest, authRequest{
		ClientID: e.none, RedirectURI: cbClaudeAI, CodeChallenge: e.challenge, State: "st&te 1", Upstream: "tn",
	}, fixedNow.Add(time.Hour))
	if err != nil {
		tb.Fatal(err)
	}
	e.sub = strings.NewReplacer(
		"{CID}", e.none, "{CID_POST}", e.post, "{CID_BASIC}", e.bas,
		"{SECRET_POST}", e.srv.clientSecret(e.post), "{SECRET_BASIC}", e.srv.clientSecret(e.bas),
		"{REQ}", e.reqTok, "{CHALLENGE}", e.challenge,
	).Replace
	return e
}

// hdr substitutes placeholders in an Authorization value. "@basic ID SECRET"
// builds a Basic header from the (substituted) id and secret, which cannot be
// done on the encoded form.
func (e *fzEnv) hdr(s string) string {
	if rest, ok := strings.CutPrefix(s, "@basic "); ok {
		id, secret, _ := strings.Cut(rest, " ")
		return basicHdr(e.sub(id), e.sub(secret))
	}
	return e.sub(s)
}

func (e *fzEnv) ids() []string { return []string{e.none, e.post, e.bas} }

func (e *fzEnv) isClient(id string) bool { return slices.Contains(e.ids(), id) }

var (
	reVerifier  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	reChallenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// ---------------------------------------------------------------------------
// PKCE

// FuzzPKCE compares the verifier and challenge checks with independent
// references (RFC 7636 §4.1 and §4.2).
func FuzzPKCE(f *testing.F) {
	sum := sha256.Sum256([]byte(fzVerifier))
	good := base64.RawURLEncoding.EncodeToString(sum[:])
	f.Add(fzVerifier, good)
	f.Add(fzVerifier, good[:42]+"=")
	f.Add(strings.Repeat("a", 42), good)
	f.Add(strings.Repeat("a", 43), good)
	f.Add(strings.Repeat("a", 128), good)
	f.Add(strings.Repeat("a", 129), good)
	f.Add(strings.Repeat("-._~", 11), "")
	f.Add(strings.Repeat("a", 42)+" ", good)
	f.Add(strings.Repeat("a", 42)+"\n", good)
	f.Add(strings.Repeat("é", 30), good)
	f.Add("", "")

	f.Fuzz(func(t *testing.T, verifier, challenge string) {
		if got, want := validVerifier(verifier), reVerifier.MatchString(verifier); got != want {
			t.Fatalf("validVerifier(%q) = %v, want %v", verifier, got, want)
		}
		if got, want := validChallenge(challenge), reChallenge.MatchString(challenge); got != want {
			t.Fatalf("validChallenge(%q) = %v, want %v", challenge, got, want)
		}
		// pkceMatches against a reference that compares decoded digest bytes.
		d := sha256.Sum256([]byte(verifier))
		want := false
		// The decoder silently skips CR and LF; the challenge is a canonical string.
		if raw, err := base64.RawURLEncoding.Strict().DecodeString(challenge); err == nil && !strings.ContainsAny(challenge, "\r\n") {
			want = string(raw) == string(d[:])
		}
		if got := pkceMatches(verifier, challenge); got != want {
			t.Fatalf("pkceMatches(%q, %q) = %v, want %v", verifier, challenge, got, want)
		}
		// The matching challenge always verifies; any one-character change does not.
		own := base64.RawURLEncoding.EncodeToString(d[:])
		if !pkceMatches(verifier, own) || !validChallenge(own) {
			t.Fatalf("own challenge %q rejected", own)
		}
		for _, repl := range []byte{'A', 'B', '-', '_'} {
			if own[0] == repl {
				continue
			}
			if pkceMatches(verifier, string(repl)+own[1:]) {
				t.Fatal("altered challenge matched")
			}
		}
		if pkceMatches(verifier, own+"A") || pkceMatches(verifier, own[:len(own)-1]) {
			t.Fatal("resized challenge matched")
		}
	})
}

// ---------------------------------------------------------------------------
// Client authentication

// FuzzParseBasic feeds arbitrary Authorization values to parseBasic. A parsed
// result must come from a case-insensitive "Basic" scheme and a base64 blob
// "urlencoded(id):urlencoded(secret)", and must round-trip.
func FuzzParseBasic(f *testing.F) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for _, s := range []string{
		"", "Basic", "Basic ", "basic " + enc("a:b"), "BASIC  " + enc("a:b") + "  ", "Basic " + enc("a%3Ab:c%2Bd"),
		"Basic " + enc("a:b:c"), "Basic " + enc("nocolon"), "Basic " + enc("%zz:b"), "Basic " + enc("a+b:c d"),
		"Basic " + enc(":"), "Basic " + enc("a:b") + "=", "Basic " + strings.TrimRight(enc("a:b"), "="),
		"Bearer " + enc("a:b"), "Basic\t" + enc("a:b"), "Basic a b", "Basic " + enc("a:b") + "\n",
		basicHdr("id with space", "se:cr/et+&="),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		id, secret, ok := parseBasic(header)
		// Classes that must be rejected, asserted directly.
		if sc, rest, found := strings.Cut(header, " "); found && strings.EqualFold(sc, "Basic") {
			if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest)); err == nil {
				encID, encSecret, hasColon := strings.Cut(string(raw), ":")
				_, e1 := url.QueryUnescape(encID)
				_, e2 := url.QueryUnescape(encSecret)
				if (!hasColon || e1 != nil || e2 != nil) && ok {
					t.Fatalf("accepted %q: colon=%v id err=%v secret err=%v", header, hasColon, e1, e2)
				}
			}
		}
		if !ok {
			if id != "" || secret != "" {
				t.Fatalf("non-empty result (%q,%q) with ok=false", id, secret)
			}
			return
		}
		scheme, rest, found := strings.Cut(header, " ")
		if !found || !strings.EqualFold(scheme, "Basic") {
			t.Fatalf("accepted %q with scheme %q", header, scheme)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
		if err != nil {
			t.Fatalf("accepted undecodable credentials in %q", header)
		}
		encID, encSecret, found := strings.Cut(string(raw), ":")
		if !found {
			t.Fatalf("accepted credentials without ':' in %q", header)
		}
		if gotID, err := url.QueryUnescape(encID); err != nil || gotID != id {
			t.Fatalf("id = %q, want unescape of %q", id, encID)
		}
		if gotSec, err := url.QueryUnescape(encSecret); err != nil || gotSec != secret {
			t.Fatalf("secret = %q, want unescape of %q", secret, encSecret)
		}
		id2, secret2, ok2 := parseBasic(basicHdr(id, secret))
		if !ok2 || id2 != id || secret2 != secret {
			t.Fatalf("round trip (%q,%q) -> (%q,%q,%v)", id, secret, id2, secret2, ok2)
		}
	})
}

// FuzzBasicRoundTrip checks RFC 6749 §2.3.1: any id and secret, encoded with
// the form-urlencoded rules and joined with ':', decode back unchanged.
func FuzzBasicRoundTrip(f *testing.F) {
	f.Add("id", "secret")
	f.Add("a:b", "c:d")
	f.Add("a b+c", "%41%zz&=;")
	f.Add("", "")
	f.Add("é\x00\xff", "\n\t ")
	f.Fuzz(func(t *testing.T, id, secret string) {
		gotID, gotSecret, ok := parseBasic(basicHdr(id, secret))
		if !ok || gotID != id || gotSecret != secret {
			t.Fatalf("(%q,%q) -> (%q,%q,%v)", id, secret, gotID, gotSecret, ok)
		}
	})
}

// FuzzAuthenticateClient drives authenticateClient with an arbitrary header
// and form body, optionally mixing in genuine pieces (mask). Whatever the
// input, a client authenticates only with its own secret in exactly one
// location, a "none" client never with a secret, and never with both a Basic
// header and a form secret.
func FuzzAuthenticateClient(f *testing.F) {
	e := newFZ(f)
	f.Add(uint8(0), uint8(0), "", "client_id={CID}")
	f.Add(uint8(1), uint8(0), "", "grant_type=x")
	f.Add(uint8(1), uint8(3), "", "client_id={CID_POST}&client_secret={SECRET_POST}")
	f.Add(uint8(2), uint8(4), "", "")
	f.Add(uint8(2), uint8(4), "", "client_id={CID_BASIC}&client_id=other")
	f.Add(uint8(1), uint8(6), "", "client_secret=zzz")
	f.Add(uint8(1), uint8(8), "", "")
	f.Add(uint8(0), uint8(0), "Basic "+base64.StdEncoding.EncodeToString([]byte("a:b")), "client_id=a")
	f.Add(uint8(1), uint8(3), "", "client_secret={SECRET_POST}&client_secret=other")
	f.Add(uint8(0), uint8(1), "", "client_id=%zz")
	f.Add(uint8(0), uint8(1), "", "client_id=a;b=c")
	f.Add(uint8(2), uint8(0), "basic e30=", "client_id={CID_BASIC}")
	f.Add(uint8(1), uint8(2), "", strings.Repeat("a=b&", 5000))

	f.Fuzz(func(t *testing.T, sel, mask uint8, hdr, body string) {
		id := e.ids()[int(sel)%3]
		secret := e.srv.clientSecret(id)
		hdr, body = e.hdr(hdr), e.sub(body)
		if mask&1 != 0 {
			body = "client_id=" + id + "&" + body
		}
		if mask&2 != 0 {
			body += "&client_secret=" + secret
		}
		if mask&4 != 0 {
			hdr = basicHdr(id, secret)
		}
		if mask&8 != 0 {
			hdr = basicHdr(id, secret+"x")
		}

		req := httptest.NewRequest(http.MethodPost, PathToken, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if hdr != "" {
			req.Header["Authorization"] = []string{hdr}
		}
		gotID, c, err := e.srv.authenticateClient(req)

		pq, pqErr := url.ParseQuery(body)
		if (pqErr != nil) != errors.Is(err, errMalformedRequest) {
			t.Fatalf("parse error %v but authenticateClient error %v", pqErr, err)
		}
		if err != nil {
			var ae *clientAuthError
			if !errors.Is(err, errMalformedRequest) && (!errors.As(err, &ae) || !errors.Is(err, errInvalidClient)) {
				t.Fatalf("unexpected error type: %v", err)
			}
			if gotID != "" {
				t.Fatalf("client id %q returned with error %v", gotID, err)
			}
			return
		}

		// Success: re-derive from the raw request what must have been presented.
		formID, formSecret := pq.Get("client_id"), pq.Get("client_secret")
		if !e.isClient(gotID) {
			t.Fatalf("authenticated unknown client %q", gotID)
		}
		want := e.srv.clientSecret(gotID)
		switch {
		case hdr != "":
			if formSecret != "" {
				t.Fatalf("accepted a Basic header together with a form secret")
			}
			bid, bsec, ok := parseBasic(hdr)
			if !ok || bid != gotID {
				t.Fatalf("Basic header %q does not carry client %q", hdr, gotID)
			}
			if formID != "" && formID != bid {
				t.Fatalf("accepted conflicting client_id %q vs Basic %q", formID, bid)
			}
			if c.AuthMethod == authNone || bsec != want {
				t.Fatalf("authenticated with a wrong Basic secret (method %s)", c.AuthMethod)
			}
		case formSecret != "":
			if formID != gotID || c.AuthMethod == authNone || formSecret != want {
				t.Fatalf("authenticated with a wrong form secret (method %s)", c.AuthMethod)
			}
		default:
			if formID != gotID || c.AuthMethod != authNone {
				t.Fatalf("authenticated without a secret (method %s)", c.AuthMethod)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// redirect_uri construction

// FuzzRedirect checks that appending code/error/state/iss to a registered URI
// keeps scheme, host and path, drops stale reserved parameters, appends each
// intended parameter exactly once and preserves all other query parameters.
func FuzzRedirect(f *testing.F) {
	e := newFZ(f)
	f.Add(cbClaudeAI, "st", "code1", "", uint8(0))
	f.Add(cbClaudeAI+"?code=old&state=old&iss=old&error=old&error_description=old&keep=1&keep=2", "", "c", "", uint8(0))
	f.Add(cbClaudeAI+"?x=1&code=old", "s&t=1#", "", "access_denied", uint8(1))
	f.Add("http://localhost:3000/cb?a=b&a=c", "state with space", "x y", "d&=", uint8(3))
	f.Add("https://example.com/p%2Fq?z=%zz&;y=1", "s", "c", "", uint8(2))
	f.Add("https://u:p@example.com:8443/a/../b?q=é", "", "", "e", uint8(1))

	f.Fuzz(func(t *testing.T, uri, state, a, b string, mode uint8) {
		orig, err := url.Parse(uri)
		if err != nil || (orig.Scheme != "http" && orig.Scheme != "https") || orig.Host == "" {
			t.Skip()
		}
		isErr := mode&1 != 0
		params := url.Values{"code": {a}}
		if isErr {
			params = url.Values{"error": {a}, "error_description": {b}}
		}
		method := http.MethodGet
		wantStatus := http.StatusFound
		if mode&2 != 0 {
			method, wantStatus = http.MethodPost, http.StatusSeeOther
		}
		rec := httptest.NewRecorder()
		e.srv.redirect(rec, httptest.NewRequest(method, PathAuthorize, nil), uri, state, params)
		if rec.Code != wantStatus {
			t.Fatalf("status = %d, want %d", rec.Code, wantStatus)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("redirect is cacheable")
		}
		got, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("Location %q: %v", rec.Header().Get("Location"), err)
		}
		if got.Fragment != orig.Fragment {
			t.Fatalf("fragment changed: %q -> %q", orig.Fragment, got.Fragment)
		}
		if got.Scheme != orig.Scheme || got.Host != orig.Host || got.EscapedPath() != orig.EscapedPath() || got.User.String() != orig.User.String() {
			t.Fatalf("target changed: %q -> %q", uri, got)
		}
		gq, oq := got.Query(), orig.Query()
		once := func(k string, want string, present bool) {
			t.Helper()
			v, ok := gq[k]
			switch {
			case !present && ok:
				t.Fatalf("%s survived: %q (registered %q)", k, v, uri)
			case present && (len(v) != 1 || v[0] != want):
				t.Fatalf("%s = %q, want exactly [%q]", k, v, want)
			}
		}
		once("iss", azPublic, true)
		once("state", state, state != "")
		once("code", a, !isErr)
		once("error", a, isErr)
		once("error_description", b, isErr)
		for k, v := range oq {
			switch k {
			case "code", "error", "error_description", "state", "iss":
				continue
			}
			if !slices.Equal(gq[k], v) {
				t.Fatalf("param %q = %q, registered %q", k, gq[k], v)
			}
		}
		for k := range gq {
			switch k {
			case "code", "error", "error_description", "state", "iss":
			default:
				if _, ok := oq[k]; !ok {
					t.Fatalf("unexpected param %q appeared", k)
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Handlers

func fzDo(e *fzEnv, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

// fzLocation checks a redirect from the authorize endpoint and returns its
// query. The target must be exactly the registered redirect URI (plus query).
func fzLocation(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	reg, _ := url.Parse(cbClaudeAI)
	if loc.Scheme != reg.Scheme || loc.Host != reg.Host || loc.EscapedPath() != reg.EscapedPath() || loc.Fragment != "" || loc.User != nil {
		t.Fatalf("redirect to %q, which is not the registered %q", loc, cbClaudeAI)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("redirect is cacheable")
	}
	q := loc.Query()
	if len(q["iss"]) != 1 || q["iss"][0] != azPublic {
		t.Fatalf("iss = %q", q["iss"])
	}
	return q
}

func fzPageHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	h := rec.Header()
	if !strings.HasPrefix(h.Get("Content-Type"), "text/html") || h.Get("Cache-Control") != "no-store" ||
		h.Get("X-Frame-Options") != "DENY" || h.Get("Content-Security-Policy") == "" {
		t.Fatalf("page headers = %v", h)
	}
}

// FuzzAuthorizeGET sends arbitrary raw query strings to GET /oauth/authorize.
// It must answer a form (200), an error page (400) or a redirect (302) that
// targets only the exact registered redirect_uri, and only for a request whose
// redirect_uri, client and PKCE parameters are well formed.
func FuzzAuthorizeGET(f *testing.F) {
	e := newFZ(f)
	valid := "client_id={CID}&response_type=code&redirect_uri=" + url.QueryEscape(cbClaudeAI) +
		"&code_challenge={CHALLENGE}&code_challenge_method=S256&state=st%26te+1&resource=" + url.QueryEscape(azRes)
	for _, s := range []string{
		valid,
		valid + "&state=dup",
		valid + "&redirect_uri=" + url.QueryEscape(cbClaudeCom),
		valid + "&resource=" + url.QueryEscape(azRes),
		strings.Replace(valid, "S256", "plain", 1),
		strings.Replace(valid, "response_type=code", "response_type=token", 1),
		strings.Replace(valid, url.QueryEscape(cbClaudeAI), url.QueryEscape(cbClaudeAI+"/"), 1),
		strings.Replace(valid, url.QueryEscape(cbClaudeAI), url.QueryEscape(cbClaudeAI+"?x=1"), 1),
		strings.Replace(valid, url.QueryEscape(cbClaudeAI), "https://evil.example/cb", 1),
		strings.Replace(valid, "state=st%26te+1", "state="+strings.Repeat("s", 1025), 1),
		strings.Replace(valid, "state=st%26te+1", "state="+strings.Repeat("s", 1024), 1),
		strings.Replace(valid, "state=st%26te+1", "state=%zz", 1),
		valid + "&x=%ff;%00&&=&==",
		valid + "&" + strings.Repeat("p=1&", 20000),
		"", "client_id=", "client_id={CID}", "client_id={CID}&client_id={CID}",
		"client_id={CID}&redirect_uri=" + url.QueryEscape(cbClaudeAI),
		"client_id={CID}&redirect_uri=" + url.QueryEscape(cbClaudeAI) + "&state=" + strings.Repeat("%00", 500),
		"client_id[]={CID}", "client%5fid={CID}", "CLIENT_ID={CID}",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, rawQuery string) {
		rawQuery = e.sub(rawQuery)
		req := httptest.NewRequest(http.MethodGet, PathAuthorize, nil)
		req.URL.RawQuery = rawQuery // bypass request-target validation
		rec := fzDo(e, req)
		q, _ := url.ParseQuery(rawQuery) // same lenient parsing as URL.Query

		switch rec.Code {
		case http.StatusOK, http.StatusBadRequest:
			fzPageHeaders(t, rec)
			if rec.Header().Get("Location") != "" {
				t.Fatal("page with a Location header")
			}
		case http.StatusFound:
		default:
			t.Fatalf("status = %d", rec.Code)
		}
		if rec.Code == http.StatusOK || rec.Code == http.StatusFound {
			// Both require a verified client and an exactly registered redirect_uri.
			if len(q["client_id"]) != 1 || !e.isClient(q["client_id"][0]) {
				t.Fatalf("status %d for client_id %q", rec.Code, q["client_id"])
			}
			if len(q["redirect_uri"]) != 1 || q["redirect_uri"][0] != cbClaudeAI {
				t.Fatalf("status %d for redirect_uri %q", rec.Code, q["redirect_uri"])
			}
		}
		if rec.Code == http.StatusFound {
			lq := fzLocation(t, rec)
			if len(lq["error"]) != 1 || len(lq["code"]) != 0 {
				t.Fatalf("redirect query %v: want an error and no code", lq)
			}
			st := q["state"]
			if len(st) == 1 && len(st[0]) <= maxStateLen && st[0] != "" {
				if len(lq["state"]) != 1 || lq["state"][0] != st[0] {
					t.Fatalf("state %q not echoed: %q", st[0], lq["state"])
				}
			} else if len(lq["state"]) != 0 {
				t.Fatalf("state %q echoed for request state %q", lq["state"], st)
			}
		}
		if rec.Code == http.StatusOK {
			one := func(k string) string {
				if len(q[k]) != 1 {
					t.Fatalf("form rendered for %d values of %s", len(q[k]), k)
				}
				return q[k][0]
			}
			if one("response_type") != "code" || one("code_challenge_method") != "S256" || !reChallenge.MatchString(one("code_challenge")) {
				t.Fatalf("form rendered for query %q", rawQuery)
			}
			if len(q["state"]) > 1 || (len(q["state"]) == 1 && len(q["state"][0]) > maxStateLen) {
				t.Fatalf("form rendered for state %q", q["state"])
			}
			if r := q["resource"]; len(r) > 1 || (len(r) == 1 && r[0] != "" && r[0] != azRes) {
				t.Fatalf("form rendered for resource %q", r)
			}
			req, err := seal.OpenAs[authRequest](e.srv.sealer, seal.KindAuthRequest, hidden(t, rec.Body.String()))
			if err != nil || req.RedirectURI != cbClaudeAI || req.ClientID != q["client_id"][0] || req.CodeChallenge != q["code_challenge"][0] {
				t.Fatalf("sealed request %+v (%v) does not match the query", req, err)
			}
		}
	})
}

// FuzzAuthorizePOST sends arbitrary raw form bodies to POST /oauth/authorize.
// Without a genuine sealed request (placeholder {REQ}) nothing but an error
// may come back; with one, the only redirect target is the registered URI.
func FuzzAuthorizePOST(f *testing.F) {
	e := newFZ(f)
	creds := "&cred_0=sekret&cred_1=alice"
	for _, s := range []struct {
		body  string
		site  string
		ctype uint8
	}{
		{"request={REQ}" + creds, "", 0},
		{"request={REQ}" + creds, "same-origin", 0},
		{"request={REQ}" + creds, "cross-site", 0},
		{"request={REQ}&request=x" + creds, "none", 0},
		{"request=x&request={REQ}" + creds, "", 0},
		{"request={REQ}" + creds, "", 1},
		{"request={REQ}" + creds, "", 2},
		{"request={REQ}" + creds + "&cred_1=bob", "", 3},
		{"request={REQ}&cred_0=&cred_1=", "", 0},
		{"request={REQ}&cred_0=%00&cred_1=a", "", 0},
		{"request={REQ}&cred_0=%ff&cred_1=a", "", 0},
		{"request={REQ}&cred_0=" + strings.Repeat("k", 4097) + "&cred_1=a", "", 0},
		{"request=" + strings.Repeat("A", 64<<10), "", 0},
		{"request={REQ}" + creds + "&" + strings.Repeat("a=b&", 10000), "", 0},
		{"", "", 0}, {"request=", "", 0}, {"request=%zz", "", 0}, {"a;b=c", "", 0},
	} {
		f.Add(s.body, s.site, s.ctype)
	}

	f.Fuzz(func(t *testing.T, body, site string, ctype uint8) {
		body = e.sub(body)
		req := httptest.NewRequest(http.MethodPost, PathAuthorize, strings.NewReader(body))
		switch ctype % 4 {
		case 0:
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		case 1: // no Content-Type
		case 2:
			req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
		case 3:
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		}
		if site != "" {
			req.Header["Sec-Fetch-Site"] = []string{site}
		}
		rec := fzDo(e, req)
		switch rec.Code {
		case http.StatusBadRequest, http.StatusForbidden, http.StatusRequestEntityTooLarge:
			fzPageHeaders(t, rec)
			if rec.Header().Get("Location") != "" {
				t.Fatal("error page with a Location header")
			}
			return
		case http.StatusSeeOther:
		default:
			t.Fatalf("status = %d for body %q", rec.Code, body)
		}
		if site != "" && site != "same-origin" && site != "none" {
			t.Fatalf("cross-site submission (%q) accepted", site)
		}
		q := fzLocation(t, rec)
		code := q.Get("code")
		if len(q["code"]) != 1 || len(q["error"]) != 0 {
			t.Fatalf("redirect query %v", q)
		}
		pq, _ := url.ParseQuery(body)
		if pq.Get(requestField) != e.reqTok {
			t.Fatal("redirect issued without the genuine sealed request")
		}
		c, err := seal.OpenAs[tokens.Code](e.srv.sealer, seal.KindCode, code)
		if err != nil || c.ClientID != e.none || c.RedirectURI != cbClaudeAI || c.CodeChallenge != e.challenge || c.JTI == "" || c.Exp == 0 {
			t.Fatalf("issued code %+v (%v)", c, err)
		}
		for h, v := range c.Creds {
			if v == "" || strings.ContainsAny(v, "\r\n\x00") || strings.TrimSpace(v) != v {
				t.Fatalf("credential %s = %q", h, v)
			}
		}
	})
}

// FuzzAuthorizeSubmit posts genuine sealed requests with arbitrary credential
// values and checks the outcome against an independent validity predicate: a
// code is issued if and only if the credentials are valid, and carries them.
func FuzzAuthorizeSubmit(f *testing.F) {
	e := newFZ(f)
	f.Add("sekret", " alice ", "", uint8(0))
	f.Add("sekret", "alice", "extra", uint8(0))
	f.Add("", "alice", "", uint8(0))
	f.Add("sekret", "  ", "", uint8(0))
	f.Add("se\tkret", "alice", "", uint8(0))
	f.Add("sekret", "ali\x7fce", "", uint8(0))
	f.Add("sekret", "alice", "a\nb", uint8(0))
	f.Add("sekret", "alice", "", uint8(1))
	f.Add("sekret", "alice", "", uint8(2))
	f.Add(strings.Repeat("k", 4096), "alice", "", uint8(0))
	f.Add(strings.Repeat("k", 4097), "alice", "", uint8(0))
	f.Add(" sekret ", "\u0085alice", "é", uint8(0))
	f.Add("\xc3\x28", "alice", "", uint8(0))

	validCred := func(v string) bool {
		if len(v) > maxCredLen || !utf8.ValidString(v) {
			return false
		}
		for _, r := range v {
			if r < 0x20 || r == 0x7f {
				return false
			}
		}
		return true
	}

	f.Fuzz(func(t *testing.T, c0, c1, c2 string, dup uint8) {
		form := url.Values{requestField: {e.reqTok}, "cred_0": {c0}, "cred_1": {c1}, "cred_2": {c2}}
		switch dup % 3 {
		case 1: // a second, garbage request value after the genuine one
			form[requestField] = append(form[requestField], "garbage")
		case 2: // garbage first: Get returns it
			form[requestField] = []string{"garbage", e.reqTok}
		}
		req := httptest.NewRequest(http.MethodPost, PathAuthorize, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := fzDo(e, req)

		t0, t1, t2 := strings.TrimSpace(c0), strings.TrimSpace(c1), strings.TrimSpace(c2)
		want := dup%3 != 2 && t0 != "" && validCred(t0) && t1 != "" && validCred(t1) && (t2 == "" || validCred(t2))
		if !want {
			if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
				t.Fatalf("status %d for invalid input %q %q %q dup=%d", rec.Code, c0, c1, c2, dup)
			}
			return
		}
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status %d for valid input %q %q %q", rec.Code, c0, c1, c2)
		}
		q := fzLocation(t, rec)
		if len(q["state"]) != 1 || q["state"][0] != "st&te 1" || len(q["code"]) != 1 {
			t.Fatalf("redirect query %v", q)
		}
		code, err := seal.OpenAs[tokens.Code](e.srv.sealer, seal.KindCode, q["code"][0])
		if err != nil {
			t.Fatal(err)
		}
		wantCreds := map[string]string{"X-Api-Key": t0, "X-User": t1}
		if t2 != "" {
			wantCreds["X-Extra"] = t2
		}
		if len(code.Creds) != len(wantCreds) {
			t.Fatalf("creds = %v, want %v", code.Creds, wantCreds)
		}
		for k, v := range wantCreds {
			if code.Creds[k] != v {
				t.Fatalf("creds = %v, want %v", code.Creds, wantCreds)
			}
		}
	})
}

// fzTokenCheck asserts the invariants of every token endpoint response and
// returns the decoded body.
func fzTokenCheck(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	h := rec.Header()
	if h.Get("Cache-Control") != "no-store" || h.Get("Pragma") != "no-cache" {
		t.Fatalf("cache headers = %v", h)
	}
	if h.Get("Content-Type") != "application/json" || h.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("headers = %v", h)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", rec.Body, err)
	}
	if rec.Code >= 500 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if rec.Code != http.StatusOK {
		if s, _ := m["error"].(string); s == "" {
			t.Fatalf("error response without error code: %s", rec.Body)
		}
		if _, ok := m["access_token"]; ok {
			t.Fatalf("error response carries a token: %s", rec.Body)
		}
	}
	if rec.Code == http.StatusUnauthorized && m["error"] != "invalid_client" {
		t.Fatalf("401 with %v", m["error"])
	}
	if h.Get("WWW-Authenticate") != "" && rec.Code != http.StatusUnauthorized {
		t.Fatalf("WWW-Authenticate on status %d", rec.Code)
	}
	return m
}

// FuzzTokenRaw sends arbitrary requests to /oauth/token. Without a genuine
// authorization code or refresh token (impossible to forge) the endpoint may
// only answer with a JSON error, never a token and never a 5xx.
func FuzzTokenRaw(f *testing.F) {
	e := newFZ(f)
	type seed struct {
		body, authz string
		ctype       uint8
	}
	basic := "@basic {CID_BASIC} {SECRET_BASIC}"
	for _, s := range []seed{
		{"grant_type=authorization_code&code=x&redirect_uri=" + url.QueryEscape(cbClaudeAI) + "&code_verifier=" + fzVerifier + "&client_id={CID}", "", 0},
		{"grant_type=refresh_token&refresh_token=x&client_id={CID}", "", 0},
		{"grant_type=refresh_token&refresh_token=x&client_id={CID_POST}&client_secret={SECRET_POST}", "", 0},
		{"grant_type=refresh_token&refresh_token=x", basic, 0},
		{"grant_type=refresh_token&refresh_token=x&client_secret={SECRET_BASIC}", basic, 0},
		{"grant_type=refresh_token&refresh_token=x&client_id=other", basic, 0},
		{"grant_type=refresh_token&refresh_token=x&client_id={CID}&client_id={CID}", "", 0},
		{"grant_type=refresh_token&grant_type=refresh_token&refresh_token=x&client_id={CID}", "", 0},
		{"grant_type=authorization_code&code={CID}&code_verifier=" + fzVerifier + "&redirect_uri=" + url.QueryEscape(cbClaudeAI) + "&client_id={CID}", "", 0},
		{"grant_type=password&client_id={CID}", "", 0},
		{"client_id={CID}", "", 1},
		{"client_id={CID}", "", 2},
		{"client_id={CID}", "", 3},
		{"client_id={CID}&" + strings.Repeat("x=y&", 8000), "", 0},
		{"a=" + strings.Repeat("z", 20<<10), "", 0},
		{"grant_type=refresh_token&refresh_token=%zz&client_id={CID}", "", 0},
		{"", "Basic", 0}, {"", "Basic !!!", 0}, {"", "Bearer abc", 0}, {"", "", 0},
	} {
		f.Add(s.body, s.authz, s.ctype)
	}

	f.Fuzz(func(t *testing.T, body, authz string, mode uint8) {
		method := http.MethodPost
		switch mode % 8 {
		case 5:
			method = http.MethodGet
		case 6:
			method = http.MethodPut
		}
		req := httptest.NewRequest(method, PathToken, strings.NewReader(e.sub(body)))
		switch mode % 8 {
		case 0, 5, 6:
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		case 1: // none
		case 2:
			req.Header.Set("Content-Type", "application/json")
		case 3:
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		case 4:
			req.Header.Set("Content-Type", "APPLICATION/X-WWW-FORM-URLENCODED;x=\"")
		}
		if authz != "" {
			req.Header["Authorization"] = []string{e.hdr(authz)}
		}
		rec := fzDo(e, req)
		m := fzTokenCheck(t, rec)
		switch rec.Code {
		case http.StatusBadRequest, http.StatusUnauthorized, http.StatusMethodNotAllowed, http.StatusRequestEntityTooLarge:
		default:
			t.Fatalf("status = %d: %v", rec.Code, m)
		}
		if method != http.MethodPost && rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s answered %d", method, rec.Code)
		}
	})
}

var fzJTI atomic.Int64

// FuzzTokenMutate starts from a genuine, complete token request (code
// exchange or refresh, for a public or a secret client) and sets, duplicates or
// removes one parameter. The request may succeed only if every parameter that
// matters still has its genuine value; a duplicated parameter never succeeds.
func FuzzTokenMutate(f *testing.F) {
	e := newFZ(f)
	f.Add(uint8(0), uint8(0), uint8(0), "authorization_code")
	f.Add(uint8(0), uint8(0), uint8(1), "x")
	f.Add(uint8(0), uint8(0), uint8(2), "")
	f.Add(uint8(1), uint8(1), uint8(0), "refresh_token")
	f.Add(uint8(1), uint8(2), uint8(0), "")
	f.Add(uint8(1), uint8(3), uint8(1), "")
	f.Add(uint8(0), uint8(3), uint8(0), "{CID}")
	f.Add(uint8(0), uint8(4), uint8(0), fzVerifier)
	f.Add(uint8(0), uint8(4), uint8(0), fzVerifier+"x")
	f.Add(uint8(0), uint8(2), uint8(0), cbClaudeCom)
	f.Add(uint8(0), uint8(5), uint8(0), azRes)
	f.Add(uint8(0), uint8(5), uint8(0), "https://other.example/")
	f.Add(uint8(1), uint8(6), uint8(0), "")
	f.Add(uint8(1), uint8(6), uint8(0), "{SECRET_POST}")
	f.Add(uint8(0), uint8(7), uint8(0), "ignored")

	fields := []string{"grant_type", "code", "redirect_uri", "client_id", "code_verifier", "resource", "client_secret", "refresh_token"}

	f.Fuzz(func(t *testing.T, flags, fieldIdx, op uint8, value string) {
		// Every success adds a live entry to the single-use caches, and the code
		// replay cache fails closed (503) when full. Start each input from empty
		// caches so results do not depend on the run's history.
		e.srv.codes, e.srv.families = newReplayCache(maxReplayEntries), newFamilyCache(maxFamilyEntries)
		refresh := flags&1 != 0
		secretClient := flags&2 != 0
		id := e.none
		if secretClient {
			id = e.post
		}
		secret := e.srv.clientSecret(id)
		value = e.sub(value)

		// Genuine request and, per field, the values the grant accepts (nil: ignored).
		form := url.Values{"client_id": {id}}
		accept := map[string][]string{"client_id": {id}, "resource": {"", azRes}, "client_secret": {""}}
		if secretClient {
			form.Set("client_secret", secret)
			accept["client_secret"] = []string{secret}
		}
		fam, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		if refresh {
			rt, err := e.srv.sealer.Seal(seal.KindRefresh, tokens.Refresh{
				Upstream: "tn", ClientID: id, Creds: map[string]string{"X-Api-Key": "k", "X-User": "u"}, Family: fam, Exp: fixedNow.Add(time.Hour).Unix(),
			}, fixedNow.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			form.Set("grant_type", grantRefreshToken)
			form.Set("refresh_token", rt)
			accept["grant_type"], accept["refresh_token"] = []string{grantRefreshToken}, []string{rt}
		} else {
			exp := fixedNow.Add(time.Hour)
			code, err := e.srv.sealer.Seal(seal.KindCode, tokens.Code{
				ClientID: id, RedirectURI: cbClaudeAI, CodeChallenge: e.challenge, Upstream: "tn",
				Creds: map[string]string{"X-Api-Key": "k", "X-User": "u"}, JTI: fam + string(rune('a'+fzJTI.Add(1)%26)), Exp: exp.Unix(),
			}, exp)
			if err != nil {
				t.Fatal(err)
			}
			form.Set("grant_type", grantAuthorizationCode)
			form.Set("code", code)
			form.Set("redirect_uri", cbClaudeAI)
			form.Set("code_verifier", fzVerifier)
			accept["grant_type"], accept["code"] = []string{grantAuthorizationCode}, []string{code}
			accept["redirect_uri"], accept["code_verifier"] = []string{cbClaudeAI}, []string{fzVerifier}
		}

		field := fields[int(fieldIdx)%len(fields)]
		mayPass := true
		switch op % 3 {
		case 0: // set
			form.Set(field, value)
			if want, strict := accept[field]; strict {
				mayPass = slices.Contains(want, value)
			}
		case 1: // duplicate: the parameter now occurs twice
			first := form.Get(field)
			form[field] = []string{first, value}
			mayPass = false
		case 2: // remove
			form.Del(field)
			if want, strict := accept[field]; strict {
				mayPass = slices.Contains(want, "")
			}
		}

		req := httptest.NewRequest(http.MethodPost, PathToken, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := fzDo(e, req)
		m := fzTokenCheck(t, rec)
		if rec.Code != http.StatusOK {
			if mayPass {
				// A genuine request, or one altered only in an ignored or
				// equivalent way, must succeed.
				t.Fatalf("genuine request rejected: %d %v (field %s op %d value %q)", rec.Code, m, field, op%3, value)
			}
			return
		}
		if !mayPass {
			t.Fatalf("token issued although %s was altered (op %d, value %q)", field, op%3, value)
		}
		access, _ := m["access_token"].(string)
		a, err := seal.OpenAs[tokens.Access](e.srv.sealer, seal.KindAccess, access)
		if err != nil || a.Upstream != "tn" || a.ClientID != id || m["token_type"] != "Bearer" {
			t.Fatalf("issued access token %+v (%v), response %v", a, err, m)
		}
		if _, err := seal.OpenAs[tokens.Refresh](e.srv.sealer, seal.KindRefresh, m["refresh_token"].(string)); err != nil {
			t.Fatalf("issued refresh token: %v", err)
		}
	})
}
