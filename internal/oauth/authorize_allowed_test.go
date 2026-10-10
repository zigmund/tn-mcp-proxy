package oauth

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/tokens"
)

func allowUser(up *config.Upstream) {
	up.Credentials[1].AllowedValues = []string{"alice"}
}

func TestAuthorizeAllowedValuesRefusesForeignWithoutUpstreamCall(t *testing.T) {
	f := newMCPFake(t)
	e := newAZValidated(t, f, allowUser)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())

	form := goodForm(sealed)
	form.Set("cred_1", "mallory")
	rec := e.post(form)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), rejectedMsg) {
		t.Fatalf("status %d, body lacks the generic rejection:\n%s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "allowed") {
		t.Error("response reveals the allow-list")
	}
	if n := len(f.requests()); n != 0 {
		t.Fatalf("foreign credentials reached the upstream (%d requests)", n)
	}

	// An allowed value (the form trims it) gets a code.
	form.Set("cred_1", " alice ")
	u := mustSeeOther(t, e.post(form))
	if _, err := seal.OpenAs[tokens.Code](e.srv.sealer, seal.KindCode, u.Query().Get("code")); err != nil {
		t.Fatal(err)
	}
	if len(f.requests()) == 0 {
		t.Error("allowed credentials were not validated upstream")
	}
}

func TestAuthorizeAllowedValuesWithoutValidate(t *testing.T) {
	e := newAZ(t, config.Upstream{
		Name: "tn", Title: "Tradernet", Path: "/tn", URL: "https://upstream.example.com/mcp",
		Credentials: []config.Credential{
			{Header: "x-api-key", Label: "API key", Secret: true},
			{Header: "x-user", Label: "User", AllowedValues: []string{"alice"}},
		},
	})
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	form := goodForm(sealed)
	form.Set("cred_1", "mallory")
	if rec := e.post(form); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "rejected these credentials") {
		t.Fatalf("status %d:\n%s", rec.Code, rec.Body)
	}
	mustSeeOther(t, e.post(goodForm(sealed)))
}

func TestRefreshAllowedValues(t *testing.T) {
	e := newTK(t)
	_, rt := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))

	// The operator restricts the upstream to a different key: refresh is refused.
	e.cfg.Upstreams[0].Credentials = []config.Credential{{Header: "x-api-key", Label: "API key", AllowedValues: []string{"someone-else"}}}
	e.wantErr(t, e.do(e.refreshForm(e.none, rt)), 400, "invalid_grant")

	// The refused attempt did not burn the token: allowing the key again works.
	e.cfg.Upstreams[0].Credentials[0].AllowedValues = []string{"sekret"}
	e.wantOK(t, e.do(e.refreshForm(e.none, rt)))
}

func TestAuthorizeAllowedRefusalIndistinguishable(t *testing.T) {
	norm := func(s string) string {
		// The sealed request and the switcher links (which carry the per-env client_id) differ by nonce.
		s = regexp.MustCompile(`(?s)<nav class="lang".*?</nav>`).ReplaceAllString(s, "")
		return regexp.MustCompile(`name="request" value="[^"]*"`).ReplaceAllString(s, `name="request" value=""`)
	}
	post := func(mod func(*config.Upstream)) *httptest.ResponseRecorder {
		f := newMCPFake(t)
		f.on("tools/call", rejectingTool())
		e := newAZValidated(t, f, mod)
		sealed := hidden(t, e.get(e.query(nil)).Body.String())
		form := goodForm(sealed)
		form.Set("cred_1", "mallory")
		return e.post(form)
	}
	genuine := post(nil)       // no list: the upstream rejects the key
	refused := post(allowUser) // list: refused before the upstream
	if genuine.Code != refused.Code || norm(genuine.Body.String()) != norm(refused.Body.String()) {
		t.Fatalf("responses differ:\ngenuine %d\n%s\nrefused %d\n%s", genuine.Code, genuine.Body, refused.Code, refused.Body)
	}
	if !strings.Contains(genuine.Body.String(), rejectedMsg) {
		t.Fatal("fixture did not produce the upstream rejection")
	}
}

func TestAuthorizeAllowedOptionalLeftEmptyRefused(t *testing.T) {
	f := newMCPFake(t)
	e := newAZValidated(t, f, func(up *config.Upstream) {
		up.Credentials[2].AllowedValues = []string{"acct-1"}
	})
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	rec := e.post(goodForm(sealed)) // cred_2 (optional) left empty
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), rejectedMsg) {
		t.Fatalf("status %d:\n%s", rec.Code, rec.Body)
	}
	if n := len(f.requests()); n != 0 {
		t.Fatalf("upstream contacted (%d)", n)
	}
	form := goodForm(sealed)
	form.Set("cred_2", "acct-1")
	mustSeeOther(t, e.post(form))
}

func TestCodeExchangeAllowedValues(t *testing.T) {
	e := newTK(t)
	code := e.code(t, e.none, nil)
	e.cfg.Upstreams[0].Credentials = []config.Credential{{Header: "x-api-key", Label: "API key", AllowedValues: []string{"someone-else"}}}
	e.wantErr(t, e.do(e.codeForm(e.none, code)), 400, "invalid_grant")

	// Refused before the single-use claim: the code is still redeemable once allowed.
	e.cfg.Upstreams[0].Credentials[0].AllowedValues = []string{"sekret"}
	e.wantOK(t, e.do(e.codeForm(e.none, code)))
}
