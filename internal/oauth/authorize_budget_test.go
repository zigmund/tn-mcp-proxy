package oauth

import (
	"math"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/tokens"
)

func TestAuthorizeOverBudgetCredentialsGetFormError(t *testing.T) {
	e := newAZ(t)
	long := strings.Repeat("a", maxCredLen)
	other := strings.Repeat("b", maxCredLen) // non-secret fields are re-rendered
	// Three maximal values cannot fit in a 16 KiB token.
	form := url.Values{
		requestField: {hidden(t, e.get(e.query(nil)).Body.String())},
		"cred_0":     {long}, "cred_1": {other}, "cred_2": {other},
	}
	rec := e.post(form)
	mustPage(t, rec, http.StatusBadRequest)
	body := rec.Body.String()
	if !strings.Contains(body, en(msgCredsTooLong)) {
		t.Errorf("no form error in:\n%s", body)
	}
	if strings.Contains(body, long[:100]) {
		t.Error("credentials echoed back")
	}
	if strings.Contains(rec.Header().Get("Location"), "server_error") {
		t.Error("server_error redirect")
	}
}

func TestAuthorizeHTMLCharsNoLongerInflate(t *testing.T) {
	e := newAZ(t)
	// 3000 '<' used to become 18000 bytes of escapes and fail with server_error.
	rec := e.post(url.Values{
		requestField: {hidden(t, e.get(e.query(nil)).Body.String())},
		"cred_0":     {strings.Repeat("<", 3000)}, "cred_1": {"s"},
	})
	u := mustSeeOther(t, rec)
	if u.Query().Get("code") == "" || u.Query().Get("error") != "" {
		t.Fatalf("redirect = %v", u)
	}
}

func TestAuthorizeMaxCredentialsRoundTrip(t *testing.T) {
	e := newAZ(t)
	up := e.srv.cfg.Upstreams[0]
	req := authRequest{ClientID: e.clientID, RedirectURI: cbClaudeAI, CodeChallenge: azChallenge, Upstream: "tn"}
	creds := func(n int) map[string]string {
		return map[string]string{
			"X-Api-Key": strings.Repeat("a", maxCredLen), "X-User": strings.Repeat("a", maxCredLen),
			"X-Extra": strings.Repeat("a", n),
		}
	}
	// The largest second value that still fits (budget derived from the cap).
	n := 0
	for n < maxCredLen && credsFit(up, req, creds(n+1)) {
		n++
	}
	if n == 0 || n >= maxCredLen {
		t.Fatalf("test needs the budget inside (0, %d), got %d", maxCredLen, n)
	}

	rec := e.post(url.Values{
		requestField: {hidden(t, e.get(e.query(nil)).Body.String())},
		"cred_0":     {strings.Repeat("a", maxCredLen)}, "cred_1": {strings.Repeat("a", maxCredLen)}, "cred_2": {strings.Repeat("a", n)},
	})
	u := mustSeeOther(t, rec)
	code, err := seal.OpenAs[tokens.Code](e.srv.sealer, seal.KindCode, u.Query().Get("code"))
	if err != nil {
		t.Fatalf("code: %v (redirect %v)", err, u)
	}
	if len(code.Creds["X-Extra"]) != n {
		t.Fatalf("creds lost: %d", len(code.Creds["X-Extra"]))
	}

	// The same holds when a session choice is configured: the code and the
	// refresh token then carry the extra field, which credsFit must have counted.
	setSessions(e.srv.cfg, t, "", "8760h", "unlimited")
	rec = e.post(url.Values{
		requestField: {hidden(t, e.get(e.query(nil)).Body.String())},
		"cred_0":     {strings.Repeat("a", maxCredLen)}, "cred_1": {strings.Repeat("a", maxCredLen)}, "cred_2": {strings.Repeat("a", n)},
		sessionField: {"8760h"},
	})
	u = mustSeeOther(t, rec)
	if _, err := seal.OpenAs[tokens.Code](e.srv.sealer, seal.KindCode, u.Query().Get("code")); err != nil {
		t.Fatalf("code with a session choice at the boundary: %v", err)
	}
	rt, err := e.srv.sealer.Seal(seal.KindRefresh, tokens.Refresh{
		Upstream: "tn", ClientID: e.clientID, Creds: code.Creds, Family: strings.Repeat("x", 22),
		Gen: math.MaxInt64, Exp: math.MaxInt64, Start: math.MaxInt64, End: math.MinInt64,
	}, time.Unix(math.MaxInt32, 0))
	if err != nil || len(rt) > seal.MaxTokenSize {
		t.Fatalf("refresh with End at the boundary: %d bytes, %v", len(rt), err)
	}
	rec = e.post(url.Values{
		requestField: {hidden(t, e.get(e.query(nil)).Body.String())},
		"cred_0":     {strings.Repeat("a", maxCredLen)}, "cred_1": {strings.Repeat("a", maxCredLen)}, "cred_2": {strings.Repeat("a", n+1)},
		sessionField: {"8760h"},
	})
	mustPage(t, rec, http.StatusBadRequest)
	e.srv.cfg.OAuth.Sessions = nil

	// The worst-case tokens derived from the accepted input all seal and open.
	exp := time.Unix(math.MaxInt32, 0)
	id := strings.Repeat("x", 22)
	for kind, payload := range map[seal.Kind]any{
		seal.KindAccess: tokens.Access{Upstream: "tn", ClientID: e.clientID, Creds: code.Creds},
		seal.KindRefresh: tokens.Refresh{
			Upstream: "tn", ClientID: e.clientID, Creds: code.Creds, Family: id,
			Gen: math.MaxInt64, Exp: math.MaxInt64, Start: math.MaxInt64, End: math.MinInt64,
		},
	} {
		tok, err := e.srv.sealer.Seal(kind, payload, exp)
		if err != nil {
			t.Fatalf("%s at the budget limit: %v", kind, err)
		}
		if len(tok) > seal.MaxTokenSize {
			t.Fatalf("%s is %d bytes", kind, len(tok))
		}
	}

	// One byte more is refused with a form error.
	rec = e.post(url.Values{
		requestField: {hidden(t, e.get(e.query(nil)).Body.String())},
		"cred_0":     {strings.Repeat("a", maxCredLen)}, "cred_1": {strings.Repeat("a", maxCredLen)}, "cred_2": {strings.Repeat("a", n+1)},
	})
	mustPage(t, rec, http.StatusBadRequest)
	if !strings.Contains(rec.Body.String(), en(msgCredsTooLong)) {
		t.Error("over-budget input not rejected with a form error")
	}
}
