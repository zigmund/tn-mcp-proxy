package oauth

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/audit"
	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
)

// pageBody GETs the authorize form from e and returns the HTML.
func pageBody(t *testing.T, e *azEnv) string {
	t.Helper()
	rec := e.get(e.query(nil))
	mustPage(t, rec, http.StatusOK)
	return rec.Body.String()
}

func enableAuditPage(e *azEnv, retention string) {
	e.srv.cfg.Audit = config.Audit{Enabled: true, Retention: retention}
	e.srv.audit = audit.New(e.srv.log, e.srv.cfg)
}

func TestPageMinimal(t *testing.T) {
	e := newAZ(t)
	body := pageBody(t, e)
	for _, absent := range []string{
		"What this server logs", "Notice from the operator", "Contact:", `role="alert"`,
		"Never logged or stored", en("hint.audit"),
	} {
		if strings.Contains(body, absent) {
			t.Errorf("minimal page contains %q", absent)
		}
	}
	for _, want := range []string{
		`<html lang="en">`, "Connect Tradernet", "Application name:", "self-declared, unverified",
		en("hint.plain"), en("hint.continue"), ">Authorize</button>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("minimal page lacks %q", want)
		}
	}
}

func TestPageEmptyClientName(t *testing.T) {
	e := newAZ(t)
	id, err := e.srv.sealer.Seal(seal.KindClient, client{RedirectURIs: []string{cbClaudeAI}, AuthMethod: authNone, IssuedAt: 1}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	q := e.query(func(q url.Values) { q.Set("client_id", id) })
	rec := e.get(q)
	mustPage(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "<b>Unnamed application</b>") {
		t.Errorf("no fallback client name:\n%s", rec.Body)
	}
}

func TestPageAuditDisclosure(t *testing.T) {
	e := newAZ(t, auditUpstream())
	enableAuditPage(e, "12 months")
	body := pageBody(t, e)
	for _, want := range []string{
		"What this server logs", "Time of each request", "Your IP address", "<li>Your User</li>", "Tools called",
		"Logs are kept for 12 months.",
		"Never logged or stored:", `<span class="chip">API key</span>`, `<span class="chip">Extra</span>`,
		en("hint.audit"),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("audit page lacks %q", want)
		}
	}
	for _, absent := range []string{"Your API key", "Your Extra", `<span class="chip">User</span>`, en("hint.plain")} {
		if strings.Contains(body, absent) {
			t.Errorf("audit page contains %q", absent)
		}
	}
}

func TestPageAuditWithoutAuditedCredentials(t *testing.T) {
	e := newAZ(t) // no credential is audited
	enableAuditPage(e, "30 days")
	body := pageBody(t, e)
	if !strings.Contains(body, "What this server logs") || !strings.Contains(body, "Your IP address") || strings.Count(body, "<li>Your ") != 1 {
		t.Errorf("panel must list time, IP and tools only:\n%s", body)
	}
	for _, label := range []string{"API key", "User", "Extra"} {
		if !strings.Contains(body, `<span class="chip">`+label+`</span>`) {
			t.Errorf("never-logged chip %q missing", label)
		}
	}
}

func TestPageAuditOffWithAuditedCredential(t *testing.T) {
	e := newAZ(t, auditUpstream())
	body := pageBody(t, e)
	if strings.Contains(body, "What this server logs") || !strings.Contains(body, en("hint.plain")) {
		t.Error("audit panel shown or plain hint missing with audit off")
	}
}

func TestPageNoticeAndContact(t *testing.T) {
	tests := []struct {
		name    string
		page    config.Page
		want    []string
		absent  []string
		section bool
	}{
		{"none", config.Page{}, nil, []string{"Notice from the operator"}, false},
		{"notice only", config.Page{Notice: map[string]string{"en": "Free.\n\nAs is."}},
			[]string{"<p>Free.</p>", "<p>As is.</p>"}, []string{"Contact:"}, true},
		{"contact only mailto", config.Page{Contact: "mailto:ops@example.org"},
			[]string{`<p>Contact: <a href="mailto:ops@example.org">ops@example.org</a></p>`}, nil, true},
		{"contact only https", config.Page{Contact: "https://example.org/help"},
			[]string{`<a href="https://example.org/help">https://example.org/help</a>`}, nil, true},
		{"both", config.Page{Contact: "mailto:ops@example.org", Notice: map[string]string{"en": "Hi."}},
			[]string{"<p>Hi.</p>", "Contact:"}, nil, true},
		{"other languages ignored", config.Page{Notice: map[string]string{"en": "Hi.", "ru": "Привет."}},
			[]string{"<p>Hi.</p>"}, []string{"Привет."}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newAZ(t)
			e.srv.cfg.OAuth.Page = tt.page
			body := pageBody(t, e)
			if got := strings.Contains(body, "Notice from the operator"); got != tt.section {
				t.Errorf("notice section present = %v, want %v", got, tt.section)
			}
			for _, w := range tt.want {
				if !strings.Contains(body, w) {
					t.Errorf("page lacks %q:\n%s", w, body)
				}
			}
			for _, a := range tt.absent {
				if strings.Contains(body, a) {
					t.Errorf("page contains %q", a)
				}
			}
		})
	}
}

func TestPageErrorBanner(t *testing.T) {
	e := newAZ(t)
	f := goodForm(hidden(t, pageBody(t, e)))
	f.Set("cred_0", "")
	rec := e.post(f)
	mustPage(t, rec, http.StatusBadRequest)
	if !strings.Contains(rec.Body.String(), `role="alert"`) || !strings.Contains(rec.Body.String(), "<p>API key is required.</p>") {
		t.Errorf("no error banner:\n%s", rec.Body)
	}
}

func TestPageErrorPage(t *testing.T) {
	e := newAZ(t)
	rec := e.get(url.Values{"client_id": {"nope"}})
	mustPage(t, rec, http.StatusBadRequest)
	body := rec.Body.String()
	for _, want := range []string{
		"<title>Authorization error</title>", `<h1 class="h-err">Authorization error</h1>`, `role="alert"`,
		en(msgClientUnknown), en("error.hint"), `<html lang="en">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("error page lacks %q", want)
		}
	}
}

func TestPageSecurityContent(t *testing.T) {
	body := pageBody(t, newAZ(t))
	h1 := regexp.MustCompile(`(?s)<h1>(.*?)</h1>`).FindStringSubmatch(body)
	if h1 == nil || !strings.HasPrefix(h1[1], `<span class="host">claude.ai</span>`) {
		t.Errorf("redirect host must lead the h1: %v", h1)
	}
	if strings.Index(body, "claude.ai") > strings.Index(body, "Evil") {
		t.Error("redirect host must come before the client name")
	}
}

// Hostile values from config, labels and the client must stay inert.
func TestPageEscaping(t *testing.T) {
	up := config.Upstream{
		Name: "tn", Title: `T<script>1</script>&"'`, Path: "/tn", URL: "https://upstream.example.com/mcp",
		Credentials: []config.Credential{
			{Header: "x-a", Label: `<i>a</i>`, Secret: true},
			{Header: "x-b", Label: `<u>b</u>`, Audit: true},
			{Header: "x-c", Label: `<s>c</s>`},
		},
	}
	e := newAZ(t, up)
	e.srv.cfg.Audit = config.Audit{Enabled: true, Retention: `<b>12</b> months & "more"`}
	e.srv.audit = audit.New(e.srv.log, e.srv.cfg)
	e.srv.cfg.OAuth.Page = config.Page{
		Contact: `https://x.example/"><script>alert(1)</script>`,
		Notice:  map[string]string{"en": "<script>alert(2)</script>\n\n<img src=x onerror=alert(3)>"},
	}
	body := pageBody(t, e)
	for _, bad := range []string{
		"<script", "<i>a</i>", "<u>b</u>", "<s>c</s>", "<b>12</b>", "<img", `"><script`, "onerror=alert(3)>",
	} {
		if strings.Contains(body, bad) {
			t.Errorf("page contains raw %q:\n%s", bad, body)
		}
	}
	for _, want := range []string{"&lt;i&gt;a&lt;/i&gt;", "&lt;u&gt;b&lt;/u&gt;", "&lt;b&gt;12&lt;/b&gt; months &amp;", "&lt;script&gt;alert(2)"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks escaped %q", want)
		}
	}

	// A contact that bypassed validation with a dangerous scheme is neutralised.
	e.srv.cfg.OAuth.Page = config.Page{Contact: "javascript:alert(1)"}
	if body := pageBody(t, e); strings.Contains(body, `href="javascript`) {
		t.Errorf("javascript: URL rendered:\n%s", body)
	}
}

func TestPageHostileClientAndHost(t *testing.T) {
	e := newAZ(t) // client name is "<b>Evil</b> App"
	body := pageBody(t, e)
	if strings.Contains(body, "<b>Evil</b>") {
		t.Error("client name not escaped")
	}
}

func TestPageHintCopy(t *testing.T) {
	plain := newAZ(t, auditUpstream())
	if b := pageBody(t, plain); !strings.Contains(b, "are not stored by this server. "+en("hint.continue")) {
		t.Errorf("plain hint wrong:\n%s", b)
	}
	logged := newAZ(t, auditUpstream())
	enableAuditPage(logged, "1 year")
	b := pageBody(t, logged)
	if strings.Contains(b, "not stored by this server") {
		t.Error("audit hint must not claim that nothing is stored")
	}
	if !strings.Contains(b, "Apart from what is listed above, this server does not log or store any credential values. "+en("hint.continue")) {
		t.Errorf("audit hint wrong:\n%s", b)
	}
}

// The CSP carries the hash of the stylesheet that is really embedded, for both
// pages, and the pages stay free of inline script, style attributes and
// external resources.
func TestPageCSPAndStrictness(t *testing.T) {
	e := newAZ(t)
	pages := map[string]string{
		"authorize": e.get(e.query(nil)).Header().Get("Content-Security-Policy"),
		"error":     e.get(url.Values{"client_id": {"nope"}}).Header().Get("Content-Security-Policy"),
	}
	for name, csp := range pages {
		if !strings.Contains(csp, "style-src "+styleSrc+";") {
			t.Errorf("%s CSP %q lacks the hash of the embedded CSS %s", name, csp, styleSrc)
		}
		if strings.Contains(csp, "unsafe") || !strings.Contains(csp, "default-src 'none'") {
			t.Errorf("%s CSP not strict: %q", name, csp)
		}
	}
	for name, src := range map[string]string{"authorize.html": authorizeHTML, "error.html": errorHTML} {
		for _, bad := range []string{"<script", "style=", "<link", "<img", "<iframe", "http://", "https://", "onclick", "javascript:"} {
			if strings.Contains(src, bad) {
				t.Errorf("%s contains %q", name, bad)
			}
		}
		if n := strings.Count(src, "<style>"); n != 1 {
			t.Errorf("%s has %d <style> elements, want 1", name, n)
		}
	}
	for _, bad := range []string{"@import", "url(", "expression("} {
		if strings.Contains(styleCSS, bad) {
			t.Errorf("style.css contains %q", bad)
		}
	}
}
