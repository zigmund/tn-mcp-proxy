package oauth

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

func TestMatchAcceptLanguage(t *testing.T) {
	tests := []struct{ header, want string }{
		{"", "en"},
		{"en", "en"},
		{"ru", "ru"},
		{"kk", "kk"},
		{"ru-RU", "ru"},
		{"kk-KZ", "kk"},
		{"RU-ru", "ru"},
		{"ru-RU,ru;q=0.9,en;q=0.8", "ru"},
		{"en;q=0.5, kk-KZ;q=0.9", "kk"},
		{"en-US,en;q=0.9,ru;q=0.8", "en"},
		{"de, ru;q=0.7, kk;q=0.6", "ru"},
		{"fr, de;q=0.7", "en"},
		{"ru;q=0", "en"},
		{"ru;q=0, kk;q=0.1", "kk"},
		{"*", "en"},
		{"*;q=0.5, ru;q=0.4", "ru"},
		{"ru;q=abc", "en"},
		{"ru;q=2", "en"},
		{"ru;q=-1", "en"},
		{"ru;level=1", "en"},
		{"xx-RU", "en"},
		{"kk_KZ", "en"},
		{"ru;q=0.5, kk;q=0.5", "ru"}, // equal q: the earlier one
		{"kk;q=0.5, ru;q=0.5", "kk"},
		{" ru ; q=0.9 , en ; q=0.1 ", "ru"},
		{strings.Repeat("de,", 100) + "ru", "en"}, // entries past the cap are not looked at
		{";;;,,,", "en"},
	}
	for _, tt := range tests {
		if got := matchAcceptLanguage(tt.header); got != tt.want {
			t.Errorf("matchAcceptLanguage(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestNegotiateLang(t *testing.T) {
	tests := []struct {
		name, query, accept, formLang, want string
	}{
		{"default", "", "", "", "en"},
		{"param", "lang=ru", "", "", "ru"},
		{"param beats header", "lang=kk", "ru", "", "kk"},
		{"header", "", "kk-KZ,kk;q=0.9", "", "kk"},
		{"unknown param falls to header", "lang=fr", "ru", "", "ru"},
		{"unknown param falls to default", "lang=fr", "", "", "en"},
		{"hostile param", "lang=" + url.QueryEscape(`ru"><script>`), "", "", "en"},
		{"uppercase param is unknown", "lang=RU", "", "", "en"},
		{"region param is unknown", "lang=ru-RU", "", "", "en"},
		{"empty param", "lang=", "kk", "", "kk"},
		{"form beats query", "lang=ru", "", "kk", "kk"},
		{"unknown form falls to query", "lang=ru", "", "xx", "ru"},
		{"unknown form falls to header", "", "kk", "xx", "kk"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+tt.query, nil)
			if tt.accept != "" {
				r.Header.Set("Accept-Language", tt.accept)
			}
			if got := negotiateLang(r, tt.formLang); got != tt.want {
				t.Errorf("negotiateLang = %q, want %q", got, tt.want)
			}
		})
	}
}

// getLang GETs the authorize form with the given extra query and headers.
func (e *azEnv) getWith(q url.Values, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, PathAuthorize+"?"+q.Encode(), nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func TestPageLanguageNegotiation(t *testing.T) {
	e := newAZ(t)
	tests := []struct {
		name   string
		mod    func(url.Values)
		accept string
		lang   string
		button string
	}{
		{"default", nil, "", "en", ">Authorize</button>"},
		{"accept ru", nil, "ru-RU,ru;q=0.9,en;q=0.8", "ru", ">Разрешить</button>"},
		{"accept kk", nil, "kk-KZ", "kk", ">Рұқсат беру</button>"},
		{"param beats accept", func(q url.Values) { q.Set("lang", "kk") }, "ru", "kk", ">Рұқсат беру</button>"},
		{"unknown param", func(q url.Values) { q.Set("lang", "zz") }, "ru", "ru", ">Разрешить</button>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rec *httptest.ResponseRecorder
			if tt.accept == "" {
				rec = e.getWith(e.query(tt.mod))
			} else {
				rec = e.getWith(e.query(tt.mod), "Accept-Language", tt.accept)
			}
			mustPage(t, rec, http.StatusOK)
			body := rec.Body.String()
			for _, want := range []string{`<html lang="` + tt.lang + `">`, tt.button, `<input type="hidden" name="lang" value="` + tt.lang + `">`} {
				if !strings.Contains(body, want) {
					t.Errorf("page lacks %q", want)
				}
			}
		})
	}
}

var switcherRe = regexp.MustCompile(`<a href="([^"]+)" lang="(\w+)" hreflang="(\w+)"( aria-current="true")?>([^<]+)</a>`)

type switcherLink struct {
	href, code, name string
	current          bool
}

func switcher(t *testing.T, body string) []switcherLink {
	t.Helper()
	var out []switcherLink
	for _, m := range switcherRe.FindAllStringSubmatch(body, -1) {
		if m[2] != m[3] {
			t.Errorf("lang %q != hreflang %q", m[2], m[3])
		}
		out = append(out, switcherLink{html.UnescapeString(m[1]), m[2], m[5], m[4] != ""})
	}
	return out
}

func TestSwitcher(t *testing.T) {
	e := newAZ(t)
	q := e.query(func(q url.Values) {
		q.Set("lang", "ru")
		q.Set("evil", `"><script>alert(1)</script>`)
		q.Set("utm_source", "sekret-marker")
	})
	rec := e.getWith(q)
	mustPage(t, rec, http.StatusOK)
	body := rec.Body.String()
	links := switcher(t, body)
	if len(links) != 3 {
		t.Fatalf("%d switcher links in:\n%s", len(links), body)
	}
	for i, want := range []struct{ code, name string }{{"en", "English"}, {"ru", "Русский"}, {"kk", "Қазақша"}} {
		l := links[i]
		if l.code != want.code || l.name != want.name {
			t.Errorf("link %d = %s %q, want %s %q (order is English, Русский, Қазақша)", i, l.code, l.name, want.code, want.name)
		}
		if l.current != (l.code == "ru") {
			t.Errorf("link %s: aria-current = %v", l.code, l.current)
		}
		u, err := url.Parse(l.href)
		if err != nil || u.Path != PathAuthorize {
			t.Fatalf("href %q: %v", l.href, err)
		}
		got := u.Query()
		if got.Get("lang") != l.code {
			t.Errorf("link %s: lang = %q", l.code, got.Get("lang"))
		}
		// Exactly the validated request, nothing from the raw query.
		want := url.Values{
			"client_id": {e.clientID}, "redirect_uri": {cbClaudeAI}, "response_type": {"code"},
			"code_challenge": {azChallenge}, "code_challenge_method": {"S256"}, "state": {"st&te 1"},
			"resource": {azRes}, "lang": {l.code},
		}
		if len(got) != len(want) {
			t.Errorf("link %s has parameters %v, want %v", l.code, got, want)
		}
		for k, v := range want {
			if got.Get(k) != v[0] {
				t.Errorf("link %s: %s = %q, want %q", l.code, k, got.Get(k), v[0])
			}
		}
	}
	for _, bad := range []string{"evil", "<script", "sekret-marker", "utm_source"} {
		if strings.Contains(body, bad) {
			t.Errorf("page echoes the raw query: %q", bad)
		}
	}

	// A link leads to the same form in the other language.
	for _, l := range links {
		req := httptest.NewRequest(http.MethodGet, l.href, nil)
		r := httptest.NewRecorder()
		e.mux.ServeHTTP(r, req)
		mustPage(t, r, http.StatusOK)
		if !strings.Contains(r.Body.String(), `<html lang="`+l.code+`">`) {
			t.Errorf("link %s does not open a %s page", l.code, l.code)
		}
	}
}

func TestSwitcherWithoutState(t *testing.T) {
	e := newAZ(t)
	rec := e.getWith(e.query(func(q url.Values) { q.Del("state") }))
	for _, l := range switcher(t, rec.Body.String()) {
		if strings.Contains(l.href, "state") {
			t.Errorf("link %s has a state: %s", l.code, l.href)
		}
	}
}

func TestSwitcherSingleUpstreamWithoutResource(t *testing.T) {
	e := newAZ(t)
	rec := e.getWith(e.query(func(q url.Values) { q.Del("resource") }))
	mustPage(t, rec, http.StatusOK)
	links := switcher(t, rec.Body.String())
	if len(links) != 3 {
		t.Fatalf("%d links", len(links))
	}
	r := httptest.NewRecorder()
	e.mux.ServeHTTP(r, httptest.NewRequest(http.MethodGet, links[1].href, nil))
	mustPage(t, r, http.StatusOK) // the resource the server filled in resolves again
}

// After a POST re-render the sealed state is not in the URL; the links still
// lead back to a working GET of the validated request, in the other language.
func TestSwitcherAfterPostRerender(t *testing.T) {
	e := newAZ(t)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	f := goodForm(sealed)
	f.Set("cred_0", "")
	f.Set("lang", "kk")
	rec := e.post(f)
	mustPage(t, rec, http.StatusBadRequest)
	links := switcher(t, rec.Body.String())
	if len(links) != 3 || !links[2].current || links[0].current {
		t.Fatalf("links after POST = %+v", links)
	}
	r := httptest.NewRecorder()
	e.mux.ServeHTTP(r, httptest.NewRequest(http.MethodGet, links[1].href, nil))
	mustPage(t, r, http.StatusOK)
	if !strings.Contains(r.Body.String(), `<html lang="ru">`) {
		t.Error("link did not open the Russian form")
	}
}

func TestPostKeepsLanguage(t *testing.T) {
	e := newAZ(t)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	f := goodForm(sealed)
	f.Set("cred_0", "")
	f.Set("lang", "ru")
	rec := e.post(f, "Accept-Language", "kk")
	mustPage(t, rec, http.StatusBadRequest)
	body := rec.Body.String()
	for _, want := range []string{`<html lang="ru">`, `name="lang" value="ru"`, "<p>Поле «API key» обязательно.</p>"} {
		if !strings.Contains(body, want) {
			t.Errorf("re-rendered form lacks %q", want)
		}
	}
	f.Set("lang", `ru"><script>`)
	rec = e.post(f)
	if body := rec.Body.String(); !strings.Contains(body, `<html lang="en">`) || strings.Contains(body, "<script") {
		t.Errorf("hostile lang not ignored:\n%s", body)
	}
}

// The language of the form never changes the outcome of the submit.
func TestPostLanguageDoesNotAffectAuthorization(t *testing.T) {
	for _, lang := range []string{"", "en", "ru", "kk", "zz", `x"y`} {
		e := newAZ(t)
		sealed := hidden(t, e.get(e.query(nil)).Body.String())
		f := goodForm(sealed)
		if lang != "" {
			f.Set("lang", lang)
		}
		u := mustSeeOther(t, e.post(f))
		if u.Query().Get("code") == "" {
			t.Errorf("lang %q: no code issued", lang)
		}
		bad := goodForm(sealed)
		bad.Set("cred_0", "")
		bad.Set("lang", lang)
		if rec := e.post(bad); rec.Code != http.StatusBadRequest {
			t.Errorf("lang %q: bad submit status %d", lang, rec.Code)
		}
	}
}

func TestErrorPagesAreLocalized(t *testing.T) {
	e := newAZ(t)
	// GET with a bad client: Accept-Language and the lang parameter both work.
	rec := e.getWith(url.Values{"client_id": {"nope"}}, "Accept-Language", "ru")
	mustPage(t, rec, http.StatusBadRequest)
	for _, want := range []string{`<html lang="ru">`, "<title>Ошибка авторизации</title>", "client_id не распознан", "Вернитесь в приложение"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("ru error page lacks %q", want)
		}
	}
	rec = e.getWith(url.Values{"client_id": {"nope"}, "lang": {"kk"}}, "Accept-Language", "ru")
	if !strings.Contains(rec.Body.String(), "<title>Авторизация қатесі</title>") {
		t.Errorf("kk error page:\n%s", rec.Body)
	}
	// The error page has no switcher: its link could not be rebuilt without
	// echoing the raw query.
	if strings.Contains(rec.Body.String(), `class="lang"`) {
		t.Error("error page has a language switcher")
	}

	// POST failure: cross-site, in the language of the form.
	f := url.Values{requestField: {"x"}, "lang": {"ru"}}
	rec = e.post(f, "Sec-Fetch-Site", "cross-site", "Accept-Language", "ru") // the body is not read for a cross-site POST
	mustPage(t, rec, http.StatusForbidden)
	if !strings.Contains(rec.Body.String(), "Отправка формы с другого сайта не разрешена.") {
		t.Errorf("cross-site error not in ru:\n%s", rec.Body)
	}
	// An invalid sealed request.
	rec = e.post(url.Values{requestField: {"garbage"}, "lang": {"kk"}})
	mustPage(t, rec, http.StatusBadRequest)
	if !strings.Contains(rec.Body.String(), "Авторизация сұрауы жарамсыз") {
		t.Errorf("expired request not in kk:\n%s", rec.Body)
	}
}

func TestDenyAuthorizeIsLocalized(t *testing.T) {
	e := newAZ(t)
	for lang, want := range map[string]string{"ru": "Слишком много запросов.", "kk": "Сұраулар тым көп.", "en": "Too many requests."} {
		rec := httptest.NewRecorder()
		e.srv.denyAuthorize(rec, httptest.NewRequest(http.MethodGet, PathAuthorize+"?lang="+lang, nil))
		if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s: %d %s", lang, rec.Code, rec.Body)
		}
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, PathAuthorize, nil)
	r.Header.Set("Accept-Language", "ru")
	e.srv.denyAuthorize(rec, r)
	if !strings.Contains(rec.Body.String(), "Слишком много запросов.") {
		t.Errorf("accept-language:\n%s", rec.Body)
	}
}

func TestRedirectInternalErrorIsLocalized(t *testing.T) {
	e := newAZ(t)
	rec := httptest.NewRecorder()
	e.srv.redirect(rec, httptest.NewRequest(http.MethodGet, PathAuthorize, nil), newLocale("ru"), "http://[::1", "", nil)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "Внутренняя ошибка сервера.") {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
}

// Everything the operator can configure, for rendering in every language.
func fullI18nEnv(t *testing.T) *azEnv {
	t.Helper()
	up := auditUpstream()
	up.Credentials[0].Labels = map[string]string{"en": "API key", "ru": "Ключ API", "kk": "API кілті"}
	up.Credentials[1].Labels = map[string]string{"en": "User", "ru": "Пользователь"} // no kk
	e := newAZ(t, up)
	e.srv.cfg.Audit = config.Audit{Enabled: true}
	e.srv.cfg.OAuth.Page = config.Page{
		Contact: "mailto:ops@example.org",
		Notice:  map[string]string{"en": "Free service.\n\nAs is.", "ru": "Бесплатный сервис.\n\nКак есть."},
		Terms: &config.Terms{
			Version: "2026-10-10",
			Body:    map[string]string{"en": "Terms one.\n\nTerms two.", "ru": "Условия раз.\n\nУсловия два."},
			URL:     map[string]string{"en": "https://example.org/terms", "ru": "https://example.org/ru"},
		},
	}
	return e
}

func TestEveryLanguageRenders(t *testing.T) {
	e := fullI18nEnv(t)
	for _, l := range pageLangs {
		t.Run(l.Code, func(t *testing.T) {
			rec := e.getWith(e.query(func(q url.Values) { q.Set("lang", l.Code) }))
			mustPage(t, rec, http.StatusOK)
			body := rec.Body.String()
			if !strings.Contains(body, `<html lang="`+l.Code+`">`) || strings.Contains(body, "%!") || strings.Contains(body, "<no value>") {
				t.Errorf("bad page:\n%s", body)
			}
			for id := range catalog[defaultLang] {
				if strings.HasPrefix(id, "err.") || strings.HasPrefix(id, "cred.") || id == msgTermsRequired {
					continue // banners, not part of the plain form
				}
				if id == "client.unnamed" || id == "hint.plain" || id == "audit.your" || id == "page.title" || id == "page.request_tail" ||
					id == "terms.summary" || id == "error.title" || id == "error.hint" {
					continue // arguments or other page
				}
				if want := newLocale(l.Code).T(id); !strings.Contains(body, html.EscapeString(want)) {
					t.Errorf("page lacks %s %q", id, want)
				}
			}

			// The error page of each language.
			rec = e.getWith(url.Values{"client_id": {"nope"}, "lang": {l.Code}})
			mustPage(t, rec, http.StatusBadRequest)
			if want := newLocale(l.Code).T("error.title"); !strings.Contains(rec.Body.String(), "<title>"+want+"</title>") {
				t.Errorf("error page lacks %q", want)
			}
			// Every server message renders through the form banner.
			for id, text := range catalog[l.Code] {
				if strings.HasPrefix(id, "err.") {
					rec := httptest.NewRecorder()
					e.srv.writeErrorPage(rec, http.StatusBadRequest, newLocale(l.Code), uiMsg(id))
					if !strings.Contains(rec.Body.String(), html.EscapeString(text)) {
						t.Errorf("%s/%s not rendered", l.Code, id)
					}
				}
			}
		})
	}
}

func TestPerLanguageOperatorText(t *testing.T) {
	e := fullI18nEnv(t)
	tests := []struct {
		lang   string
		want   []string
		absent []string
	}{
		{"en", []string{"<label for=\"cred_0\">API key</label>", "<li>Your User</li>", "These records are kept by the server.", "<p>Free service.</p>", "Terms one."}, []string{"Ключ API"}},
		{"ru", []string{
			"<label for=\"cred_0\">Ключ API</label>",
			"<li>Значение «Пользователь»</li>",
			"Эти записи хранятся на сервере.",
			"<p>Бесплатный сервис.</p>",
			"<p>Условия раз.</p>",
			`<a href="https://example.org/ru" rel="noopener">Полный текст</a>`,
			`<span class="chip">Ключ API</span>`,
			`<span class="chip" lang="en">Extra</span>`,
		}, nil},
		// kk: every operator text falls back to en and is marked as such.
		{"kk", []string{
			"<label for=\"cred_0\">API кілті</label>",
			`<li>«<span lang="en">User</span>» мәні</li>`,
			"Бұл жазбалар серверде сақталады.",
			`<p lang="en">Free service.</p>`,
			`<div class="terms-body" tabindex="0" role="region" aria-label="Пайдалану шарттарының мәтіні" lang="en">`,
			`<p>Terms one.</p>`,
			`<a href="https://example.org/terms" rel="noopener" lang="en" hreflang="en">Толық мәтін</a>`,
			`<span class="chip">API кілті</span>`,
			`<span class="chip" lang="en">Extra</span>`,
		}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.lang, func(t *testing.T) {
			rec := e.getWith(e.query(func(q url.Values) { q.Set("lang", tt.lang) }))
			mustPage(t, rec, http.StatusOK)
			body := rec.Body.String()
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

func TestPerLanguageLabelInBanner(t *testing.T) {
	e := fullI18nEnv(t)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	f := goodForm(sealed)
	f.Set("cred_0", "")
	f.Set("lang", "ru")
	f.Set(acceptTermsField, "on")
	rec := e.post(f)
	if !strings.Contains(rec.Body.String(), "<p>Поле «Ключ API» обязательно.</p>") {
		t.Errorf("localized label not used in the banner:\n%s", rec.Body)
	}
}

func setTerms(e *azEnv) {
	e.srv.cfg.OAuth.Page.Terms = &config.Terms{
		Version: "2026-10-10",
		Body:    map[string]string{"en": "Free.\n\nAs is.", "ru": "Бесплатно.\n\nКак есть."},
		URL:     map[string]string{"en": "https://example.org/terms"},
	}
}

func TestTermsRendering(t *testing.T) {
	e := newAZ(t)
	if b := pageBody(t, e); strings.Contains(b, "accept_terms") || strings.Contains(b, "<details") {
		t.Errorf("terms rendered without config:\n%s", b)
	}
	setTerms(e)
	b := pageBody(t, e)
	for _, want := range []string{
		`<details class="terms">`,
		`<summary>Terms of use (version 2026-10-10)</summary>`,
		`role="region" aria-label="Terms of use text"`,
		`<p>Free.</p>`, `<p>As is.</p>`,
		`<p class="full"><a href="https://example.org/terms" rel="noopener">Full text</a></p>`,
		`<input type="checkbox" name="accept_terms" value="on" required>`,
		"I have read and accept the terms of use",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("page lacks %q:\n%s", want, b)
		}
	}
	for _, bad := range []string{`class="check bad"`, "aria-invalid", `role="alert"`} {
		if strings.Contains(b, bad) {
			t.Errorf("fresh page contains %q", bad)
		}
	}
	// Order: terms, hint, checkbox, button.
	idx := func(s string) int { return strings.Index(b, s) }
	if idx("<details") >= idx(`class="hint"`) || idx(`class="hint"`) >= idx(`name="accept_terms"`) || idx(`name="accept_terms"`) >= idx("<button") {
		t.Error("terms block, hint, checkbox, button are out of order")
	}

	// No URL: no "Full text" row.
	e.srv.cfg.OAuth.Page.Terms.URL = nil
	if b := pageBody(t, e); strings.Contains(b, "Full text") {
		t.Error("full text link without a URL")
	}
}

func TestTermsEscaping(t *testing.T) {
	e := newAZ(t)
	e.srv.cfg.OAuth.Page.Terms = &config.Terms{
		Version: `<i>v</i>&"1`,
		Body:    map[string]string{"en": "<script>alert(1)</script>\n\n<img src=x onerror=alert(2)> & \"q\""},
		URL:     map[string]string{"en": `https://example.org/"><script>alert(3)</script>`},
	}
	b := pageBody(t, e)
	for _, bad := range []string{"<script", "<img", "<i>v</i>", `"><script`, "onerror=alert(2)>"} {
		if strings.Contains(b, bad) {
			t.Errorf("page contains raw %q:\n%s", bad, b)
		}
	}
	for _, want := range []string{"&lt;script&gt;alert(1)", "&lt;img src=x", "&lt;i&gt;v&lt;/i&gt;"} {
		if !strings.Contains(b, want) {
			t.Errorf("page lacks escaped %q", want)
		}
	}
}

func TestTermsEnforcement(t *testing.T) {
	e := newAZ(t)
	setTerms(e)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())

	for name, mod := range map[string]func(url.Values){
		"absent": func(url.Values) {},
		"off":    func(f url.Values) { f.Set(acceptTermsField, "off") },
		"one":    func(f url.Values) { f.Set(acceptTermsField, "1") },
		"true":   func(f url.Values) { f.Set(acceptTermsField, "true") },
		"empty":  func(f url.Values) { f.Set(acceptTermsField, "") },
		"ON":     func(f url.Values) { f.Set(acceptTermsField, "ON") },
	} {
		t.Run("refused "+name, func(t *testing.T) {
			f := goodForm(sealed)
			f.Set("cred_2", "extra-value")
			f.Set("lang", "ru")
			mod(f)
			rec := e.post(f)
			mustPage(t, rec, http.StatusBadRequest)
			b := rec.Body.String()
			for _, want := range []string{
				`<div class="err" role="alert" id="err">`, "<p>Чтобы продолжить, примите условия использования.</p>",
				`class="check bad"`, `aria-invalid="true" aria-describedby="err"`,
				`value="alice"`, `value="extra-value"`, // non-secret values are kept
			} {
				if !strings.Contains(b, want) {
					t.Errorf("re-rendered form lacks %q", want)
				}
			}
			if strings.Contains(b, "sekret") {
				t.Error("secret echoed")
			}
			if rec.Header().Get("Location") != "" {
				t.Error("redirected without acceptance")
			}
		})
	}

	f := goodForm(sealed)
	f.Set(acceptTermsField, "on")
	mustSeeOther(t, e.post(f))
}

// Without acceptance nothing downstream runs: no upstream call, and the global
// ceiling on issued codes is untouched.
func TestTermsRefusalCostsNothing(t *testing.T) {
	f := newMCPFake(t)
	e, _ := newCeiling(t, f, 1, nil)
	setTerms(e)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	for i := 0; i < 20; i++ {
		rec := e.postFrom(fmt.Sprintf("203.0.113.%d:1", i+20), goodForm(sealed))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
	if n := len(f.requests()); n != 0 {
		t.Fatalf("upstream contacted %d times without acceptance", n)
	}
	// The burst of one code is still there.
	form := goodForm(sealed)
	form.Set(acceptTermsField, "on")
	mustSeeOther(t, e.postFrom("203.0.113.10:1", form))
	if len(f.requests()) == 0 {
		t.Error("fixture: the accepted submit never reached the upstream")
	}
}

// The acceptance is asked before the credentials are looked at: even an
// invalid credential gets the terms message first, with the allow-list and the
// size budget never consulted.
func TestTermsCheckedBeforeCredentialChecks(t *testing.T) {
	f := newMCPFake(t)
	e := newAZValidated(t, f, allowUser)
	setTerms(e)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	form := goodForm(sealed)
	form.Set("cred_1", "mallory") // not in the allow-list
	rec := e.post(form)
	mustPage(t, rec, http.StatusBadRequest)
	if !strings.Contains(rec.Body.String(), en(msgTermsRequired)) || strings.Contains(rec.Body.String(), rejectedMsg) {
		t.Errorf("terms message expected:\n%s", rec.Body)
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("upstream contacted %d times", n)
	}
}

func TestTermsIgnoredWhenNotConfigured(t *testing.T) {
	e := newAZ(t)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	mustSeeOther(t, e.post(goodForm(sealed))) // no accept_terms needed
}

func TestAuditRecordLangAndTerms(t *testing.T) {
	e := newAZ(t, auditUpstream())
	buf := enableAudit(e.srv, true)
	setTerms(e)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())

	refused := goodForm(sealed)
	refused.Set("lang", "ru")
	mustPage(t, e.post(refused), http.StatusBadRequest)
	if n := len(buf.audits(t, "authorize")); n != 0 {
		t.Fatalf("authorize record for a refused submit (%d)", n)
	}

	f := goodForm(sealed)
	f.Set(acceptTermsField, "on")
	f.Set("lang", "ru")
	mustSeeOther(t, e.post(f))
	recs := buf.audits(t, "authorize")
	if len(recs) != 1 {
		t.Fatalf("%d records", len(recs))
	}
	if recs[0]["terms_version"] != "2026-10-10" || recs[0]["lang"] != "ru" {
		t.Errorf("record = %v", recs[0])
	}

	// Without terms: lang is recorded, terms_version is absent.
	e2 := newAZ(t, auditUpstream())
	buf2 := enableAudit(e2.srv, true)
	sealed2 := hidden(t, e2.get(e2.query(nil)).Body.String())
	mustSeeOther(t, e2.post(goodForm(sealed2), "Accept-Language", "kk"))
	r2 := buf2.audits(t, "authorize")[0]
	if _, ok := r2["terms_version"]; ok || r2["lang"] != "kk" {
		t.Errorf("record without terms = %v", r2)
	}
}

// A form rendered under one terms version is not accepted under another: the
// submit re-renders with the current terms and a form bound to them.
func TestTermsVersionBoundToForm(t *testing.T) {
	e := newAZ(t, auditUpstream())
	buf := enableAudit(e.srv, true)
	setTerms(e)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())

	e.srv.cfg.OAuth.Page.Terms.Version = "2027-01-01" // config changed and restarted
	f := goodForm(sealed)
	f.Set(acceptTermsField, "on")
	rec := e.post(f)
	mustPage(t, rec, http.StatusBadRequest)
	b := rec.Body.String()
	for _, want := range []string{en(msgTermsRequired), "Terms of use (version 2027-01-01)", `class="check bad"`} {
		if !strings.Contains(b, want) {
			t.Errorf("re-render lacks %q", want)
		}
	}
	if len(buf.audits(t, "authorize")) != 0 {
		t.Fatal("authorize record for a stale form")
	}

	// The re-rendered form carries the new binding and now succeeds.
	f2 := goodForm(hidden(t, b))
	f2.Set(acceptTermsField, "on")
	mustSeeOther(t, e.post(f2))
	r := buf.audits(t, "authorize")[0]
	if r["terms_version"] != "2027-01-01" || r["terms_lang"] != "en" {
		t.Errorf("record = %v", r)
	}

	// A form rendered before terms existed is stale too.
	e2 := newAZ(t)
	s2 := hidden(t, e2.get(e2.query(nil)).Body.String())
	setTerms(e2)
	f3 := goodForm(s2)
	f3.Set(acceptTermsField, "on")
	mustPage(t, e2.post(f3), http.StatusBadRequest)
}

func TestAuditTermsLang(t *testing.T) {
	e := newAZ(t, auditUpstream())
	buf := enableAudit(e.srv, true)
	setTerms(e)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	f := goodForm(sealed)
	f.Set(acceptTermsField, "on")
	f.Set("lang", "ru")
	mustSeeOther(t, e.post(f))
	if r := buf.audits(t, "authorize")[0]; r["terms_lang"] != "ru" || r["lang"] != "ru" {
		t.Errorf("record = %v", r)
	}
	// kk has no terms text: the English text was shown, and that is recorded.
	f.Set("lang", "kk")
	mustSeeOther(t, e.post(f))
	if r := buf.audits(t, "authorize")[1]; r["terms_lang"] != "en" || r["lang"] != "kk" {
		t.Errorf("record = %v", r)
	}
}

// Every Slot message contains its argument exactly once, in every language.
func TestSlotMessagesUseArgumentOnce(t *testing.T) {
	for lang, msgs := range catalog {
		if n := strings.Count(msgs["audit.your"], "%[1]s"); n != 1 {
			t.Errorf("%s/audit.your has %d arguments: %q", lang, n, msgs["audit.your"])
		}
	}
	// A translation that broke the rule degrades to the unsplit text.
	catalog["zz"] = map[string]string{"audit.your": "x"}
	t.Cleanup(func() { delete(catalog, "zz") })
	s := newLocale("zz").Slot("audit.your", config.LangText{Text: "L", Lang: "en"})
	if s.Lang != "" || s.Text == "" {
		t.Errorf("slot = %+v", s)
	}
}
