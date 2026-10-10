package oauth

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// langParam is the query (and hidden form) parameter that selects the page
// language. It only affects display, never an authorization decision.
const langParam = "lang"

// maxAcceptLangEntries bounds the work done for one Accept-Language header.
const maxAcceptLangEntries = 32

// pageLang is a built-in page language: its code and its own name, which is
// never translated.
type pageLang struct{ Code, Name string }

// pageLangs are the built-in languages in switcher order; the first is the
// default and the fallback.
var pageLangs = []pageLang{{"en", "English"}, {"ru", "Русский"}, {"kk", "Қазақша"}}

// supportedLang reports whether code is a built-in language.
func supportedLang(code string) bool {
	for _, l := range pageLangs {
		if l.Code == code {
			return true
		}
	}
	return false
}

// negotiateLang picks the page language of a request: a valid lang parameter
// (formLang, from the POST body, then the URL query), then the best
// Accept-Language match, then the default. Unknown values are ignored.
func negotiateLang(r *http.Request, formLang string) string {
	if supportedLang(formLang) {
		return formLang
	}
	if v := r.URL.Query().Get(langParam); supportedLang(v) {
		return v
	}
	return matchAcceptLanguage(r.Header.Get("Accept-Language"))
}

// matchAcceptLanguage returns the supported language with the highest q-value
// in an Accept-Language header (RFC 9110 §12.5.4). A region is ignored
// ("ru-RU" is ru); q=0 means "not acceptable"; among equal q-values the
// earlier entry wins. The result is the default language when nothing matches.
func matchAcceptLanguage(header string) string {
	best, bestQ := defaultLang, 0.0
	for i, part := range strings.SplitN(header, ",", maxAcceptLangEntries+1) {
		if i >= maxAcceptLangEntries {
			break
		}
		tag, params, _ := strings.Cut(part, ";")
		tag = strings.ToLower(strings.TrimSpace(tag))
		primary, _, _ := strings.Cut(tag, "-")
		if !supportedLang(primary) {
			continue
		}
		q := 1.0
		if params = strings.TrimSpace(params); params != "" {
			name, val, ok := strings.Cut(params, "=")
			if !ok || strings.ToLower(strings.TrimSpace(name)) != "q" {
				continue
			}
			f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
			if err != nil || f < 0 || f > 1 {
				continue
			}
			q = f
		}
		if q > bestQ {
			best, bestQ = primary, q
		}
	}
	return best
}

// langLink is one entry of the language switcher.
type langLink struct {
	Code, Name, URL string
	Current         bool
}

// langLinks builds the switcher for the authorize page from the validated
// request: each link is /oauth/authorize with the request's parameters and
// lang=xx. Only values the server has validated (and sealed) are used, never
// the raw query, so nothing a client sent can reach a link, and the links
// also work from a page rendered after a POST.
func langLinks(cur locale, req authRequest, resource string) []langLink {
	q := url.Values{
		"client_id":             {req.ClientID},
		"redirect_uri":          {req.RedirectURI},
		"response_type":         {"code"},
		"code_challenge":        {req.CodeChallenge},
		"code_challenge_method": {"S256"},
		"resource":              {resource},
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	base := PathAuthorize + "?" + q.Encode() + "&" + langParam + "="
	links := make([]langLink, len(pageLangs))
	for i, l := range pageLangs {
		links[i] = langLink{Code: l.Code, Name: l.Name, URL: base + l.Code, Current: l.Code == cur.Lang()}
	}
	return links
}
