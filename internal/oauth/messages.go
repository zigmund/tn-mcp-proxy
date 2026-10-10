package oauth

import "fmt"

// defaultLang is the language of the message catalog that is always complete;
// every other language falls back to it per message.
const defaultLang = "en"

// Message ids of the authorize and error pages. Templates refer to them as
// string literals ({{.L.T "audit.heading"}}); a test checks that each one used
// there exists in the default language.
const (
	// Messages that are produced in Go (form banner, error page).
	msgInternal        = "err.internal"
	msgCrossSite       = "err.cross_site"
	msgFormTooLarge    = "err.form_too_large"
	msgFormMalformed   = "err.form_malformed"
	msgRequestExpired  = "err.request_expired"
	msgRedirectGone    = "err.redirect_gone"
	msgTooManyRequests = "err.too_many_requests"
	msgClientIDMissing = "err.client_id_missing"
	msgRedirectBad     = "err.redirect_bad"
	msgClientUnknown   = "err.client_unknown"
	msgCredRequired    = "cred.required"
	msgCredTooLong     = "cred.too_long"
	msgCredInvalid     = "cred.invalid"
	msgCredsTooLong    = "cred.together_too_long"
	msgCredsRejected   = "cred.rejected"
	msgCredsNoVerdict  = "cred.unavailable"
)

// catalog holds the page text: language code -> message id -> text. A text is
// a fmt format with explicit argument indexes (%[1]s), so a translation can
// reorder its arguments. Arguments are plain values and the result is plain
// text: html/template escapes it where it is rendered, so an argument (host,
// title, retention, label) can never inject markup. Never put HTML in a text.
//
// To add a language, add an entry under its lowercase code with any subset of
// the ids below; a missing id falls back to defaultLang.
var catalog = map[string]map[string]string{
	defaultLang: {
		"page.title":        "Connect %[1]s",
		"page.request_tail": "is requesting access to %[1]s",

		"client.name":       "Application name:",
		"client.unnamed":    "Unnamed application",
		"client.unverified": "self-declared, unverified",
		"field.optional":    "(optional)",

		"audit.heading":   "What this server logs",
		"audit.time":      "Time of each request",
		"audit.ip":        "Your IP address",
		"audit.your":      "Your %[1]s",
		"audit.tools":     "Tools called",
		"audit.retention": "Logs are kept for %[1]s.",
		"audit.never":     "Never logged or stored:",

		"notice.heading": "Notice from the operator",
		"notice.contact": "Contact:",

		// The hint is true in both modes: without audit no credential value is
		// logged, with audit only the ones the panel lists are.
		"hint.plain":    "These credentials are encrypted into the access tokens issued to the application at the address above and are not stored by this server.",
		"hint.audit":    "These credentials are encrypted into the access tokens issued to the application at the address above. Apart from what is listed above, this server does not log or store any credential values.",
		"hint.continue": "Only continue if you started this connection yourself.",

		"button.authorize": "Authorize",

		"error.title": "Authorization error",
		"error.hint":  "Go back to the application and start the connection again.",

		msgInternal:        "Internal server error.",
		msgCrossSite:       "Cross-site form submission is not allowed.",
		msgFormTooLarge:    "The submitted form is too large.",
		msgFormMalformed:   "The submitted form is malformed.",
		msgRequestExpired:  "This authorization request is invalid or has expired.",
		msgRedirectGone:    "The redirect_uri is no longer allowed for this application.",
		msgTooManyRequests: "Too many requests. Please wait a moment and try again.",
		msgClientIDMissing: "The request is missing a valid client_id.",
		msgRedirectBad:     "The redirect_uri is missing or not allowed for this application.",
		msgClientUnknown:   "The client_id is not recognized. Register the application again.",
		msgCredRequired:    "%[1]s is required.",
		msgCredTooLong:     "%[1]s is too long.",
		msgCredInvalid:     "%[1]s contains invalid characters.",
		msgCredsTooLong:    "The credentials together are too long.",
		msgCredsRejected:   "%[1]s rejected these credentials. Check them and try again.",
		msgCredsNoVerdict:  "Could not verify the credentials with %[1]s right now. Try again later.",
	},
}

// message is a catalog id with its arguments, resolved when a page is
// rendered so the language is only known there. The zero value is "no message".
type message struct {
	ID   string
	Args []any
}

func uiMsg(id string, args ...any) message { return message{ID: id, Args: args} }

// locale renders messages in one language.
type locale struct{ lang string }

// newLocale returns the locale for lang; an unknown code is the default.
func newLocale(lang string) locale {
	if _, ok := catalog[lang]; !ok {
		lang = defaultLang
	}
	return locale{lang: lang}
}

// Lang is the language code for the page's lang attribute.
func (l locale) Lang() string { return l.lang }

// T returns the text of id, formatted with args. A id missing in the
// language falls back to the default language, and one missing there is
// returned as is, so a typo is visible rather than blank.
func (l locale) T(id string, args ...any) string {
	text, ok := catalog[l.lang][id]
	if !ok {
		if text, ok = catalog[defaultLang][id]; !ok {
			return id
		}
	}
	if len(args) == 0 {
		return text
	}
	return fmt.Sprintf(text, args...)
}

// Msg renders m; the zero message is empty.
func (l locale) Msg(m message) string {
	if m.ID == "" {
		return ""
	}
	return l.T(m.ID, m.Args...)
}
