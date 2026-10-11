package oauth

import (
	"fmt"
	"strings"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

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
	msgCredsNotAllowed = "cred.not_allowed"
	msgCredsNoVerdict  = "cred.unavailable"
	msgTermsRequired   = "terms.error"
)

// catalog holds the page text: language code -> message id -> text. A text is
// a fmt format with explicit argument indexes (%[1]s), so a translation can
// reorder its arguments. Arguments are plain values and the result is plain
// text: html/template escapes it where it is rendered, so an argument (host,
// title, retention, label) can never inject markup. Never put HTML in a text.
//
// To add a language, add an entry under its lowercase code and list it in
// pageLangs; a missing id falls back to defaultLang, but a test requires the
// built-in languages (ru, kk) to cover every id.
var catalog = map[string]map[string]string{
	"ru": catalogRU,
	"kk": catalogKK,
	defaultLang: {
		"lang.nav_label": "Language",

		"terms.summary":      "Terms of use (version %[1]s)",
		"terms.region_label": "Terms of use text",
		"terms.full_text":    "Full text",
		"terms.accept":       "I have read and accept the terms of use",
		msgTermsRequired:     "Accept the terms of use to continue.",

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
		msgCredsNotAllowed: "These credentials cannot be used on this server: its operator only allows specific keys.",
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

// slot is a message with one operator-supplied argument (a label, a retention
// text) that may be written in another language than the page, in which case
// the template wraps the argument in a lang attribute. Lang is empty when the
// argument is in the page language, and Text is then the whole sentence.
type slot struct {
	Text               string
	Before, Arg, After string
	Lang               string
}

// Slot renders id with arg as its only argument, split around the argument
// when arg is in another language than the page.
func (l locale) Slot(id string, arg config.LangText) slot {
	if arg.Lang == l.lang || arg.Lang == "" {
		return slot{Text: l.T(id, arg.Text)}
	}
	const marker = "\x00"
	text := l.T(id, marker)
	before, after, _ := strings.Cut(text, marker)
	if strings.Count(l.T(id), "%[1]s") != 1 {
		return slot{Text: l.T(id, arg.Text)} // a translation must use the argument once
	}
	return slot{Before: before, Arg: arg.Text, After: after, Lang: arg.Lang}
}
