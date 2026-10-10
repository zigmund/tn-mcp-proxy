package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits of the operator page config (oauth.page).
const (
	// MaxPageContactLen is the longest oauth.page.contact, in bytes.
	MaxPageContactLen = 256
	// MaxPageNoticeLen is the longest single oauth.page.notice text, in bytes.
	MaxPageNoticeLen = 4 << 10
	// MaxPageNoticeLangs is the most languages oauth.page.notice may carry.
	MaxPageNoticeLangs = 32
	// DefaultNoticeLang is the notice language used when the requested one has
	// no entry.
	DefaultNoticeLang = "en"
)

var noticeLangRe = regexp.MustCompile(`^[a-z]{2,3}$`)

// Page is the operator's contribution to the authorize page, shown under
// "Notice from the operator". Both parts are optional. The text is plain: it
// is HTML-escaped on output and never interpreted.
type Page struct {
	// Contact is a mailto: address or an https:// URL, shown as a link.
	Contact string `yaml:"contact"`
	// Notice maps a lowercase language code (2 or 3 letters) to plain text;
	// paragraphs are separated by blank lines. It must have an "en" entry.
	Notice map[string]string `yaml:"notice"`
}

// validate checks p. Errors are prefixed with the field name and never echo
// the offending text.
func (p Page) validate() []error {
	var errs []error
	if p.Contact != "" {
		if err := checkContact(p.Contact); err != nil {
			errs = append(errs, fmt.Errorf("oauth.page.contact: %w", err))
		}
	}
	if len(p.Notice) > MaxPageNoticeLangs {
		errs = append(errs, fmt.Errorf("oauth.page.notice: more than %d languages", MaxPageNoticeLangs))
	}
	if _, ok := p.Notice[DefaultNoticeLang]; len(p.Notice) > 0 && !ok {
		errs = append(errs, fmt.Errorf("oauth.page.notice.%s: required when oauth.page.notice is set", DefaultNoticeLang))
	}
	for _, lang := range p.noticeLangs() {
		field := "oauth.page.notice." + lang
		text := p.Notice[lang]
		switch {
		case !noticeLangRe.MatchString(lang):
			// The key is not echoed: it is unbounded operator input.
			errs = append(errs, errors.New("oauth.page.notice: every key must be a lowercase language code of 2 or 3 letters"))
		case strings.TrimSpace(text) == "":
			errs = append(errs, fmt.Errorf("%s: must not be empty", field))
		case len(text) > MaxPageNoticeLen:
			errs = append(errs, fmt.Errorf("%s: longer than %d bytes", field, MaxPageNoticeLen))
		case !utf8.ValidString(text) || strings.ContainsFunc(text, func(r rune) bool {
			return (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.Is(unicode.Cf, r)
		}):
			errs = append(errs, fmt.Errorf("%s: must be valid UTF-8 text without control or format characters (newline and tab are allowed)", field))
		}
	}
	return errs
}

// checkContact accepts a mailto: address or an https:// URL with a host.
func checkContact(c string) error {
	if len(c) > MaxPageContactLen {
		return fmt.Errorf("longer than %d bytes", MaxPageContactLen)
	}
	if !utf8.ValidString(c) || strings.ContainsFunc(c, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) }) {
		return errors.New("must not contain whitespace, control or format characters")
	}
	switch {
	case strings.HasPrefix(c, "mailto:"):
		if len(c) == len("mailto:") {
			return errors.New("mailto: needs an address")
		}
		return nil
	case strings.HasPrefix(c, "https://"):
		u, err := url.Parse(c)
		if err != nil || u.Hostname() == "" || u.User != nil {
			return errors.New("must be a valid https:// URL with a host and no user info")
		}
		return nil
	}
	return errors.New("must start with mailto: or https://")
}

// normalize trims the contact and each notice text and converts CRLF line
// endings, so a config file edited on Windows validates the same.
func (p *Page) normalize() {
	p.Contact = strings.TrimSpace(p.Contact)
	for lang, text := range p.Notice {
		p.Notice[lang] = strings.TrimSpace(strings.ReplaceAll(text, "\r\n", "\n"))
	}
}

// noticeLangs returns the notice language codes in sorted order, the
// deterministic order every accessor uses (a YAML mapping has no meaningful one).
func (p Page) noticeLangs() []string {
	langs := make([]string, 0, len(p.Notice))
	for l := range p.Notice {
		langs = append(langs, l)
	}
	sort.Strings(langs)
	return langs
}

// NoticeFor returns the notice text for lang, falling back to DefaultNoticeLang
// ("en", which validation requires whenever a notice is set). It is empty when
// no notice is configured.
func (p Page) NoticeFor(lang string) string {
	if t, ok := p.Notice[lang]; ok {
		return t
	}
	if t, ok := p.Notice[DefaultNoticeLang]; ok {
		return t
	}
	return ""
}

// NoticeParagraphs is NoticeFor split into paragraphs on blank lines, each
// trimmed, empty ones dropped.
func (p Page) NoticeParagraphs(lang string) []string {
	var out []string
	for _, para := range blankLineRe.Split(p.NoticeFor(lang), -1) {
		if para = strings.TrimSpace(para); para != "" {
			out = append(out, para)
		}
	}
	return slices.Clip(out)
}

var blankLineRe = regexp.MustCompile(`\n[ \t]*\n`)

// ContactHref is the link target for Contact: the contact itself, or empty
// when none is configured.
func (p Page) ContactHref() string { return p.Contact }

// ContactText is the visible link text of Contact: the contact without a
// leading "mailto:".
func (p Page) ContactText() string { return strings.TrimPrefix(p.Contact, "mailto:") }
