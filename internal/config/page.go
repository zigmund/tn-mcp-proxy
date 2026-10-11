package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits of the operator page config (oauth.page).
const (
	// MaxPageContactLen is the longest oauth.page.contact, in bytes.
	MaxPageContactLen = 256
	// MaxPageNoticeLen is the longest oauth.page.notice, in bytes.
	MaxPageNoticeLen = 4 << 10
)

// Page is the operator's contribution to the authorize page. Notice and
// Contact are shown under "Notice from the operator"; TermsFile adds the
// terms of use the user must accept. All parts are optional. The texts are
// plain: they are HTML-escaped on output and never interpreted.
type Page struct {
	// Contact is a mailto: address or an https:// URL, shown as a link.
	Contact string `yaml:"contact"`
	// Notice is plain text; paragraphs are separated by blank lines.
	Notice string `yaml:"notice"`
	// TermsFile is the path of a plain-text file with the terms of use;
	// paragraphs are separated by blank lines. When set, the user must accept
	// the terms on the form. It is read when the config is loaded.
	TermsFile string `yaml:"terms_file"`

	// TermsText is the normalized content of TermsFile, filled by Parse. It is
	// not part of the YAML.
	TermsText string `yaml:"-"`
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
	switch {
	case len(p.Notice) > MaxPageNoticeLen:
		errs = append(errs, fmt.Errorf("oauth.page.notice: longer than %d bytes", MaxPageNoticeLen))
	case badText(p.Notice, true):
		errs = append(errs, errors.New("oauth.page.notice: must be valid UTF-8 text without control or format characters (newline and tab are allowed)"))
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

// normalize trims the contact, the notice and the terms path, and converts
// CRLF line endings in the notice, so a config file edited on Windows
// validates the same.
func (p *Page) normalize() {
	p.Contact = strings.TrimSpace(p.Contact)
	p.Notice = strings.TrimSpace(strings.ReplaceAll(p.Notice, "\r\n", "\n"))
	p.TermsFile = strings.TrimSpace(p.TermsFile)
}

// NoticeParagraphs is the notice split into paragraphs on blank lines, each
// trimmed, empty ones dropped. It is empty when no notice is configured.
func (p Page) NoticeParagraphs() []string { return splitParagraphs(p.Notice) }

// TermsEnabled reports whether the user must accept terms of use.
func (p Page) TermsEnabled() bool { return p.TermsFile != "" }

// TermsParagraphs is the terms text split into paragraphs on blank lines. It
// is empty when no terms are configured.
func (p Page) TermsParagraphs() []string { return splitParagraphs(p.TermsText) }

var blankLineRe = regexp.MustCompile(`\n[ \t]*\n`)

// ContactHref is the link target for Contact: the contact itself, or empty
// when none is configured.
func (p Page) ContactHref() string { return p.Contact }

// ContactText is the visible link text of Contact: the contact without a
// leading "mailto:".
func (p Page) ContactText() string { return strings.TrimPrefix(p.Contact, "mailto:") }

// splitParagraphs splits text on blank lines; each paragraph is trimmed and
// empty ones are dropped.
func splitParagraphs(text string) []string {
	var out []string
	for _, para := range blankLineRe.Split(text, -1) {
		if para = strings.TrimSpace(para); para != "" {
			out = append(out, para)
		}
	}
	return slices.Clip(out)
}

// badText reports whether text is not valid UTF-8 or holds control or format
// characters (newline and tab are fine when multiline; otherwise only
// printable characters are).
func badText(text string, multiline bool) bool {
	if !utf8.ValidString(text) {
		return true
	}
	return strings.ContainsFunc(text, func(r rune) bool {
		switch {
		case unicode.Is(unicode.Cf, r):
			return true
		case multiline:
			return unicode.IsControl(r) && r != '\n' && r != '\t'
		}
		return !unicode.IsPrint(r)
	})
}
