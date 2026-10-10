package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// Limits of the optional terms of use (oauth.page.terms).
const (
	// MaxTermsTextLen is the largest terms text file, in bytes.
	MaxTermsTextLen = 32 << 10
	// MaxTermsVersionLen is the longest terms version, in characters.
	MaxTermsVersionLen = 32
	// MaxTermsURLLen is the longest full-text URL, in bytes.
	MaxTermsURLLen = 512
)

// Terms is an optional user agreement the user must accept on the authorize
// page before a code is issued. The texts are plain: they are HTML-escaped on
// output and never interpreted.
type Terms struct {
	// Version identifies the text that is accepted; it is shown on the page and
	// written to the audit log. Required.
	Version string `yaml:"version"`
	// Text maps a language code to the path of a plain-text file; paragraphs
	// are separated by blank lines. It must have an "en" entry. The files are
	// read when the config is loaded.
	Text map[string]string `yaml:"text"`
	// URL optionally maps a language code to an https:// URL of the full text.
	// It must have an "en" entry when set.
	URL map[string]string `yaml:"url"`

	// Body is Text after loading: language code -> normalized text. It is
	// filled by Parse and is not part of the YAML.
	Body map[string]string `yaml:"-"`
}

// TermsView is the terms to render for one requested language.
type TermsView struct {
	Version string
	// Paragraphs is the text, split on blank lines, in TextLang.
	Paragraphs []string
	TextLang   string
	// URL is the full-text link in URLLang; empty when none is configured.
	URL     string
	URLLang string
}

// validate checks the part of t that needs no file access. A nil t is valid
// (terms are off).
func (t *Terms) validate() []error {
	if t == nil {
		return nil
	}
	var errs []error
	const f = "oauth.page.terms"
	switch v := t.Version; {
	case v == "":
		errs = append(errs, errors.New(f+".version: required when "+f+" is set"))
	case len([]rune(v)) > MaxTermsVersionLen:
		errs = append(errs, fmt.Errorf("%s.version: longer than %d characters", f, MaxTermsVersionLen))
	case badText(v, false):
		errs = append(errs, errors.New(f+".version: must be printable text without control or format characters"))
	}
	if len(t.Text) == 0 {
		errs = append(errs, errors.New(f+".text: required when "+f+" is set"))
	}
	// The texts themselves are checked while loading; here only the keys and paths.
	if len(t.Text) > MaxLangTexts {
		errs = append(errs, fmt.Errorf("%s.text: more than %d languages", f, MaxLangTexts))
	}
	if len(t.Text) > 0 {
		if _, ok := t.Text[DefaultNoticeLang]; !ok {
			errs = append(errs, fmt.Errorf("%s.text.%s: required when %s.text is set", f, DefaultNoticeLang, f))
		}
	}
	for _, lang := range sortedKeys(t.Text) {
		switch {
		case !noticeLangRe.MatchString(lang):
			errs = append(errs, errors.New(f+".text: every key must be a lowercase language code of 2 or 3 letters"))
		case strings.TrimSpace(t.Text[lang]) == "":
			errs = append(errs, fmt.Errorf("%s.text.%s: file path must not be empty", f, lang))
		}
	}
	if len(t.URL) > 0 {
		if len(t.URL) > MaxLangTexts {
			errs = append(errs, fmt.Errorf("%s.url: more than %d languages", f, MaxLangTexts))
		}
		if _, ok := t.URL[DefaultNoticeLang]; !ok {
			errs = append(errs, fmt.Errorf("%s.url.%s: required when %s.url is set", f, DefaultNoticeLang, f))
		}
	}
	for _, lang := range sortedKeys(t.URL) {
		if !noticeLangRe.MatchString(lang) {
			errs = append(errs, errors.New(f+".url: every key must be a lowercase language code of 2 or 3 letters"))
			continue
		}
		if err := checkHTTPSURL(t.URL[lang]); err != nil {
			errs = append(errs, fmt.Errorf("%s.url.%s: %w", f, lang, err))
		}
	}
	return errs
}

// normalize trims the version and the URLs.
func (t *Terms) normalize() {
	if t == nil {
		return
	}
	t.Version = strings.TrimSpace(t.Version)
	for l, p := range t.Text {
		t.Text[l] = strings.TrimSpace(p)
	}
	for l, u := range t.URL {
		t.URL[l] = strings.TrimSpace(u)
	}
}

// resolvePaths makes relative text file paths absolute against baseDir.
func (t *Terms) resolvePaths(baseDir string) {
	if t == nil {
		return
	}
	for l, p := range t.Text {
		if p != "" && !filepath.IsAbs(p) {
			t.Text[l] = filepath.Join(baseDir, p)
		}
	}
}

// load reads and checks the text files into Body. Errors name the field, and
// for an unreadable file the OS error (which carries the path, not content);
// the content is never echoed.
func (t *Terms) load() []error {
	if t == nil {
		return nil
	}
	var errs []error
	t.Body = make(map[string]string, len(t.Text))
	for _, lang := range sortedKeys(t.Text) {
		path := t.Text[lang]
		field := "oauth.page.terms.text." + lang
		if !noticeLangRe.MatchString(lang) || path == "" {
			continue // reported by validate
		}
		text, err := readTermsFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", field, err))
			continue
		}
		t.Body[lang] = text
	}
	return errs
}

// readTermsFile reads one terms file: at most MaxTermsTextLen bytes of valid
// UTF-8 text with no control or format characters but newline and tab; CRLF is
// normalized to LF.
func readTermsFile(path string) (string, error) {
	// Stat follows symlinks; a FIFO or device would block or never end.
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("reading file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("reading file: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, MaxTermsTextLen+1))
	if err != nil {
		return "", fmt.Errorf("reading file: %w", err)
	}
	if len(raw) > MaxTermsTextLen {
		return "", fmt.Errorf("file is longer than %d bytes", MaxTermsTextLen)
	}
	text := strings.TrimSpace(strings.ReplaceAll(string(raw), "\r\n", "\n"))
	switch {
	case text == "":
		return "", errors.New("file must not be empty")
	case badText(text, true):
		return "", errors.New("file must be valid UTF-8 text without control or format characters (newline and tab are allowed)")
	}
	return text, nil
}

// checkHTTPSURL accepts an https:// URL with a host and no user info.
func checkHTTPSURL(s string) error {
	switch {
	case len(s) > MaxTermsURLLen:
		return fmt.Errorf("longer than %d bytes", MaxTermsURLLen)
	case badText(s, false) || strings.ContainsFunc(s, func(r rune) bool { return r == ' ' }):
		return errors.New("must not contain whitespace, control or format characters")
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return errors.New("must be a valid https:// URL with a host and no user info")
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TermsEnabled reports whether the user must accept terms of use.
func (p Page) TermsEnabled() bool { return p.Terms != nil }

// TermsFor returns the terms for lang, falling back to "en" per part (text and
// URL separately). ok is false when no terms are configured.
func (p Page) TermsFor(lang string) (v TermsView, ok bool) {
	t := p.Terms
	if t == nil {
		return TermsView{}, false
	}
	body := lookupLang(t.Body, lang)
	u := lookupLang(t.URL, lang)
	return TermsView{
		Version:    t.Version,
		Paragraphs: splitParagraphs(body.Text),
		TextLang:   body.Lang,
		URL:        u.Text,
		URLLang:    u.Lang,
	}, true
}

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
