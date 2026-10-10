package config

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxLangTexts is the most languages any per-language text map may carry.
const MaxLangTexts = MaxPageNoticeLangs

// LangText is a text together with the language it is actually written in,
// which differs from the requested one when the lookup fell back to the default.
type LangText struct {
	Text string
	Lang string
}

// langTextRules describes one per-language text map for checkLangMap.
type langTextRules struct {
	// Field is the config path of the map, for error messages.
	Field string
	// MaxLen caps one text: in bytes, or in characters when Runes is set.
	MaxLen int
	Runes  bool
	// Multiline allows newline and tab. Without it the text must be printable.
	Multiline bool
}

// checkLangMap validates a map of lowercase language code -> plain text: "en"
// is required when the map is not empty, every text is non-empty, within the
// cap, valid UTF-8 and free of control and format characters. Errors name the
// field and never echo a key or text, which are unbounded operator input.
func checkLangMap(r langTextRules, m map[string]string) []error {
	if len(m) == 0 {
		return nil
	}
	var errs []error
	if len(m) > MaxLangTexts {
		errs = append(errs, fmt.Errorf("%s: more than %d languages", r.Field, MaxLangTexts))
	}
	if _, ok := m[DefaultNoticeLang]; !ok {
		errs = append(errs, fmt.Errorf("%s.%s: required when %s is set", r.Field, DefaultNoticeLang, r.Field))
	}
	langs := make([]string, 0, len(m))
	for l := range m {
		langs = append(langs, l)
	}
	sort.Strings(langs)
	for _, lang := range langs {
		field := r.Field + "." + lang
		text := m[lang]
		size := len(text)
		if r.Runes {
			size = utf8.RuneCountInString(text)
		}
		unit := "bytes"
		if r.Runes {
			unit = "characters"
		}
		switch {
		case !noticeLangRe.MatchString(lang):
			errs = append(errs, fmt.Errorf("%s: every key must be a lowercase language code of 2 or 3 letters", r.Field))
		case strings.TrimSpace(text) == "":
			errs = append(errs, fmt.Errorf("%s: must not be empty", field))
		case size > r.MaxLen:
			errs = append(errs, fmt.Errorf("%s: longer than %d %s", field, r.MaxLen, unit))
		case badText(text, r.Multiline):
			if r.Multiline {
				errs = append(errs, fmt.Errorf("%s: must be valid UTF-8 text without control or format characters (newline and tab are allowed)", field))
			} else {
				errs = append(errs, fmt.Errorf("%s: must be valid UTF-8 printable text without control or format characters", field))
			}
		}
	}
	return errs
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

// lookupLang returns m[lang], else m[DefaultNoticeLang], with the language
// the text is in. The text is empty when neither exists.
func lookupLang(m map[string]string, lang string) LangText {
	if t, ok := m[lang]; ok {
		return LangText{Text: t, Lang: lang}
	}
	if t, ok := m[DefaultNoticeLang]; ok {
		return LangText{Text: t, Lang: DefaultNoticeLang}
	}
	return LangText{}
}
