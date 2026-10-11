package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const termsRU = "Бесплатно, как есть.\n\nНа свой риск."

// writeFiles writes name -> content into a fresh dir and returns it.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func termsYAML(body string) string {
	return pageYAML("oauth:\n  page:\n    terms:\n" + body)
}

func TestTermsValidation(t *testing.T) {
	long := strings.Repeat("a", MaxTermsTextLen)
	tests := []struct {
		name    string
		files   map[string]string
		yaml    string
		wantErr string
	}{
		{"ok", map[string]string{"en.txt": "Free.\n\nAs is.", "ru.txt": termsRU},
			"      version: \"2026-10-10\"\n      text: { en: en.txt, ru: ru.txt }\n      url: { en: \"https://example.org/terms\" }\n", ""},
		{"ok text only", map[string]string{"en.txt": "Free."}, "      version: v1\n      text: { en: en.txt }\n", ""},
		{"no version", map[string]string{"en.txt": "x"}, "      text: { en: en.txt }\n", "oauth.page.terms.version: required"},
		{"version too long", map[string]string{"en.txt": "x"}, "      version: " + strings.Repeat("v", MaxTermsVersionLen+1) + "\n      text: { en: en.txt }\n", "version: longer than 32 characters"},
		{"version control", map[string]string{"en.txt": "x"}, "      version: \"a\\u0007\"\n      text: { en: en.txt }\n", "version: must be printable"},
		{"no text", nil, "      version: v1\n", "oauth.page.terms.text: required"},
		{"text without en", map[string]string{"ru.txt": "x"}, "      version: v1\n      text: { ru: ru.txt }\n", "oauth.page.terms.text.en: required"},
		{"text bad key", map[string]string{"en.txt": "x"}, "      version: v1\n      text: { en: en.txt, EN-us: en.txt }\n", "every key must be a lowercase language code"},
		{"empty path", nil, "      version: v1\n      text: { en: \"\" }\n", "text.en: file path must not be empty"},
		{"missing file", nil, "      version: v1\n      text: { en: nope.txt }\n", "oauth.page.terms.text.en: reading file"},
		{"empty file", map[string]string{"en.txt": " \n\n"}, "      version: v1\n      text: { en: en.txt }\n", "file must not be empty"},
		{"size max", map[string]string{"en.txt": long}, "      version: v1\n      text: { en: en.txt }\n", ""},
		{"size cap", map[string]string{"en.txt": long + "a"}, "      version: v1\n      text: { en: en.txt }\n", "file is longer than 32768 bytes"},
		{"control char", map[string]string{"en.txt": "a\x07b"}, "      version: v1\n      text: { en: en.txt }\n", "without control or format"},
		{"bare CR", map[string]string{"en.txt": "a\rb"}, "      version: v1\n      text: { en: en.txt }\n", "without control or format"},
		{"bidi", map[string]string{"en.txt": "a\u202eb"}, "      version: v1\n      text: { en: en.txt }\n", "without control or format"},
		{"invalid utf8", map[string]string{"en.txt": "a\xffb"}, "      version: v1\n      text: { en: en.txt }\n", "valid UTF-8"},
		{"tab newline crlf ok", map[string]string{"en.txt": "a\tb\r\n\r\nc"}, "      version: v1\n      text: { en: en.txt }\n", ""},
		{"url without en", map[string]string{"en.txt": "x"}, "      version: v1\n      text: { en: en.txt }\n      url: { ru: \"https://example.org/ru\" }\n", "oauth.page.terms.url.en: required"},
		{"url http", map[string]string{"en.txt": "x"}, "      version: v1\n      text: { en: en.txt }\n      url: { en: \"http://example.org\" }\n", "url.en: must be a valid https://"},
		{"url userinfo", map[string]string{"en.txt": "x"}, "      version: v1\n      text: { en: en.txt }\n      url: { en: \"https://u:p@example.org\" }\n", "url.en: must be a valid https://"},
		{"url space", map[string]string{"en.txt": "x"}, "      version: v1\n      text: { en: en.txt }\n      url: { en: \"https://example.org/a b\" }\n", "url.en: must not contain whitespace"},
		{"url too long", map[string]string{"en.txt": "x"}, "      version: v1\n      text: { en: en.txt }\n      url: { en: \"https://example.org/" + strings.Repeat("a", MaxTermsURLLen) + "\" }\n", "url.en: longer than 512"},
		{"unknown key", map[string]string{"en.txt": "x"}, "      version: v1\n      text: { en: en.txt }\n      title: x\n", "field title not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeFiles(t, tt.files)
			_, err := Parse([]byte(termsYAML(tt.yaml)), dir)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestTermsErrorDoesNotEchoContent(t *testing.T) {
	dir := writeFiles(t, map[string]string{"en.txt": "sekret-clause \x07"})
	_, err := Parse([]byte(termsYAML("      version: v1\n      text: { en: en.txt }\n")), dir)
	if err == nil || strings.Contains(err.Error(), "sekret-clause") {
		t.Fatalf("err = %v", err)
	}
}

func TestTermsLoadAndLookup(t *testing.T) {
	dir := writeFiles(t, map[string]string{"en.txt": "One.\r\n\r\nTwo.\r\n", "ru.txt": termsRU})
	cfg, err := Parse([]byte(termsYAML("      version: \" 2026-10-10 \"\n      text: { en: en.txt, ru: ru.txt }\n      url: { en: \"https://example.org/terms\", ru: \"https://example.org/ru\" }\n")), dir)
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.OAuth.Page
	if !p.TermsEnabled() {
		t.Fatal("terms not enabled")
	}
	if want := filepath.Join(dir, "en.txt"); p.Terms.Text["en"] != want {
		t.Errorf("path = %q, want %q (relative to the config dir)", p.Terms.Text["en"], want)
	}
	v, ok := p.TermsFor("en")
	if !ok || v.Version != "2026-10-10" || !reflect.DeepEqual(v.Paragraphs, []string{"One.", "Two."}) || v.TextLang != "en" || v.URL != "https://example.org/terms" {
		t.Errorf("en = %+v", v)
	}
	if v, _ := p.TermsFor("ru"); v.TextLang != "ru" || v.URLLang != "ru" || len(v.Paragraphs) != 2 || v.Paragraphs[0] != "Бесплатно, как есть." {
		t.Errorf("ru = %+v", v)
	}
	// kk has neither text nor URL: both fall back to en.
	if v, _ := p.TermsFor("kk"); v.TextLang != "en" || v.URLLang != "en" || v.Paragraphs[0] != "One." {
		t.Errorf("kk = %+v", v)
	}
	if _, ok := (Page{}).TermsFor("en"); ok || (Page{}).TermsEnabled() {
		t.Error("empty page must have no terms")
	}
}

func TestTermsURLFallsBackPerPart(t *testing.T) {
	dir := writeFiles(t, map[string]string{"en.txt": "x", "ru.txt": "y"})
	cfg, err := Parse([]byte(termsYAML("      version: v1\n      text: { en: en.txt, ru: ru.txt }\n      url: { en: \"https://example.org/terms\" }\n")), dir)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := cfg.OAuth.Page.TermsFor("ru")
	if v.TextLang != "ru" || v.URLLang != "en" {
		t.Errorf("ru = %+v, want ru text and en URL", v)
	}
}

func i18nYAML(audit, creds string) string {
	return "public_url: https://mcp.example.com/\nsecrets:\n  token_keys: [\"" + key1 + "\"]\n" + audit +
		"upstreams:\n  - name: tn\n    path: /tn/mcp\n    url: https://tradernet.com/mcp/tn\n    credentials:\n" + creds
}

func TestLabelsValidation(t *testing.T) {
	tests := []struct {
		name, cred, wantErr string
	}{
		{"ok", "      - { header: X-A, label: API key, labels: { en: API key, ru: Ключ API } }\n", ""},
		{"en only fills label", "      - { header: X-A, labels: { en: API key, ru: Ключ } }\n", ""},
		{"no label at all", "      - { header: X-A }\n", ""},
		{"without en", "      - { header: X-A, label: API key, labels: { ru: Ключ } }\n", "credentials[0].labels.en: required"},
		{"en differs", "      - { header: X-A, label: Key, labels: { en: API key } }\n", "labels.en: must equal label"},
		{"bad key", "      - { header: X-A, labels: { en: a, RU: b } }\n", "every key must be a lowercase language code"},
		{"empty", "      - { header: X-A, labels: { en: \" \" } }\n", "labels.en: must not be empty"},
		{"too long", "      - { header: X-A, labels: { en: " + strings.Repeat("a", MaxCredentialLabelLen+1) + " } }\n", "longer than 128 characters"},
		{"max", "      - { header: X-A, labels: { en: " + strings.Repeat("я", MaxCredentialLabelLen) + " } }\n", ""},
		{"control", "      - { header: X-A, labels: { en: \"a\\u0007\" } }\n", "printable text without control or format"},
		{"newline", "      - { header: X-A, labels: { en: \"a\\nb\" } }\n", "printable text without control or format"},
		{"bidi", "      - { header: X-A, labels: { en: \"a\\u202eb\" } }\n", "printable text without control or format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(i18nYAML("", tt.cred)), ".")
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLabelLookup(t *testing.T) {
	cfg, err := Parse([]byte(i18nYAML("", "      - { header: X-A, labels: { en: API key, ru: Ключ API } }\n      - { header: X-B }\n")), ".")
	if err != nil {
		t.Fatal(err)
	}
	a, b := cfg.Upstreams[0].Credentials[0], cfg.Upstreams[0].Credentials[1]
	if a.Label != "API key" {
		t.Errorf("label default = %q, want labels.en", a.Label)
	}
	for _, c := range []struct {
		lang string
		want LangText
	}{
		{"ru", LangText{"Ключ API", "ru"}},
		{"en", LangText{"API key", "en"}},
		{"kk", LangText{"API key", "en"}}, // falls back to en
	} {
		if got := a.LabelIn(c.lang); got != c.want {
			t.Errorf("LabelIn(%q) = %+v, want %+v", c.lang, got, c.want)
		}
	}
	if got := b.LabelIn("ru"); got != (LangText{"X-B", "en"}) {
		t.Errorf("no labels: %+v, want the header", got)
	}
	if got := (Credential{Header: "X-C"}).LabelIn("en"); got.Text != "X-C" {
		t.Errorf("hand-built label = %+v", got)
	}
	up := Upstream{Credentials: []Credential{{Header: "X-A", Label: "A", Labels: map[string]string{"ru": "Я"}, Audit: true}, {Header: "X-B", Label: "B"}}}
	if got := up.AuditedLabels("ru"); !reflect.DeepEqual(got, []LangText{{"Я", "ru"}}) {
		t.Errorf("AuditedLabels(ru) = %+v", got)
	}
	if got := up.NeverLoggedLabels("ru"); !reflect.DeepEqual(got, []LangText{{"B", "en"}}) {
		t.Errorf("NeverLoggedLabels(ru) = %+v", got)
	}
}

func TestNoticeIn(t *testing.T) {
	p := Page{Notice: map[string]string{"en": "e", "ru": "r"}}
	if got := p.NoticeIn("ru"); got != (LangText{"r", "ru"}) {
		t.Errorf("ru = %+v", got)
	}
	if got := p.NoticeIn("kk"); got != (LangText{"e", "en"}) {
		t.Errorf("kk = %+v", got)
	}
	if got := (Page{}).NoticeIn("ru"); got != (LangText{}) {
		t.Errorf("empty = %+v", got)
	}
}

// The sample agreements of deploy/ pass the same checks as an operator's own.
func TestSampleTermsLoad(t *testing.T) {
	dir := filepath.Join("..", "..", "deploy")
	cfg, err := Parse([]byte(termsYAML("      version: sample\n      text:\n        en: terms.example.en.txt\n        ru: terms.example.ru.txt\n        kk: terms.example.kk.txt\n")), dir)
	if err != nil {
		t.Fatal(err)
	}
	var counts []int
	for _, lang := range []string{"en", "ru", "kk"} {
		v, _ := cfg.OAuth.Page.TermsFor(lang)
		if v.TextLang != lang || len(v.Paragraphs) == 0 {
			t.Errorf("%s: %+v", lang, v)
		}
		if got := strings.Join(v.Paragraphs, "\n"); !strings.Contains(got, "[") {
			t.Errorf("%s sample has no placeholder", lang)
		}
		counts = append(counts, len(v.Paragraphs))
	}
	// The Russian and Kazakh samples say no more than the English one.
	if counts[0] != counts[1] || counts[0] != counts[2] {
		t.Errorf("paragraph counts en/ru/kk = %v, want equal", counts)
	}
}

// A directory (or a FIFO, device, ...) is refused before it is opened.
func TestTermsNotRegularFile(t *testing.T) {
	dir := writeFiles(t, nil)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub", filepath.Join(dir, "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	for _, p := range []string{"sub", "link"} {
		_, err := Parse([]byte(termsYAML("      version: v1\n      text: { en: "+p+" }\n")), dir)
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("%s: err = %v", p, err)
		}
	}
}
