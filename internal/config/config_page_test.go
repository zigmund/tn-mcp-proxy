package config

import (
	"reflect"
	"strings"
	"testing"
)

func pageYAML(page string) string {
	return "public_url: https://mcp.example.com/\nsecrets:\n  token_keys: [\"" + key1 + "\"]\n" + page +
		"upstreams:\n  - name: tn\n    path: /tn/mcp\n    url: https://tradernet.com/mcp/tn\n    credentials:\n      - { header: X-TN-API-Key }\n"
}

func TestPageValidation(t *testing.T) {
	long := strings.Repeat("a", MaxPageNoticeLen)
	tests := []struct {
		name, page, wantErr string
	}{
		{"absent", "", ""},
		{"mailto", "oauth:\n  page:\n    contact: \"mailto:ops@example.org\"\n", ""},
		{"https", "oauth:\n  page:\n    contact: https://example.org/contact?a=b\n", ""},
		{"contact http", "oauth:\n  page:\n    contact: http://example.org\n", "must start with mailto: or https://"},
		{"contact javascript", "oauth:\n  page:\n    contact: \"javascript:alert(1)\"\n", "must start with mailto: or https://"},
		{"contact bare", "oauth:\n  page:\n    contact: ops@example.org\n", "must start with mailto: or https://"},
		{"mailto empty", "oauth:\n  page:\n    contact: \"mailto:\"\n", "needs an address"},
		{"https no host", "oauth:\n  page:\n    contact: \"https:///x\"\n", "valid https:// URL"},
		{"https userinfo", "oauth:\n  page:\n    contact: \"https://u:p@example.org\"\n", "no user info"},
		{"contact space", "oauth:\n  page:\n    contact: \"mailto:a b@example.org\"\n", "whitespace, control or format"},
		{"contact control", "oauth:\n  page:\n    contact: \"mailto:a\\u0007@example.org\"\n", "whitespace, control or format"},
		{"contact too long", "oauth:\n  page:\n    contact: \"mailto:" + strings.Repeat("a", MaxPageContactLen) + "\"\n", "longer than 256"},
		{"contact max", "oauth:\n  page:\n    contact: \"mailto:" + strings.Repeat("a", MaxPageContactLen-len("mailto:")) + "\"\n", ""},
		{"notice en", "oauth:\n  page:\n    notice:\n      en: |\n        Free.\n\n        As is.\n", ""},
		{"notice three letters", "oauth:\n  page:\n    notice:\n      en: x\n      kaz: x\n", ""},
		{"notice uppercase", "oauth:\n  page:\n    notice:\n      en: x\n      EN: x\n", "lowercase language code"},
		{"notice without en", "oauth:\n  page:\n    notice:\n      ru: x\n", "oauth.page.notice.en: required"},
		{"notice bidi", "oauth:\n  page:\n    notice:\n      en: \"a\\u202eb\"\n", "format characters"},
		{"contact bidi", "oauth:\n  page:\n    contact: \"mailto:a\\u202e@example.org\"\n", "format characters"},
		{"notice region", "oauth:\n  page:\n    notice:\n      en: x\n      en-US: x\n", "lowercase language code"},
		{"notice one letter", "oauth:\n  page:\n    notice:\n      en: x\n      e: x\n", "lowercase language code"},
		{"notice four letters", "oauth:\n  page:\n    notice:\n      en: x\n      engl: x\n", "lowercase language code"},
		{"notice digit key", "oauth:\n  page:\n    notice:\n      en: x\n      e1: x\n", "lowercase language code"},
		{"notice empty", "oauth:\n  page:\n    notice:\n      en: \"  \\n\"\n", "oauth.page.notice.en: must not be empty"},
		{"notice max", "oauth:\n  page:\n    notice:\n      en: " + long + "\n", ""},
		{"notice too long", "oauth:\n  page:\n    notice:\n      en: " + long + "a\n", "longer than 4096 bytes"},
		{"notice control", "oauth:\n  page:\n    notice:\n      en: \"a\\u0007b\"\n", "without control or format"},
		{"notice bare CR", "oauth:\n  page:\n    notice:\n      en: \"a\\rb\"\n", "without control or format"},
		{"notice CRLF ok", "oauth:\n  page:\n    notice:\n      en: \"a\\r\\n\\r\\nb\"\n", ""},
		{"notice tab and newline ok", "oauth:\n  page:\n    notice:\n      en: \"a\\tb\\nc\"\n", ""},
		{"notice unicode", "oauth:\n  page:\n    notice:\n      en: x\n      ru: \"Бесплатно, как есть.\"\n", ""},
		{"notice duplicate key", "oauth:\n  page:\n    notice:\n      en: a\n      en: b\n", "already defined"},
		{"unknown key", "oauth:\n  page:\n    title: x\n", "field title not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(pageYAML(tt.page)), ".")
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestPageTooManyLanguages(t *testing.T) {
	var b strings.Builder
	b.WriteString("oauth:\n  page:\n    notice:\n      en: x\n")
	for i := 0; i < MaxPageNoticeLangs; i++ {
		b.WriteString("      " + string(rune('a'+i/26)) + string(rune('a'+i%26)) + ": x\n")
	}
	if _, err := Parse([]byte(pageYAML(b.String())), "."); err == nil || !strings.Contains(err.Error(), "more than 32 languages") {
		t.Fatalf("err = %v", err)
	}
}

func TestPageErrorDoesNotEchoText(t *testing.T) {
	_, err := Parse([]byte(pageYAML("oauth:\n  page:\n    contact: \"gopher://sekret-host\"\n")), ".")
	if err == nil || strings.Contains(err.Error(), "sekret-host") {
		t.Fatalf("err = %v", err)
	}
}

func TestPageAccessors(t *testing.T) {
	cfg, err := Parse([]byte(pageYAML("oauth:\n  page:\n    contact: \"  mailto:ops@example.org \"\n    notice:\n      ru: |\n        Привет.\n\n        Пока.\n      en: |\n        Hello.\n\n\n          \n        Bye.\n")), ".")
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.OAuth.Page
	if p.ContactHref() != "mailto:ops@example.org" || p.ContactText() != "ops@example.org" {
		t.Errorf("contact = %q / %q", p.ContactHref(), p.ContactText())
	}
	if got, want := p.NoticeParagraphs("en"), []string{"Hello.", "Bye."}; !reflect.DeepEqual(got, want) {
		t.Errorf("en = %q, want %q", got, want)
	}
	if got, want := p.NoticeParagraphs("ru"), []string{"Привет.", "Пока."}; !reflect.DeepEqual(got, want) {
		t.Errorf("ru = %q, want %q", got, want)
	}
	if got := p.NoticeFor("kk"); !strings.HasPrefix(got, "Hello.") {
		t.Errorf("unknown language must fall back to en, got %q", got)
	}
}

func TestPageNoticeFallback(t *testing.T) {
	p := Page{Notice: map[string]string{"ru": "r", "kk": "k"}}
	if got := p.NoticeFor("fr"); got != "" {
		t.Errorf("no en entry: fallback = %q, want empty", got)
	}
	p.Notice["en"] = "e"
	if got := p.NoticeFor("fr"); got != "e" {
		t.Errorf("fallback = %q, want en", got)
	}
	if got := p.NoticeFor("ru"); got != "r" {
		t.Errorf("exact = %q", got)
	}
	if got := (Page{}).NoticeFor("en"); got != "" {
		t.Errorf("empty = %q", got)
	}
	if got := (Page{}).NoticeParagraphs("en"); len(got) != 0 {
		t.Errorf("empty paragraphs = %q", got)
	}
	if (Page{}).ContactHref() != "" || (Page{}).ContactText() != "" {
		t.Error("empty contact must stay empty")
	}
	if got := (Page{Contact: "https://example.org"}).ContactText(); got != "https://example.org" {
		t.Errorf("https text = %q", got)
	}
}

func TestNeverLoggedLabels(t *testing.T) {
	u := Upstream{Credentials: []Credential{
		{Header: "X-A", Label: "API key", Audit: true},
		{Header: "X-B", Secret: true},
		{Header: "X-C", Label: "SID", Optional: true},
	}}
	if got, want := u.NeverLoggedLabels(), []string{"X-B", "SID"}; !reflect.DeepEqual(got, want) {
		t.Errorf("NeverLoggedLabels = %q, want %q", got, want)
	}
}
