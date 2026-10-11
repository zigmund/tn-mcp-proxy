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
		{"notice", "oauth:\n  page:\n    notice: |\n      Free.\n\n      As is.\n", ""},
		{"notice map rejected", "oauth:\n  page:\n    notice:\n      en: x\n", "cannot unmarshal"},
		{"notice bidi", "oauth:\n  page:\n    notice: \"a\\u202eb\"\n", "without control or format"},
		{"contact bidi", "oauth:\n  page:\n    contact: \"mailto:a\\u202e@example.org\"\n", "format characters"},
		{"notice max", "oauth:\n  page:\n    notice: " + long + "\n", ""},
		{"notice too long", "oauth:\n  page:\n    notice: " + long + "a\n", "longer than 4096 bytes"},
		{"notice control", "oauth:\n  page:\n    notice: \"a\\u0007b\"\n", "without control or format"},
		{"notice bare CR", "oauth:\n  page:\n    notice: \"a\\rb\"\n", "without control or format"},
		{"notice CRLF ok", "oauth:\n  page:\n    notice: \"a\\r\\n\\r\\nb\"\n", ""},
		{"notice tab and newline ok", "oauth:\n  page:\n    notice: \"a\\tb\\nc\"\n", ""},
		{"notice unicode", "oauth:\n  page:\n    notice: \"Бесплатно, как есть.\"\n", ""},
		{"notice blank is unset", "oauth:\n  page:\n    notice: \"  \\n\"\n", ""},
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

func TestPageErrorDoesNotEchoText(t *testing.T) {
	_, err := Parse([]byte(pageYAML("oauth:\n  page:\n    contact: \"gopher://sekret-host\"\n")), ".")
	if err == nil || strings.Contains(err.Error(), "sekret-host") {
		t.Fatalf("err = %v", err)
	}
}

func TestPageAccessors(t *testing.T) {
	cfg, err := Parse([]byte(pageYAML("oauth:\n  page:\n    contact: \"  mailto:ops@example.org \"\n    notice: |\n      Hello.\n\n\n        \n      Bye.\n")), ".")
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.OAuth.Page
	if p.ContactHref() != "mailto:ops@example.org" || p.ContactText() != "ops@example.org" {
		t.Errorf("contact = %q / %q", p.ContactHref(), p.ContactText())
	}
	if got, want := p.NoticeParagraphs(), []string{"Hello.", "Bye."}; !reflect.DeepEqual(got, want) {
		t.Errorf("notice = %q, want %q", got, want)
	}
}

func TestPageEmptyAccessors(t *testing.T) {
	if got := (Page{}).NoticeParagraphs(); len(got) != 0 {
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
