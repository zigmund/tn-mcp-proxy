package oauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// en renders a default-language message, for assertions on page text.
func en(id string, args ...any) string { return newLocale(defaultLang).T(id, args...) }

var tmplMsgRe = regexp.MustCompile(`\.L\.T "([^"]+)"`)

// Every id the templates use exists in the default language, and every default
// text is plain (no markup that would be escaped into visible tags).
func TestCatalogCoversTemplates(t *testing.T) {
	for name, src := range map[string]string{"authorize.html": authorizeHTML, "error.html": errorHTML} {
		for _, m := range tmplMsgRe.FindAllStringSubmatch(src, -1) {
			if _, ok := catalog[defaultLang][m[1]]; !ok {
				t.Errorf("%s uses message %q missing from the %s catalog", name, m[1], defaultLang)
			}
		}
	}
	for lang, msgs := range catalog {
		for id, text := range msgs {
			if strings.ContainsAny(text, "<>") {
				t.Errorf("%s/%s contains markup characters: %q", lang, id, text)
			}
		}
	}
}

// The built-in languages translate every message of the default language, and
// every language in the switcher has a catalog.
func TestBuiltInLanguagesCoverEveryID(t *testing.T) {
	for _, l := range pageLangs {
		msgs, ok := catalog[l.Code]
		if !ok {
			t.Fatalf("language %s has no catalog", l.Code)
		}
		for id := range catalog[defaultLang] {
			if text, ok := msgs[id]; !ok || strings.TrimSpace(text) == "" {
				t.Errorf("%s misses message %q", l.Code, id)
			}
		}
	}
	if pageLangs[0].Code != defaultLang {
		t.Errorf("the first language is %q, want the default %q", pageLangs[0].Code, defaultLang)
	}
	for code := range catalog {
		if !supportedLang(code) {
			t.Errorf("catalog %q is not in pageLangs", code)
		}
	}
}

// Other languages may only add ids the default language has, so a typo cannot
// hide behind the fallback.
func TestCatalogLanguagesSubsetOfDefault(t *testing.T) {
	for lang, msgs := range catalog {
		for id := range msgs {
			if _, ok := catalog[defaultLang][id]; !ok {
				t.Errorf("%s defines %q, unknown in %s", lang, id, defaultLang)
			}
		}
	}
}

func TestLocaleLookup(t *testing.T) {
	catalog["zz"] = map[string]string{"audit.your": "Votre %[2]s (%[1]s)"}
	t.Cleanup(func() { delete(catalog, "zz") })

	l := newLocale("zz")
	if l.Lang() != "zz" {
		t.Errorf("lang = %q", l.Lang())
	}
	if got := l.T("audit.your", "a", "b"); got != "Votre b (a)" {
		t.Errorf("translated, reordered = %q", got)
	}
	if got := l.T("button.authorize"); got != "Authorize" {
		t.Errorf("fallback to default = %q", got)
	}
	if got := l.T("no.such.id"); got != "no.such.id" {
		t.Errorf("unknown id = %q", got)
	}
	if got := newLocale("nope"); got.Lang() != defaultLang {
		t.Errorf("unknown language = %q, want %q", got.Lang(), defaultLang)
	}
	if got := l.Msg(message{}); got != "" {
		t.Errorf("zero message = %q", got)
	}
	if got := l.Msg(uiMsg("audit.your", "x", "y")); got != "Votre y (x)" {
		t.Errorf("Msg = %q", got)
	}
}

var verbRe = regexp.MustCompile(`%\[(\d+)\]s`)

// argIndexes returns the set of %[n]s argument indexes of text, and fails the
// test on any other use of '%'.
func argIndexes(t *testing.T, where, text string) map[string]bool {
	t.Helper()
	set := map[string]bool{}
	for _, m := range verbRe.FindAllStringSubmatch(text, -1) {
		set[m[1]] = true
	}
	if strings.Contains(verbRe.ReplaceAllString(text, ""), "%") {
		t.Errorf("%s: stray %% outside a %%[n]s verb: %q", where, text)
	}
	return set
}

// Every msg* id constant of messages.go is defined in the default language.
func TestCatalogHasEveryIDConstant(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "messages.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, "msg") {
					continue
				}
				n++
				id, err := strconv.Unquote(vs.Values[i].(*ast.BasicLit).Value)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := catalog[defaultLang][id]; !ok {
					t.Errorf("%s = %q is missing from the %s catalog", name.Name, id, defaultLang)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no msg* constants found")
	}
}

// A translation takes the same arguments as the default text, and every text
// is free of stray percent signs.
func TestCatalogPlaceholders(t *testing.T) {
	for id, text := range catalog[defaultLang] {
		argIndexes(t, defaultLang+"/"+id, text)
	}
	for lang, msgs := range catalog {
		if lang == defaultLang {
			continue
		}
		for id, text := range msgs {
			got := argIndexes(t, lang+"/"+id, text)
			want := argIndexes(t, defaultLang+"/"+id, catalog[defaultLang][id])
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s/%s uses arguments %v, %s uses %v", lang, id, got, defaultLang, want)
			}
		}
	}
}
