package oauth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// en renders a catalog message, for assertions on page text.
func en(id string, args ...any) string { return text(id, args...) }

var tmplMsgRe = regexp.MustCompile(`\{\{T "([^"]+)"`)

// Every id the templates use exists in the catalog, and every text is plain
// (no markup that would be escaped into visible tags).
func TestCatalogCoversTemplates(t *testing.T) {
	n := 0
	for name, src := range map[string]string{"authorize.html": authorizeHTML, "error.html": errorHTML} {
		for _, m := range tmplMsgRe.FindAllStringSubmatch(src, -1) {
			n++
			if _, ok := catalog[m[1]]; !ok {
				t.Errorf("%s uses message %q missing from the catalog", name, m[1])
			}
		}
	}
	if n == 0 {
		t.Fatal("no template messages found")
	}
	for id, text := range catalog {
		if strings.ContainsAny(text, "<>") {
			t.Errorf("%s contains markup characters: %q", id, text)
		}
	}
}

func TestText(t *testing.T) {
	if got := text("audit.your", "User"); got != "Your User" {
		t.Errorf("formatted = %q", got)
	}
	if got := text("button.authorize"); got != "Authorize" {
		t.Errorf("plain = %q", got)
	}
	if got := text("no.such.id"); got != "no.such.id" {
		t.Errorf("unknown id = %q", got)
	}
	if got := msgText(message{}); got != "" {
		t.Errorf("zero message = %q", got)
	}
	if got := msgText(uiMsg("audit.your", "x")); got != "Your x" {
		t.Errorf("msgText = %q", got)
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

// Every msg* id constant of messages.go is defined in the catalog.
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
				if _, ok := catalog[id]; !ok {
					t.Errorf("%s = %q is missing from the catalog", name.Name, id)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no msg* constants found")
	}
}

// Every text is free of stray percent signs.
func TestCatalogPlaceholders(t *testing.T) {
	for id, text := range catalog {
		argIndexes(t, id, text)
	}
}
