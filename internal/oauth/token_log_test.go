package oauth

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestShortID(t *testing.T) {
	a, b := shortID("client-a"), shortID("client-b")
	if len(a) != 8 || a == b || a != shortID("client-a") {
		t.Fatalf("shortID: %q %q", a, b)
	}
	// SHA-256("abc") starts with ba7816bf.
	if got := shortID("abc"); got != "ba7816bf" {
		t.Errorf("shortID(abc) = %q", got)
	}
}

func TestRefreshReuseLogHasNoRawIdentifiers(t *testing.T) {
	e := newTK(t)
	var logs bytes.Buffer
	e.srv.log = slog.New(slog.NewTextHandler(&logs, nil))

	_, g0 := e.wantOK(t, e.do(e.codeForm(e.none, e.code(t, e.none, nil))))
	e.wantOK(t, e.do(e.refreshForm(e.none, g0)))
	fam, _ := e.chainRefresh(t, g0)
	e.wantErr(t, e.do(e.refreshForm(e.none, g0)), 400, "invalid_grant") // reuse

	out := logs.String()
	if !strings.Contains(out, "refresh token reuse detected") {
		t.Fatalf("no reuse warning in %q", out)
	}
	if strings.Contains(out, e.none) || strings.Contains(out, fam) {
		t.Errorf("log contains a raw client_id or family id: %q", out)
	}
	for _, want := range []string{"client_id=" + shortID(e.none), "family=" + shortID(fam)} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q: %q", want, out)
		}
	}
}
