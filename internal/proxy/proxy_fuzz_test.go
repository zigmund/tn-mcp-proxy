package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"

	"github.com/zigmund/tn-mcp-proxy/internal/seal"
)

// fuzzToken is a genuine never-expiring access token for the "tn" upstream,
// sealed once with bytes32(1). It is a constant, not generated per run,
// because fuzz workers are separate processes that must agree on which strings
// are genuine.
const fuzzToken = "AQF8wpt7fXYvJAy791kl4KRznERUUEDyW47bzAmbQ4nuobZ_wclohDpGYYzv4pD89n4LUGWKDzYM9c9yhY9Mq4hDvTK-WwLziKC4cyFaEOviDzP6rDclSJXfbSRu9qdn5BvwN_UsJfDJ0CGjoZCIu1kxM-Xgdep1dijc19VHTULvKxvjHjKcVoj0nr1iiA"

func isSpaceOrCtl(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }

// FuzzBearer checks the Authorization header parser against its contract: the
// scheme is matched case-insensitively and exactly (a single space separates it
// from the token, or nothing follows), the token is one run of characters
// without whitespace or controls, and it is a substring of the header.
func FuzzBearer(f *testing.F) {
	for _, s := range []string{
		"", "Bearer", "Bearer ", "Bearer tok", "bearer tok", "BEARER tok", "BeArEr  tok  ",
		"Bearer a b", "Bearer a\tb", "Bearer\ttok", "Bearer tok", "Bearer a b",
		"Bearer a\x00b", "Bearer a\r\nb", " \tBearer tok\n", "Basic dXNlcjpwYXNz", "Bearertok",
		"Bearer " + fuzzToken, "Token Bearer x", "Bearer  Bearer",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, h string) {
		tok, present := bearer(h)

		// Reference: scheme check on the trimmed header.
		trimmed := strings.TrimSpace(h)
		wantPresent := len(trimmed) >= 6 && strings.EqualFold(trimmed[:6], "bearer") &&
			(len(trimmed) == 6 || trimmed[6] == ' ')
		if present != wantPresent {
			t.Fatalf("present = %v, want %v for %q", present, wantPresent, h)
		}
		if !present {
			if tok != "" {
				t.Fatalf("token %q returned without the Bearer scheme", tok)
			}
			return
		}
		if strings.IndexFunc(tok, isSpaceOrCtl) >= 0 {
			t.Fatalf("token %q contains whitespace or control characters (header %q)", tok, h)
		}
		if !strings.Contains(h, tok) {
			t.Fatalf("token %q is not a substring of %q", tok, h)
		}
		// Exactly one token: a non-empty result is everything after the scheme.
		if tok != "" && strings.TrimSpace(trimmed[6:]) != tok {
			t.Fatalf("token %q is not the whole remainder of %q", tok, h)
		}
		// The scheme is case-insensitive.
		for _, scheme := range []string{"Bearer", "bearer", "BEARER", "bEaReR"} {
			if len(trimmed) < 6 {
				break
			}
			tok2, present2 := bearer(scheme + trimmed[6:])
			if tok2 != tok || !present2 {
				t.Fatalf("scheme %q: got (%q,%v), want (%q,true)", scheme, tok2, present2, tok)
			}
		}
		// A clean token always round-trips.
		if tok != "" {
			if got, ok := bearer("Bearer " + tok); !ok || got != tok {
				t.Fatalf("round trip of %q: (%q,%v)", tok, got, ok)
			}
		}
	})
}

// FuzzAuthenticate runs arbitrary Authorization headers through the proxy's
// authentication step. It may succeed only when the header carries exactly the
// genuine token, and otherwise must answer 401 with a Bearer challenge.
func FuzzAuthenticate(f *testing.F) {
	s, err := seal.New([][]byte{bytes32(1)})
	if err != nil {
		f.Fatal(err)
	}
	hi, err := New(testUpstream("http://upstream.invalid"), publicURL, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		f.Fatal(err)
	}
	h := hi.(*handler)

	for _, seed := range []string{
		"Bearer " + fuzzToken, "bearer " + fuzzToken, "BEARER   " + fuzzToken + "  ",
		"Bearer " + fuzzToken + " x", "Bearer " + fuzzToken + "\tx", "Bearer " + fuzzToken + "\u00a0x", "Bearer " + fuzzToken + "A", "Bearer " + fuzzToken[:20],
		"Bearer\t" + fuzzToken, "Basic " + fuzzToken, fuzzToken, "", "Bearer ",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		req := httptest.NewRequest(http.MethodPost, "/mcp/tn", nil)
		req.Header["Authorization"] = []string{header} // bypass header validation
		rec := httptest.NewRecorder()
		creds, ok := h.authenticate(rec, req)

		tok, _ := bearer(header)
		// Independent checks, not derived from bearer.
		if header == "Bearer "+fuzzToken && !ok {
			t.Fatal("the exact genuine header was rejected")
		}
		if rest, found := strings.CutPrefix(strings.TrimSpace(header), "Bearer "); found {
			if after, junk := strings.CutPrefix(rest, fuzzToken); junk && after != "" && unicode.IsSpace([]rune(after)[0]) && strings.TrimSpace(after) != "" && ok {
				t.Fatalf("header with junk after the token authenticated: %q", header)
			}
		}
		if ok != (tok == fuzzToken) {
			t.Fatalf("authenticate = %v for header %q", ok, header)
		}
		if ok {
			if creds["X-Tn-Api-Key"] != "key-123" || creds["X-Tn-Api-Secret"] != "secret-456" {
				t.Fatalf("creds = %v", creds)
			}
			return
		}
		res := rec.Result()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", res.StatusCode)
		}
		if !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "Bearer ") {
			t.Fatalf("WWW-Authenticate = %q", res.Header.Get("WWW-Authenticate"))
		}
	})
}
