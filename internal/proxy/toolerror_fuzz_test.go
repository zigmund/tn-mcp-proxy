package proxy

import (
	"strings"
	"testing"
)

// FuzzHasToolError checks that the trigger never panics and reports a tool
// error only when the input mentions isError at all (possibly via a JSON
// \u escape of the key).
func FuzzHasToolError(f *testing.F) {
	for _, s := range []string{
		toolErrBody, notErrBody,
		"[" + toolErrBody + "," + notErrBody + "]",
		``, `[`, `{`, `null`, `[null]`, `{"result":null}`, `{"result":{"isError":true}}`,
		`{"result":{"isError":"true"}}`, `{"result":{"isError":true}}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if hasToolError([]byte(body)) && !strings.Contains(body, "isError") && !strings.Contains(body, `\u`) {
			t.Fatalf("reported a tool error without isError in the input: %q", body)
		}
	})
}

// FuzzNarrowAcceptEncoding checks the outbound value is always one of the two
// codings the proxy can decode.
func FuzzNarrowAcceptEncoding(f *testing.F) {
	for _, s := range []string{"", "gzip", "gzip, deflate, br, zstd", "*;q=0", "gzip;q=", ";;;", "gzip;q=1e999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		if got := narrowAcceptEncoding(in); got != "gzip" && got != "identity" {
			t.Fatalf("narrowAcceptEncoding(%q) = %q", in, got)
		}
	})
}
