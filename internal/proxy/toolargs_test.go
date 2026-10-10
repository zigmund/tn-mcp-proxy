package proxy

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

func forbid(up *config.Upstream) { up.ForbiddenArguments = []string{"api_key", "api_secret"} }

func call(args string) string {
	return `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"t","arguments":` + args + `}}`
}

const (
	msgParse   = `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}`
	msgInvalid = `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid Request"}}`
)

func argErr(id, name string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"error":{"code":-32602,"message":"argument not allowed: ` + name + `"}}`
}

func utf16le(s string) string {
	var b strings.Builder
	b.WriteString("\xff\xfe")
	for i := 0; i < len(s); i++ {
		b.WriteByte(s[i])
		b.WriteByte(0)
	}
	return b.String()
}

const both = `{"api_key":"K","api_secret":"S"}`

func TestForbiddenArguments(t *testing.T) {
	tests := []struct {
		name, body string
		want       string // "" = forwarded unchanged, else the exact rejection body
	}{
		{"clean call", call(`{"q":"x"}`), ""},
		{"no arguments", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t"}}`, ""},
		{"surrounding JSON whitespace", " \r\n\t" + call(`{"q":1}`) + "\n", ""},
		{"api_key", call(`{"api_key":"K"}`), argErr("7", "api_key")},
		{"api_secret", call(`{"q":1,"api_secret":"S"}`), argErr("7", "api_secret")},
		{"upper case", call(`{"API_KEY":"K"}`), argErr("7", "api_key")},
		{"mixed case", call(`{"Api_Secret":"K"}`), argErr("7", "api_secret")},
		{"null value", call(`{"api_key":null}`), argErr("7", "api_key")},
		{"empty value", call(`{"api_key":""}`), argErr("7", "api_key")},
		{"escaped key", call(`{"api_key":"K"}`), argErr("7", "api_key")},
		{"string id", `{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"arguments":{"api_key":"K"}}}`, argErr(`"abc"`, "api_key")},
		{"fractional id", `{"jsonrpc":"2.0","id":1.5,"method":"tools/call","params":{"arguments":{"api_key":"K"}}}`, argErr("1.5", "api_key")},
		{"object id is not echoed", `{"jsonrpc":"2.0","id":{"x":1},"method":"tools/call","params":{"arguments":{"api_key":"K"}}}`, argErr("null", "api_key")},
		{"array id is not echoed", `{"jsonrpc":"2.0","id":[1],"method":"tools/call","params":{"arguments":{"api_key":"K"}}}`, argErr("null", "api_key")},
		{"no id", `{"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"api_key":"K"}}}`, argErr("null", "api_key")},
		{"nested value is not an argument name", call(`{"filter":{"api_key":"K"}}`), ""},
		{"other method", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"arguments":{"api_key":"K"}}}`, ""},
		{"initialize", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"api_key":"K"}}`, ""},
		{"batch clean", `[` + call(`{"q":1}`) + `,` + call(`{"q":2}`) + `]`, ""},
		{"batch second offends", `[` + call(`{"q":1}`) + `,` + call(`{"api_key":"K"}`) + `]`, argErr("null", "api_key")},
		{"batch with ping", `[{"jsonrpc":"2.0","id":1,"method":"ping"},` + call(`{"API_SECRET":"S"}`) + `]`, argErr("null", "api_secret")},

		// Fail closed: the upstream may parse these differently from Go.
		{"duplicate params, case variant", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":` + both + `},"PARAMS":{}}`, argErr("1", "api_key")},
		{"duplicate params, exact", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":` + both + `},"params":{}}`, msgInvalid},
		{"duplicate method, exact", `{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"x","params":{"arguments":` + both + `}}`, msgInvalid},
		{"duplicate arguments, exact", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":` + both + `,"arguments":{}}}`, msgInvalid},
		{"duplicate arguments, null last", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":` + both + `,"arguments":null}}`, msgInvalid},
		{"method non-string", `{"jsonrpc":"2.0","id":1,"method":1,"params":{"arguments":` + both + `}}`, msgInvalid},
		{"method null", `{"jsonrpc":"2.0","id":1,"method":null,"params":{"arguments":` + both + `}}`, msgInvalid},
		{"duplicate method, case variant", `{"jsonrpc":"2.0","id":1,"method":"tools/call","METHOD":"x","params":{"arguments":` + both + `}}`, argErr("1", "api_key")},
		{"unicode-fold key paramſ", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":` + both + `},"paramſ":{}}`, argErr("1", "api_key")},
		{"Method wrong type, case variant", `{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":1,"params":{"arguments":` + both + `}}`, argErr("1", "api_key")},
		{"Arguments wrong type, case variant", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":` + both + `,"Arguments":5}}`, argErr("1", "api_key")},
		{"Arguments null, case variant", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":` + both + `,"Arguments":null}}`, argErr("1", "api_key")},
		{"NaN", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":` + both + `,"x":NaN}}`, msgParse},
		{"Infinity", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":` + both + `,"x":Infinity}}`, msgParse},
		{"UTF-8 BOM", "\xef\xbb\xbf" + call(both), msgParse},
		{"UTF-16LE", utf16le(call(both)), msgParse},
		{"invalid UTF-8", call("{\"q\":\"\xff\"}"), msgParse},
		{"malformed json", `{"method":"tools/call","params":{"arguments":{"api_key":`, msgParse},
		{"not json", `api_key=K`, msgParse},
		{"empty body", ``, msgParse},
		{"whitespace body", " \n", msgParse},
		{"scalar", `7`, msgParse},
		{"string", `"tools/call"`, msgParse},
		{"empty batch", `[]`, msgParse},
		{"batch with scalar", `[1]`, msgParse},
		{"nested batch", `[[` + call(both) + `]]`, msgParse},
		{"trailing garbage", call(`{}`) + `x`, msgParse},
		{"deep nesting", `{"jsonrpc":"2.0","method":"x","params":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`, msgParse},
		{"arguments not an object", call(`["api_key"]`), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnvUp(t, nil, forbid)
			tok := "Bearer " + e.access(t, goodCreds())
			resp := e.do(t, "POST", "/mcp/tn", tok, map[string]string{"Content-Type": "application/json"}, tt.body)
			got, _ := io.ReadAll(resp.Body)
			if tt.want == "" {
				if resp.StatusCode != 200 {
					t.Fatalf("status %d: %s", resp.StatusCode, got)
				}
				reqs := e.requests()
				if len(reqs) != 1 || reqs[0].body != tt.body {
					t.Fatalf("upstream saw %+v, want the exact body %q", reqs, tt.body)
				}
				if cl := reqs[0].header.Get("Content-Length"); cl != strconv.Itoa(len(tt.body)) {
					t.Errorf("Content-Length = %q, want %d", cl, len(tt.body))
				}
				return
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d, want 400: %s", resp.StatusCode, got)
			}
			if n := len(e.requests()); n != 0 {
				t.Fatalf("rejected call reached the upstream (%d requests)", n)
			}
			if string(got) != tt.want {
				t.Errorf("body = %s\nwant   %s", got, tt.want)
			}
			if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q", ct)
			}
			if logs := e.logs.String(); strings.Contains(logs, `"K"`) || strings.Contains(logs, "=K ") {
				t.Errorf("log leaks a value: %s", logs)
			}
		})
	}
}
