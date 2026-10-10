package credcheck

import (
	"strings"
	"testing"
)

// FuzzParseRPC checks the JSON/SSE response parser against its contract: it
// never panics, and returns either an error or a message that is the response
// (not a request or notification) to the id asked for.
func FuzzParseRPC(f *testing.F) {
	for _, ct := range []string{"application/json", "text/event-stream", "text/event-stream; charset=utf-8", "text/html", ""} {
		for _, body := range []string{
			`{"jsonrpc":"2.0","id":2,"result":{"isError":false}}`,
			`[{"id":2,"result":{}}]`,
			`{"id":2,"method":"ping","result":{}}`,
			"data: {\"id\":2,\"result\":{}}\n\n",
			"data: {\"id\":2,\ndata: \"result\":{}}\r\n\r\n",
			": c\nevent: message\ndata\n\ndata: x\n",
			"\ufeffdata: {\"id\":2,\"result\":{}}\r\r",
			"event: ping\rdata: {\"id\":2,\"result\":null}\r\n\r\n",
			`{"id":2,"result":null,"error":null}`,
			"",
		} {
			f.Add(ct, body)
		}
	}
	f.Fuzz(func(t *testing.T, contentType, body string) {
		m, err := parseRPC(contentType, strings.NewReader(body), idToolCall)
		if err != nil {
			if m != nil {
				t.Fatalf("message returned together with error %v", err)
			}
			return
		}
		if m == nil || !m.isResponseTo(idToolCall) {
			t.Fatalf("parseRPC(%q, %q) = %+v, not a response to id %d", contentType, body, m, idToolCall)
		}
	})
}
