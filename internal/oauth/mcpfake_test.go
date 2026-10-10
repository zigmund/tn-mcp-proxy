package oauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// recorded is one request received by mcpFake.
type recorded struct {
	Method string // HTTP method; for POST the JSON-RPC method follows in RPC
	RPC    string
	Header http.Header
	Msg    map[string]any
}

type respFunc func(w http.ResponseWriter, r *http.Request, id any)

// mcpFake is a stateless-by-default MCP upstream for the credential checker.
type mcpFake struct {
	srv *httptest.Server

	session string // Mcp-Session-Id issued by initialize, if set
	version string // protocolVersion returned by initialize, default 2025-06-18

	mu   sync.Mutex
	reqs []recorded
	h    map[string]respFunc // by JSON-RPC method, or "DELETE"
}

func newMCPFake(t *testing.T) *mcpFake {
	t.Helper()
	f := &mcpFake{version: "2025-06-18", h: map[string]respFunc{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *mcpFake) on(method string, fn respFunc) { f.h[method] = fn }

func (f *mcpFake) serve(w http.ResponseWriter, r *http.Request) {
	rec := recorded{Method: r.Method, Header: r.Header.Clone()}
	var id any
	if r.Method == http.MethodPost {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &rec.Msg)
		rec.RPC, _ = rec.Msg["method"].(string)
		id = rec.Msg["id"]
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, rec)
	f.mu.Unlock()

	key := rec.RPC
	if r.Method == http.MethodDelete {
		key = "DELETE"
	}
	if fn := f.h[key]; fn != nil {
		fn(w, r, id)
		return
	}
	switch key {
	case "initialize":
		if f.session != "" {
			w.Header().Set("Mcp-Session-Id", f.session)
		}
		mcpJSON(w, http.StatusOK, rpcResult(id, fmt.Sprintf(`{"protocolVersion":%q,"capabilities":{}}`, f.version)))
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/call":
		mcpJSON(w, http.StatusOK, rpcResult(id, `{"content":[{"type":"text","text":"ok"}]}`))
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (f *mcpFake) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

// methods lists "POST initialize", "DELETE", ... in arrival order.
func (f *mcpFake) methods() []string {
	var out []string
	for _, r := range f.requests() {
		out = append(out, strings.TrimSpace(r.Method+" "+r.RPC))
	}
	return out
}

func mcpJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func rpcResult(id any, result string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%v,"result":%s}`, id, result)
}

func rpcErr(id any, code int) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%v,"error":{"code":%d,"message":"upstream-secret-text"}}`, id, code)
}

// replyJSON answers with a fixed JSON body (id substituted) and status.
func replyJSON(status int, result string) respFunc {
	return func(w http.ResponseWriter, _ *http.Request, id any) { mcpJSON(w, status, rpcResult(id, result)) }
}

func status(code int) respFunc {
	return func(w http.ResponseWriter, _ *http.Request, _ any) { w.WriteHeader(code) }
}
