package credcheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
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
	f := &mcpFake{version: mcpProtocolVersion, h: map[string]respFunc{}}
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

func sse(body string) respFunc {
	return func(w http.ResponseWriter, _ *http.Request, _ any) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, body)
	}
}

var testCreds = map[string]string{"X-Api-Key": "k-secret", "X-User": "alice"}

func (f *mcpFake) upstream(v config.Validate) config.Upstream {
	if v.Tool == "" {
		v.Tool = "get_auth_info"
	}
	if v.Timeout == 0 {
		v.Timeout = 5 * time.Second
	}
	return config.Upstream{Name: "tn", Title: "Tradernet", Path: "/tn", URL: f.srv.URL + "/mcp", Validate: &v}
}

func (f *mcpFake) Check(v config.Validate) error {
	return New("").Check(context.Background(), f.upstream(v), testCreds)
}

// wantCheck asserts the outcome kind and that the reason contains reason.
func wantCheck(t *testing.T, err error, kind error, reason string) {
	t.Helper()
	if kind == nil {
		if err != nil {
			t.Fatalf("check = %v, want success", err)
		}
		return
	}
	var ce *CheckError
	if !errors.Is(err, kind) || !errors.As(err, &ce) {
		t.Fatalf("check = %v, want kind %v", err, kind)
	}
	if !strings.Contains(ce.Reason, reason) {
		t.Fatalf("reason = %q, want it to contain %q", ce.Reason, reason)
	}
	if strings.Contains(err.Error(), "upstream-secret-text") || strings.Contains(err.Error(), "k-secret") {
		t.Fatalf("error leaks secret text: %v", err)
	}
}

func TestCheckValidJSON(t *testing.T) {
	f := newMCPFake(t)
	wantCheck(t, f.Check(config.Validate{Arguments: map[string]any{"limit": 3, "nested": map[string]any{"a": []any{"x"}}}}), nil, "")

	if got, want := f.methods(), []string{"POST initialize", "POST notifications/initialized", "POST tools/call"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("requests = %v, want %v", got, want)
	}
	for _, r := range f.requests() {
		for k, v := range testCreds {
			if r.Header.Get(k) != v {
				t.Errorf("%s: header %s = %q, want credential", r.RPC, k, r.Header.Get(k))
			}
		}
		if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json, text/event-stream" {
			t.Errorf("%s: Content-Type/Accept = %q / %q", r.RPC, r.Header.Get("Content-Type"), r.Header.Get("Accept"))
		}
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "tn-mcp-proxy/") {
			t.Errorf("%s: User-Agent = %q", r.RPC, r.Header.Get("User-Agent"))
		}
		if r.Msg["jsonrpc"] != "2.0" {
			t.Errorf("%s: jsonrpc = %v", r.RPC, r.Msg["jsonrpc"])
		}
	}

	reqs := f.requests()
	init := reqs[0].Msg["params"].(map[string]any)
	if init["protocolVersion"] != mcpProtocolVersion || init["clientInfo"].(map[string]any)["name"] != "tn-mcp-proxy" {
		t.Errorf("initialize params = %v", init)
	}
	if _, has := reqs[1].Msg["id"]; has {
		t.Error("notification carries an id")
	}
	call := reqs[2].Msg["params"].(map[string]any)
	wantArgs := map[string]any{"limit": float64(3), "nested": map[string]any{"a": []any{"x"}}}
	if call["name"] != "get_auth_info" || !reflect.DeepEqual(call["arguments"], wantArgs) {
		t.Errorf("tools/call params = %v", call)
	}
}

func TestCheckDefaultArguments(t *testing.T) {
	f := newMCPFake(t)
	wantCheck(t, f.Check(config.Validate{}), nil, "")
	args, ok := f.requests()[2].Msg["params"].(map[string]any)["arguments"].(map[string]any)
	if !ok || len(args) != 0 {
		t.Errorf("arguments = %v, want {}", f.requests()[2].Msg["params"])
	}
}

func TestCheckNoValidateIsNoop(t *testing.T) {
	f := newMCPFake(t)
	up := f.upstream(config.Validate{})
	up.Validate = nil
	if err := New("").Check(context.Background(), up, testCreds); err != nil {
		t.Fatal(err)
	}
	if n := len(f.requests()); n != 0 {
		t.Errorf("upstream contacted %d times", n)
	}
}

func TestCheckValidSSE(t *testing.T) {
	f := newMCPFake(t)
	f.on("initialize", sse("event: message\ndata: "+rpcResult(1, `{"protocolVersion":"2025-06-18"}`)+"\n\n"))
	f.on("tools/call", sse(strings.Join([]string{
		": keepalive",
		"",
		"event: message",
		`data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`,
		"",
		// A server request that reuses our id is not the response.
		`data: {"jsonrpc":"2.0","id":2,"method":"sampling/createMessage","params":{}}`,
		"",
		"data: not json",
		"",
		`data: {"jsonrpc":"2.0","id":2,`,
		`data:  "result":{"content":[],"isError":false}}`,
		"",
		// Anything after the response is never read.
		`data: {"jsonrpc":"2.0","id":2,"result":{"isError":true}}`,
		"",
	}, "\n")))
	wantCheck(t, f.Check(config.Validate{}), nil, "")
}

func TestCheckSSEWithCRLFAndNoFinalBlankLine(t *testing.T) {
	f := newMCPFake(t)
	f.on("tools/call", sse("data: "+rpcResult(2, `{"content":[]}`)+"\r\n"))
	wantCheck(t, f.Check(config.Validate{}), nil, "")
}

func TestCheckOutcomes(t *testing.T) {
	huge := strings.Repeat("a", maxCheckBody)
	tests := []struct {
		name   string
		method string
		fn     respFunc
		kind   error
		reason string
	}{
		{"isError true", "tools/call", replyJSON(200, `{"content":[{"type":"text","text":"upstream-secret-text"}],"isError":true}`), ErrRejected, "tool reported an error"},
		{"401 at initialize", "initialize", status(401), ErrRejected, "http 401"},
		{"403 at initialize", "initialize", status(403), ErrRejected, "http 403"},
		{"401 at initialized", "notifications/initialized", status(401), ErrRejected, "http 401"},
		{"401 at tools/call", "tools/call", status(401), ErrRejected, "http 401"},
		{"403 at tools/call", "tools/call", status(403), ErrRejected, "http 403"},
		{"jsonrpc error", "tools/call", func(w http.ResponseWriter, _ *http.Request, id any) { mcpJSON(w, 200, rpcErr(id, -32602)) }, ErrUnavailable, "jsonrpc error code -32602"},
		{"jsonrpc error at initialize", "initialize", func(w http.ResponseWriter, _ *http.Request, id any) { mcpJSON(w, 200, rpcErr(id, -32600)) }, ErrUnavailable, "jsonrpc error code -32600"},
		{"500 at tools/call", "tools/call", status(500), ErrUnavailable, "http 500"},
		{"500 at initialize", "initialize", status(500), ErrUnavailable, "http 500"},
		{"429 at tools/call", "tools/call", status(429), ErrUnavailable, "http 429"},
		{"initialized 500", "notifications/initialized", status(500), ErrUnavailable, "http 500"},
		{"404", "tools/call", status(404), ErrUnavailable, "http 404"},
		{"malformed json", "tools/call", func(w http.ResponseWriter, _ *http.Request, _ any) { mcpJSON(w, 200, `{"jsonrpc":`) }, ErrUnavailable, "malformed"},
		{"batch array", "tools/call", func(w http.ResponseWriter, _ *http.Request, id any) { mcpJSON(w, 200, "["+rpcResult(id, `{}`)+"]") }, ErrUnavailable, "malformed"},
		{"null result", "tools/call", replyJSON(200, `null`), ErrUnavailable, "no matching response"},
		{"null error and null result", "tools/call", func(w http.ResponseWriter, _ *http.Request, id any) {
			mcpJSON(w, 200, fmt.Sprintf(`{"jsonrpc":"2.0","id":%v,"result":null,"error":null}`, id))
		}, ErrUnavailable, "no matching response"},
		{"result with null error is accepted as result", "tools/call", func(w http.ResponseWriter, _ *http.Request, id any) {
			mcpJSON(w, 200, fmt.Sprintf(`{"jsonrpc":"2.0","id":%v,"result":{"isError":true},"error":null}`, id))
		}, ErrRejected, "tool reported an error"},
		{"null result with error", "tools/call", func(w http.ResponseWriter, _ *http.Request, id any) {
			mcpJSON(w, 200, fmt.Sprintf(`{"jsonrpc":"2.0","id":%v,"result":null,"error":{"code":-32000}}`, id))
		}, ErrUnavailable, "jsonrpc error code -32000"},
		{"scalar result", "tools/call", replyJSON(200, `true`), ErrUnavailable, "malformed"},
		{"init null result", "initialize", replyJSON(200, `null`), ErrUnavailable, "no matching response"},
		{"id mismatch", "tools/call", func(w http.ResponseWriter, _ *http.Request, _ any) { mcpJSON(w, 200, rpcResult(99, `{}`)) }, ErrUnavailable, "no matching response"},
		{"string id", "tools/call", func(w http.ResponseWriter, _ *http.Request, _ any) { mcpJSON(w, 200, rpcResult(`"2"`, `{}`)) }, ErrUnavailable, "no matching response"},
		{"no id", "tools/call", func(w http.ResponseWriter, _ *http.Request, _ any) { mcpJSON(w, 200, `{"jsonrpc":"2.0","result":{}}`) }, ErrUnavailable, "no matching response"},
		{"wrong content type", "tools/call", func(w http.ResponseWriter, _ *http.Request, id any) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, rpcResult(id, `{}`))
		}, ErrUnavailable, "content type"},
		{"missing content type", "tools/call", func(w http.ResponseWriter, _ *http.Request, id any) {
			w.Header()["Content-Type"] = nil
			_, _ = io.WriteString(w, rpcResult(id, `{}`))
		}, ErrUnavailable, "content type"},
		{"sse without response", "tools/call", sse(`data: {"jsonrpc":"2.0","method":"notifications/message"}` + "\n\n"), ErrUnavailable, "no matching response"},
		{"sse id mismatch only", "tools/call", sse("data: " + rpcResult(7, `{}`) + "\n\n"), ErrUnavailable, "no matching response"},
		{"oversized json", "tools/call", func(w http.ResponseWriter, _ *http.Request, id any) {
			mcpJSON(w, 200, rpcResult(id, `{"pad":"`+huge+`"}`))
		}, ErrUnavailable, "too large"},
		{"oversized sse", "tools/call", sse(strings.Repeat(": "+strings.Repeat("a", 1000)+"\n", maxCheckBody/1000+10) + "data: " + rpcResult(2, `{}`) + "\n\n"), ErrUnavailable, "too large"},
		{"oversized sse line", "tools/call", sse("data: " + huge + "\n\n"), ErrUnavailable, "too large"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newMCPFake(t)
			f.on(tt.method, tt.fn)
			wantCheck(t, f.Check(config.Validate{}), tt.kind, tt.reason)
		})
	}
}

// TestCheckStopsAtFirstFailure: a refused step ends the check.
func TestCheckStopsAtFirstFailure(t *testing.T) {
	f := newMCPFake(t)
	f.on("initialize", status(401))
	wantCheck(t, f.Check(config.Validate{}), ErrRejected, "http 401")
	if got := f.methods(); !reflect.DeepEqual(got, []string{"POST initialize"}) {
		t.Errorf("requests = %v", got)
	}
}

func TestCheckRedirectNotFollowed(t *testing.T) {
	var mu sync.Mutex
	var hits []http.Header
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.Header.Clone())
		mu.Unlock()
		mcpJSON(w, 200, rpcResult(1, `{}`))
	}))
	defer other.Close()

	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			f := newMCPFake(t)
			f.on("initialize", func(w http.ResponseWriter, r *http.Request, _ any) {
				http.Redirect(w, r, other.URL+"/steal", code)
			})
			wantCheck(t, f.Check(config.Validate{}), ErrUnavailable, fmt.Sprintf("http %d", code))
		})
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hits) != 0 {
		t.Fatalf("redirect target received %d request(s) with headers %v", len(hits), hits)
	}
}

func TestCheckTimeout(t *testing.T) {
	f := newMCPFake(t)
	f.on("tools/call", func(w http.ResponseWriter, r *http.Request, _ any) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})
	start := time.Now()
	err := f.Check(config.Validate{Timeout: 300 * time.Millisecond})
	wantCheck(t, err, ErrUnavailable, "timeout")
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("check took %v, want about the 300ms timeout", d)
	}
}

func TestCheckParentContextCanceled(t *testing.T) {
	f := newMCPFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := New("").Check(ctx, f.upstream(config.Validate{}), testCreds)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("check = %v, want unavailable", err)
	}
}

func TestCheckUnreachableUpstream(t *testing.T) {
	f := newMCPFake(t)
	up := f.upstream(config.Validate{})
	f.srv.Close()
	err := New("").Check(context.Background(), up, testCreds)
	wantCheck(t, err, ErrUnavailable, "transport error")
	if strings.Contains(err.Error(), f.srv.URL) {
		t.Errorf("error contains the upstream URL: %v", err)
	}
	var ce *CheckError
	errors.As(err, &ce)
	if ce.Cause == nil || strings.Contains(ce.Cause.Error(), "/mcp") {
		t.Errorf("cause = %v, want the transport error without the URL", ce.Cause)
	}
}

func TestCheckSessionPropagation(t *testing.T) {
	f := newMCPFake(t)
	f.session = "sess-123"
	f.version = "2025-03-26"
	wantCheck(t, f.Check(config.Validate{}), nil, "")

	want := []string{"POST initialize", "POST notifications/initialized", "POST tools/call", "DELETE"}
	if got := f.methods(); !reflect.DeepEqual(got, want) {
		t.Fatalf("requests = %v, want %v", got, want)
	}
	for i, r := range f.requests() {
		wantSID, wantVer := "sess-123", "2025-03-26"
		if i == 0 { // initialize precedes both
			wantSID, wantVer = "", ""
		}
		if r.Header.Get("Mcp-Session-Id") != wantSID || r.Header.Get("Mcp-Protocol-Version") != wantVer {
			t.Errorf("%s %s: session %q version %q, want %q %q", r.Method, r.RPC,
				r.Header.Get("Mcp-Session-Id"), r.Header.Get("Mcp-Protocol-Version"), wantSID, wantVer)
		}
		for k, v := range testCreds {
			if r.Header.Get(k) != v {
				t.Errorf("%s %s: credential %s missing", r.Method, r.RPC, k)
			}
		}
	}
}

func TestCheckStatelessSendsProtocolVersion(t *testing.T) {
	f := newMCPFake(t)
	wantCheck(t, f.Check(config.Validate{}), nil, "")
	for _, r := range f.requests()[1:] {
		if r.Header.Get("Mcp-Session-Id") != "" || r.Header.Get("Mcp-Protocol-Version") != mcpProtocolVersion {
			t.Errorf("%s: session %q version %q", r.RPC, r.Header.Get("Mcp-Session-Id"), r.Header.Get("Mcp-Protocol-Version"))
		}
	}
}

// TestCheckDeleteAfterFailure: the session is closed even when the check fails,
// and a failing DELETE changes nothing.
func TestCheckDeleteAfterFailure(t *testing.T) {
	f := newMCPFake(t)
	f.session = "sess-1"
	f.on("tools/call", replyJSON(200, `{"isError":true}`))
	f.on("DELETE", status(500))
	wantCheck(t, f.Check(config.Validate{}), ErrRejected, "tool reported an error")
	if got := f.methods(); got[len(got)-1] != "DELETE" {
		t.Errorf("requests = %v, want a trailing DELETE", got)
	}

	f2 := newMCPFake(t)
	f2.session = "sess-2"
	f2.on("DELETE", status(405))
	wantCheck(t, f2.Check(config.Validate{}), nil, "")
}

func TestCheckUpstreamURLUsedAsConfigured(t *testing.T) {
	var gotURI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.RequestURI
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	up := config.Upstream{Name: "tn", URL: srv.URL + "/mcp/tn?k=v", Validate: &config.Validate{Tool: "t"}}
	_ = New("").Check(context.Background(), up, testCreds)
	if gotURI != "/mcp/tn?k=v" {
		t.Errorf("request URI = %q", gotURI)
	}
}

func TestCheckConcurrencyCap(t *testing.T) {
	f := newMCPFake(t)
	entered, release := make(chan struct{}, 4), make(chan struct{})
	f.on("tools/call", func(w http.ResponseWriter, r *http.Request, id any) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		mcpJSON(w, 200, rpcResult(id, `{}`))
	})
	c := New("")
	c.sem = make(chan struct{}, 1)

	first := make(chan error, 1)
	go func() { first <- c.Check(context.Background(), f.upstream(config.Validate{}), testCreds) }()
	<-entered

	before := len(f.requests())
	err := c.Check(context.Background(), f.upstream(config.Validate{Timeout: 100 * time.Millisecond}), testCreds)
	wantCheck(t, err, ErrUnavailable, "too many concurrent checks")
	if n := len(f.requests()); n != before {
		t.Errorf("a refused check reached the upstream (%d -> %d requests)", before, n)
	}

	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first check = %v", err)
	}
	// The slot was released: a new check goes through.
	wantCheck(t, c.Check(context.Background(), f.upstream(config.Validate{}), testCreds), nil, "")
	if len(c.sem) != 0 {
		t.Errorf("%d slot(s) leaked", len(c.sem))
	}
}

func TestCheckConcurrentChecksNeverExceedCap(t *testing.T) {
	f := newMCPFake(t)
	const cap, n = 2, 8
	var mu sync.Mutex
	inFlight, peak := 0, 0
	f.on("tools/call", func(w http.ResponseWriter, _ *http.Request, id any) {
		mu.Lock()
		inFlight++
		peak = max(peak, inFlight)
		mu.Unlock()
		time.Sleep(30 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
		mcpJSON(w, 200, rpcResult(id, `{}`))
	})
	c := New("")
	c.sem = make(chan struct{}, cap)
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- c.Check(context.Background(), f.upstream(config.Validate{Timeout: 20 * time.Second}), testCreds)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("check = %v", err)
		}
	}
	if peak > cap || peak == 0 {
		t.Errorf("peak in-flight tools/call = %d, want 1..%d", peak, cap)
	}
}

func TestParseRPC(t *testing.T) {
	tests := []struct {
		name, ct, body string
		id             int64
		want           string // result JSON, or "" with wantErr
		wantErr        error
	}{
		{"json", "application/json", `{"jsonrpc":"2.0","id":2,"result":{"a":1}}`, 2, `{"a":1}`, nil},
		{"json charset", "application/json; charset=utf-8", `{"id":2,"result":{}}`, 2, `{}`, nil},
		{"json other id", "application/json", `{"id":3,"result":{}}`, 2, "", errNoResponse},
		{"json notification", "application/json", `{"method":"x"}`, 2, "", errNoResponse},
		{"json request with our id", "application/json", `{"id":2,"method":"ping","result":{}}`, 2, "", errNoResponse},
		{"json empty", "application/json", ``, 2, "", errMalformed},
		{"json array", "application/json", `[{"id":2,"result":{}}]`, 2, "", errMalformed},
		{"sse", "text/event-stream", "data: {\"id\":2,\"result\":{\"a\":1}}\n\n", 2, `{"a":1}`, nil},
		{"sse no space", "text/event-stream; charset=utf-8", "data:{\"id\":2,\"result\":{}}\n\n", 2, `{}`, nil},
		{"sse empty", "text/event-stream", "", 2, "", errNoResponse},
		{"sse bare data", "text/event-stream", "data\n\ndata: {\"id\":2,\"result\":{}}\n\n", 2, `{}`, nil},
		{"sse BOM", "text/event-stream", "\ufeffdata: {\"id\":2,\"result\":{}}\n\n", 2, `{}`, nil},
		{"sse CRLF", "text/event-stream", "data: {\"id\":2,\r\ndata: \"result\":{}}\r\n\r\n", 2, `{}`, nil},
		{"sse lone CR", "text/event-stream", "data: {\"id\":2,\"result\":{}}\r\r", 2, `{}`, nil},
		{"sse CR split lines", "text/event-stream", "data: {\"id\":2,\rdata: \"result\":{}}\r\r", 2, `{}`, nil},
		{"sse comments", "text/event-stream", ": c1\n:\ndata: {\"id\":2,\"result\":{}}\n: c2\n\n", 2, `{}`, nil},
		{"sse event message", "text/event-stream", "event: message\ndata: {\"id\":2,\"result\":{}}\n\n", 2, `{}`, nil},
		{"sse other event type", "text/event-stream", "event: ping\ndata: {\"id\":2,\"result\":{}}\n\n", 2, "", errNoResponse},
		{"sse event type resets", "text/event-stream", "event: ping\ndata: x\n\ndata: {\"id\":2,\"result\":{}}\n\n", 2, `{}`, nil},
		{"json null error", "application/json", `{"id":2,"result":{},"error":null}`, 2, `{}`, nil},
		{"json null result no error", "application/json", `{"id":2,"result":null}`, 2, "", errNoResponse},
		{"json null result with error", "application/json", `{"id":2,"result":null,"error":{"code":1}}`, 2, "null", nil},
		{"xml", "application/xml", `<a/>`, 2, "", errContentType},
		{"bad content type", "///", `{}`, 2, "", errContentType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := parseRPC(tt.ct, strings.NewReader(tt.body), tt.id)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err == nil && string(m.Result) != tt.want {
				t.Errorf("result = %s, want %s", m.Result, tt.want)
			}
		})
	}
}

func TestCheckReportsGivenVersion(t *testing.T) {
	for _, tt := range []struct{ name, version, want string }{
		{"given", "v1.2.3", "v1.2.3"},
		{"empty falls back to dev", "", "dev"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newMCPFake(t)
			err := New(tt.version).Check(context.Background(), f.upstream(config.Validate{}), testCreds)
			wantCheck(t, err, nil, "")
			reqs := f.requests()
			if len(reqs) == 0 {
				t.Fatal("no requests")
			}
			for _, r := range reqs {
				if got := r.Header.Get("User-Agent"); got != "tn-mcp-proxy/"+tt.want {
					t.Errorf("%s: User-Agent = %q", r.RPC, got)
				}
			}
			init := reqs[0].Msg["params"].(map[string]any)["clientInfo"].(map[string]any)
			if init["name"] != "tn-mcp-proxy" || init["version"] != tt.want {
				t.Errorf("clientInfo = %v, want version %q", init, tt.want)
			}
		})
	}
}
