package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

const (
	rpcPost = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"portfolio_get"}}`

	toolErrBody = `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"Error executing tool portfolio_get: Ticker not found"}],"isError":true}}`
	notErrBody  = `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"Error executing tool: this is just data"}],"isError":false}}`

	// validateTool is validate.tool: the credential re-check calls it.
	validateTool  = "get_auth_info"
	wantChallenge = `Bearer error="invalid_token", error_description="upstream rejected credentials", ` + meta
)

// recheckOn enables the re-check with a short timeout so slow-upstream tests
// stay fast.
func recheckOn(u *config.Upstream) {
	u.Validate = &config.Validate{Tool: validateTool, Timeout: 700 * time.Millisecond, RecheckOnToolError: true}
}

func quietRechecker() *Rechecker {
	return NewRechecker(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// reply describes what the fake upstream answers to the proxied request.
type reply struct {
	status int
	ctype  string
	enc    string
	body   []byte
}

func (rp reply) write(w http.ResponseWriter) {
	if rp.ctype != "" {
		w.Header().Set("Content-Type", rp.ctype)
	}
	if rp.enc != "" {
		w.Header().Set("Content-Encoding", rp.enc)
	}
	w.Header().Set("Set-Cookie", "up=1")
	status := rp.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(rp.body)
}

func (rp reply) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { rp.write(w) }
}

// valFunc answers the credential re-check's tools/call.
type valFunc func(w http.ResponseWriter, r *http.Request, id json.RawMessage)

func rpcJSON(w http.ResponseWriter, id json.RawMessage, result string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(id)+`,"result":`+result+`}`)
}

func valResult(isErr bool) valFunc {
	return func(w http.ResponseWriter, _ *http.Request, id json.RawMessage) {
		rpcJSON(w, id, `{"content":[{"type":"text","text":"x"}],"isError":`+strconv.FormatBool(isErr)+`}`)
	}
}

var (
	valAccept = valResult(false)
	valReject = valResult(true)
)

func valStatus(code int) valFunc {
	return func(w http.ResponseWriter, _ *http.Request, _ json.RawMessage) { w.WriteHeader(code) }
}

// valHang never answers until the client gives up.
func valHang(_ http.ResponseWriter, r *http.Request, _ json.RawMessage) { <-r.Context().Done() }

// valGate holds the answer until gate is closed, then delegates.
func valGate(gate <-chan struct{}, then valFunc) valFunc {
	return func(w http.ResponseWriter, r *http.Request, id json.RawMessage) {
		select {
		case <-gate:
			then(w, r, id)
		case <-r.Context().Done():
		}
	}
}

// recheckBackend is a fake upstream that serves the proxied tool call with
// proxied and the validation MCP session (initialize, initialized, tools/call
// of validateTool, DELETE) with val.
func recheckBackend(proxied reply, val valFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		var m struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &m)
		switch {
		case r.Method == http.MethodPost && m.Method == "initialize":
			rpcJSON(w, m.ID, `{"protocolVersion":"2025-06-18","capabilities":{}}`)
		case r.Method == http.MethodPost && m.Method == "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPost && m.Method == "tools/call" && m.Params.Name == validateTool:
			val(w, r, m.ID)
		default:
			proxied.write(w)
		}
	}
}

func newRecheckEnv(t *testing.T, proxied reply, val valFunc, opts ...Option) *env {
	t.Helper()
	return newEnvUp(t, recheckBackend(proxied, val), recheckOn, opts...)
}

func jsonReply(body string) reply { return reply{ctype: "application/json", body: []byte(body)} }

// validations counts the credential check sessions the upstream saw (one
// tools/call of validateTool each).
func (e *env) validations() int {
	n := 0
	for _, r := range e.requests() {
		if strings.Contains(r.body, `"name":"`+validateTool+`"`) {
			n++
		}
	}
	return n
}

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func readAll(t *testing.T, r *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (e *env) post(t *testing.T, ae string) *http.Response {
	t.Helper()
	return e.postAs(t, goodCreds(), ae)
}

func (e *env) postAs(t *testing.T, creds map[string]string, ae string) *http.Response {
	t.Helper()
	tok := e.access(t, creds)
	// Accept-Encoding is always set so net/http does not add and undo gzip itself.
	return e.do(t, http.MethodPost, "/mcp/tn", "Bearer "+tok, map[string]string{
		"Accept-Encoding": ae, "Content-Type": "application/json",
		"Accept": "application/json, text/event-stream",
	}, rpcPost)
}

func wantRejected(t *testing.T, resp *http.Response) {
	t.Helper()
	got := readAll(t, resp)
	if resp.StatusCode != 401 {
		t.Fatalf("status %d, want 401", resp.StatusCode)
	}
	if c := resp.Header.Get("WWW-Authenticate"); c != wantChallenge {
		t.Errorf("challenge %q", c)
	}
	if string(got) != "unauthorized\n" {
		t.Errorf("body %q", got)
	}
	if resp.Header.Get("Content-Length") != "13" || resp.ContentLength != 13 {
		t.Errorf("content-length %q / %d", resp.Header.Get("Content-Length"), resp.ContentLength)
	}
	if resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Set-Cookie") != "" {
		t.Errorf("leaked upstream headers: %v", resp.Header)
	}
}

func wantPassthrough(t *testing.T, resp *http.Response, want []byte) {
	t.Helper()
	got := readAll(t, resp)
	if resp.StatusCode != 200 || !bytes.Equal(got, want) {
		t.Errorf("status %d, body %q (want 200, %q)", resp.StatusCode, got, want)
	}
	if resp.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("unexpected challenge %q", resp.Header.Get("WWW-Authenticate"))
	}
}

func TestRecheckRejected(t *testing.T) {
	e := newRecheckEnv(t, jsonReply(toolErrBody), valReject)
	wantRejected(t, e.post(t, "identity"))
	if n := e.validations(); n != 1 {
		t.Errorf("validation sessions = %d, want 1", n)
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "confirmed by re-check") {
		t.Errorf("missing warning in logs: %s", logs)
	}
	for _, secret := range []string{"Ticker not found", "key-123", "secret-456", "sid-789"} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain %q", secret)
		}
	}
}

// The recheck must use the token's credentials, not anything the client sent.
func TestRecheckUsesTokenCredentials(t *testing.T) {
	e := newRecheckEnv(t, jsonReply(toolErrBody), valReject)
	tok := e.access(t, goodCreds())
	resp := e.do(t, http.MethodPost, "/mcp/tn", "Bearer "+tok, map[string]string{
		"Accept-Encoding": "identity", "Content-Type": "application/json",
		"X-TN-API-Key": "attacker-key",
	}, rpcPost)
	wantRejected(t, resp)

	var checked int
	for _, r := range e.requests() {
		if !strings.Contains(r.body, `"method":"initialize"`) && !strings.Contains(r.body, validateTool) &&
			!strings.Contains(r.body, "notifications/initialized") {
			continue
		}
		checked++
		for k, want := range map[string]string{"X-Tn-Api-Key": "key-123", "X-Tn-Api-Secret": "secret-456", "X-Tn-Sid": "sid-789"} {
			if got := r.header.Get(k); got != want {
				t.Errorf("recheck request %s = %q, want %q", k, got, want)
			}
		}
	}
	if checked != 3 {
		t.Errorf("saw %d recheck requests, want 3 (initialize, initialized, tools/call)", checked)
	}
}

func TestRecheckAcceptedPassesThrough(t *testing.T) {
	e := newRecheckEnv(t, jsonReply(toolErrBody), valAccept)
	wantPassthrough(t, e.post(t, "identity"), []byte(toolErrBody))
	if n := e.validations(); n != 1 {
		t.Errorf("validation sessions = %d, want 1", n)
	}
}

func TestRecheckUnavailablePassesThrough(t *testing.T) {
	tests := []struct {
		name string
		val  valFunc
	}{
		{"500", valStatus(500)},
		{"timeout", valHang},
		{"jsonrpc error", func(w http.ResponseWriter, _ *http.Request, id json.RawMessage) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(id)+`,"error":{"code":-32601,"message":"x"}}`)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newRecheckEnv(t, jsonReply(toolErrBody), tt.val)
			wantPassthrough(t, e.post(t, "identity"), []byte(toolErrBody))
			if !strings.Contains(e.logs.String(), "credential recheck unavailable") {
				t.Errorf("no unavailable warning: %s", e.logs.String())
			}
		})
	}
}

func TestRecheckNotTriggered(t *testing.T) {
	e := newRecheckEnv(t, jsonReply(notErrBody), valReject)
	wantPassthrough(t, e.post(t, "identity"), []byte(notErrBody))
	if n := e.validations(); n != 0 {
		t.Errorf("validation sessions = %d, want 0 without isError", n)
	}
}

func TestRecheckBatch(t *testing.T) {
	ok := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"fine"}]}}`
	e := newRecheckEnv(t, jsonReply("["+ok+","+toolErrBody+"]"), valReject)
	wantRejected(t, e.post(t, "identity"))
	if n := e.validations(); n != 1 {
		t.Errorf("validation sessions = %d, want 1", n)
	}

	plain := "[" + ok + "," + notErrBody + "]"
	e = newRecheckEnv(t, jsonReply(plain), valReject)
	wantPassthrough(t, e.post(t, "identity"), []byte(plain))
	if n := e.validations(); n != 0 {
		t.Errorf("validation sessions = %d, want 0", n)
	}
}

func TestRecheckGzip(t *testing.T) {
	raw := gz(t, toolErrBody)
	rp := reply{ctype: "application/json", enc: "gzip", body: raw}

	e := newRecheckEnv(t, rp, valReject)
	wantRejected(t, e.post(t, "gzip, deflate, br, zstd"))

	e = newRecheckEnv(t, rp, valAccept)
	resp := e.post(t, "gzip")
	got := readAll(t, resp)
	if resp.StatusCode != 200 || !bytes.Equal(got, raw) || resp.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("status %d enc %q, bytes equal %v", resp.StatusCode, resp.Header.Get("Content-Encoding"), bytes.Equal(got, raw))
	}
}

// Responses that are not inspected never cause a recheck, even when they carry
// isError and would be rejected.
func TestRecheckNotInspected(t *testing.T) {
	pad := strings.Repeat(" ", maxInspectBody)
	bomb := gz(t, toolErrBody+pad) // decodes beyond the cap
	tests := []struct {
		name string
		rp   reply
	}{
		{"malformed json", reply{ctype: "application/json", body: []byte(`{"result":{"isError":true`)}},
		{"empty body", reply{ctype: "application/json"}},
		{"jsonrpc error object", reply{ctype: "application/json", body: []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad"}}`)}},
		{"isError not a bool", reply{ctype: "application/json", body: []byte(`{"result":{"isError":"true"}}`)}},
		{"text/plain", reply{ctype: "text/plain", body: []byte(toolErrBody)}},
		{"sse", reply{ctype: "text/event-stream", body: []byte("event: message\ndata: " + toolErrBody + "\n\n")}},
		{"no content type", reply{body: []byte(toolErrBody)}},
		{"status 500", reply{status: 500, ctype: "application/json", body: []byte(toolErrBody)}},
		{"status 202", reply{status: 202, ctype: "application/json", body: []byte(toolErrBody)}},
		{"brotli despite narrowing", reply{ctype: "application/json", enc: "br", body: []byte(toolErrBody)}},
		{"corrupt gzip", reply{ctype: "application/json", enc: "gzip", body: []byte("not gzip")}},
		{"gzip beyond decode cap", reply{ctype: "application/json", enc: "gzip", body: bomb}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newRecheckEnv(t, tt.rp, valReject)
			resp := e.post(t, "gzip")
			got := readAll(t, resp)
			wantStatus := tt.rp.status
			if wantStatus == 0 {
				wantStatus = 200
			}
			if resp.StatusCode != wantStatus || !bytes.Equal(got, tt.rp.body) {
				t.Errorf("status %d (want %d), body %q (want %q)", resp.StatusCode, wantStatus, got, tt.rp.body)
			}
			if resp.Header.Get("WWW-Authenticate") != "" || resp.Header.Get("Content-Encoding") != tt.rp.enc {
				t.Errorf("headers changed: %v", resp.Header)
			}
			if resp.Header.Get("Set-Cookie") != "" {
				t.Error("Set-Cookie not removed")
			}
			if len(e.requests()) != 1 {
				t.Errorf("upstream saw %d requests, want only the proxied one", len(e.requests()))
			}
		})
	}
}

func TestRecheckMediaTypeParams(t *testing.T) {
	e := newRecheckEnv(t, reply{ctype: "application/json; charset=utf-8", body: []byte(toolErrBody)}, valReject)
	wantRejected(t, e.post(t, "identity"))
}

func TestRecheckCaching(t *testing.T) {
	clock := new(atomic.Int64)
	clock.Store(1_000)
	rc := quietRechecker()
	rc.now = func() time.Time { return time.Unix(clock.Load(), 0) }

	e := newRecheckEnv(t, jsonReply(toolErrBody), valReject, WithRechecker(rc))
	wantRejected(t, e.post(t, "identity"))
	wantRejected(t, e.post(t, "identity"))
	if n := e.validations(); n != 1 {
		t.Fatalf("two errors within the TTL cost %d sessions, want 1", n)
	}

	// Other credentials are a different key.
	other := goodCreds()
	other["X-Tn-Api-Key"] = "key-other"
	wantRejected(t, e.postAs(t, other, "identity"))
	if n := e.validations(); n != 2 {
		t.Fatalf("sessions = %d, want 2 for another credential set", n)
	}

	clock.Add(int64(recheckTTL/time.Second) + 1)
	wantRejected(t, e.post(t, "identity"))
	if n := e.validations(); n != 3 {
		t.Fatalf("sessions after TTL = %d, want 3", n)
	}
}

func TestRecheckAcceptedIsCached(t *testing.T) {
	e := newRecheckEnv(t, jsonReply(toolErrBody), valAccept)
	for range 3 {
		wantPassthrough(t, e.post(t, "identity"), []byte(toolErrBody))
	}
	if n := e.validations(); n != 1 {
		t.Errorf("sessions = %d, want 1", n)
	}
}

// "No verdict" is remembered only briefly.
func TestRecheckUnavailableCachedShortly(t *testing.T) {
	clock := new(atomic.Int64)
	clock.Store(1_000)
	rc := quietRechecker()
	rc.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	e := newRecheckEnv(t, jsonReply(toolErrBody), valStatus(500), WithRechecker(rc))

	wantPassthrough(t, e.post(t, "identity"), []byte(toolErrBody))
	wantPassthrough(t, e.post(t, "identity"), []byte(toolErrBody))
	if n := e.validations(); n != 1 {
		t.Fatalf("sessions = %d, want 1 within the short TTL", n)
	}
	clock.Add(int64(unavailableTTL/time.Second) + 1)
	wantPassthrough(t, e.post(t, "identity"), []byte(toolErrBody))
	if n := e.validations(); n != 2 {
		t.Fatalf("sessions = %d, want 2 after it expired", n)
	}
}

func TestRecheckConcurrentSingleFlight(t *testing.T) {
	gate := make(chan struct{})
	e := newRecheckEnv(t, jsonReply(toolErrBody), valGate(gate, valReject))

	const n = 6
	toks := make([]string, n)
	for i := range toks {
		toks[i] = e.access(t, goodCreds())
	}
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost, e.proxy.URL+"/mcp/tn", strings.NewReader(rpcPost))
			req.Header.Set("Authorization", "Bearer "+toks[i])
			req.Header.Set("Accept-Encoding", "identity")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			_ = resp.Body.Close()
			codes[i] = resp.StatusCode
		}()
	}
	// Let the requests pile up on the in-flight check, then answer it.
	deadline := time.Now().Add(5 * time.Second)
	for e.validations() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)
	close(gate)
	wg.Wait()

	if got := e.validations(); got != 1 {
		t.Errorf("concurrent errors cost %d sessions, want 1", got)
	}
	for i, c := range codes {
		if c != 401 {
			t.Errorf("request %d: status %d, want 401", i, c)
		}
	}
}

func TestRecheckSaturatedSkips(t *testing.T) {
	rc := quietRechecker()
	for range cap(rc.sem) {
		rc.sem <- struct{}{}
	}
	e := newRecheckEnv(t, jsonReply(toolErrBody), valReject, WithRechecker(rc))
	wantPassthrough(t, e.post(t, "identity"), []byte(toolErrBody))
	if n := e.validations(); n != 0 {
		t.Errorf("sessions = %d, want 0 when saturated", n)
	}
	// A slot frees up: rechecks work again.
	<-rc.sem
	wantRejected(t, e.post(t, "identity"))
}

// A client that leaves while the check runs gets nothing, and the check still
// finishes by itself (bounded by validate.timeout).
func TestRecheckClientGone(t *testing.T) {
	gate := make(chan struct{})
	e := newRecheckEnv(t, jsonReply(toolErrBody), valGate(gate, valReject))
	tok := e.access(t, goodCreds())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.proxy.URL+"/mcp/tn", strings.NewReader(rpcPost))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept-Encoding", "identity")
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	if resp, err := http.DefaultClient.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Error("expected the canceled request to fail")
	}
	close(gate)
}

// A body above the cap is forwarded intact, whether or not its length is
// declared up front, and never triggers a recheck.
func TestRecheckOversizeIntact(t *testing.T) {
	big := []byte(`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"` +
		strings.Repeat("x", 2*maxInspectBody) + `"}],"isError":true}}`)
	for _, chunked := range []bool{false, true} {
		backend := func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if chunked {
				// Flushing before the end makes the response chunked: no Content-Length.
				_, _ = w.Write(big[:1000])
				w.(http.Flusher).Flush()
				_, _ = w.Write(big[1000:])
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(big)))
			_, _ = w.Write(big)
		}
		e := newEnvUp(t, backend, recheckOn)
		wantPassthrough(t, e.post(t, "identity"), big)
		if len(e.requests()) != 1 {
			t.Errorf("chunked=%v: upstream saw %d requests", chunked, len(e.requests()))
		}
	}
}

// A body of exactly the cap is still inspected.
func TestRecheckBodyAtCap(t *testing.T) {
	head := `{"jsonrpc":"2.0","id":2,"result":{"content":[],"isError":true}}`
	body := head + strings.Repeat(" ", maxInspectBody-len(head))
	e := newRecheckEnv(t, jsonReply(body), valReject)
	wantRejected(t, e.post(t, "identity"))
}

// A streaming JSON response larger than the cap must start arriving before the
// upstream finishes (the prefix is replayed, the rest streamed).
func TestRecheckLargeStreamsThrough(t *testing.T) {
	release := make(chan struct{})
	first := bytes.Repeat([]byte("a"), maxInspectBody+10)
	backend := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(first)
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write([]byte("tail"))
	}
	e := newEnvUp(t, backend, recheckOn)
	resp := e.post(t, "identity")
	buf := make([]byte, 100)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatal(err)
	}
	close(release)
	rest, _ := io.ReadAll(resp.Body)
	if !bytes.HasSuffix(rest, []byte("tail")) {
		t.Errorf("tail missing, got %d bytes", len(rest))
	}
}

func TestRecheckGetUntouched(t *testing.T) {
	e := newRecheckEnv(t, jsonReply(toolErrBody), valReject)
	tok := e.access(t, goodCreds())
	resp := e.do(t, http.MethodGet, "/mcp/tn", "Bearer "+tok, map[string]string{"Accept-Encoding": "gzip, deflate, br, zstd"}, "")
	wantPassthrough(t, resp, []byte(toolErrBody))
	if ae := e.requests()[0].header.Get("Accept-Encoding"); ae != "gzip, deflate, br, zstd" {
		t.Errorf("GET Accept-Encoding = %q, want untouched", ae)
	}
	if n := e.validations(); n != 0 {
		t.Errorf("sessions = %d, want 0 for GET", n)
	}
}

// With recheck_on_tool_error unset nothing is inspected or narrowed, even when
// a validate block exists.
func TestRecheckOffUnchanged(t *testing.T) {
	off := func(u *config.Upstream) {
		u.Validate = &config.Validate{Tool: validateTool, Timeout: time.Second}
	}
	e := newEnvUp(t, recheckBackend(jsonReply(toolErrBody), valReject), off)
	wantPassthrough(t, e.post(t, "gzip, deflate, br, zstd"), []byte(toolErrBody))
	if ae := e.requests()[0].header.Get("Accept-Encoding"); ae != "gzip, deflate, br, zstd" {
		t.Errorf("Accept-Encoding = %q, want untouched when the feature is off", ae)
	}
	if n := e.validations(); n != 0 {
		t.Errorf("sessions = %d, want 0", n)
	}

	// No validate block at all, and a shared rechecker must not enable it.
	e = newEnvUp(t, jsonReply(toolErrBody).handler(), nil, WithRechecker(quietRechecker()))
	wantPassthrough(t, e.post(t, "br"), []byte(toolErrBody))
	if ae := e.requests()[0].header.Get("Accept-Encoding"); ae != "br" {
		t.Errorf("Accept-Encoding = %q, want untouched", ae)
	}
}

func TestRecheckNarrowsAcceptEncodingOnPost(t *testing.T) {
	tests := []struct{ in, want string }{
		{"gzip, deflate, br, zstd", "gzip"},
		{"br, zstd", "identity"},
		{"identity", "identity"},
		{"gzip;q=0, br", "identity"},
		{"GZIP;q=0.5", "gzip"},
		{"x-gzip", "gzip"},
		{"*", "gzip"},
		{"*;q=0", "identity"},
		{"gzip;q=0, *", "identity"},
		{"gzip;q=abc", "identity"},
	}
	// An absent header cannot be sent through net/http's client (it adds gzip).
	if got := narrowAcceptEncoding(""); got != "identity" {
		t.Errorf("narrowAcceptEncoding(\"\") = %q, want identity", got)
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			e := newRecheckEnv(t, jsonReply(`{}`), valAccept)
			e.post(t, tt.in)
			if got := e.requests()[0].header.Get("Accept-Encoding"); got != tt.want {
				t.Errorf("upstream Accept-Encoding = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRecheckUpstream401StillRewritten(t *testing.T) {
	backend := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", "Bearer realm=up")
		w.WriteHeader(401)
	}
	e := newEnvUp(t, backend, recheckOn)
	resp := e.post(t, "identity")
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") != wantChallenge {
		t.Errorf("status %d challenge %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
}

func TestRecheckCacheKey(t *testing.T) {
	r := NewRechecker(nil)
	a := r.cacheKey("tn", map[string]string{"X-Tn-Api-Key": "k", "X-Tn-Sid": "s"})
	if b := r.cacheKey("tn", map[string]string{"x-tn-sid": "s", "X-TN-API-KEY": "k"}); a != b {
		t.Error("key must not depend on header case or map order")
	}
	for name, other := range map[string]struct {
		up    string
		creds map[string]string
	}{
		"upstream":  {"tn2", map[string]string{"X-Tn-Api-Key": "k", "X-Tn-Sid": "s"}},
		"value":     {"tn", map[string]string{"X-Tn-Api-Key": "k2", "X-Tn-Sid": "s"}},
		"boundary":  {"tn", map[string]string{"X-Tn-Api-Key": "ks", "X-Tn-Sid": ""}},
		"extra key": {"tn", map[string]string{"X-Tn-Api-Key": "k", "X-Tn-Sid": "s", "X-A": "b"}},
	} {
		if r.cacheKey(other.up, other.creds) == a {
			t.Errorf("%s change did not change the key", name)
		}
	}
	// Another Rechecker (another process key) hashes differently.
	if NewRechecker(nil).cacheKey("tn", map[string]string{"X-Tn-Api-Key": "k", "X-Tn-Sid": "s"}) == a {
		t.Error("cache key must be keyed per process")
	}
}

func TestRecheckCacheBounded(t *testing.T) {
	r := quietRechecker()
	// Fill past the bound the way run() does.
	for i := range maxRecheckEntries + 50 {
		k := r.cacheKey("tn", map[string]string{"K": strconv.Itoa(i)})
		r.mu.Lock()
		for r.order.Len() >= maxRecheckEntries {
			r.removeLocked(r.order.Front())
		}
		r.cache[k] = r.order.PushBack(&cacheEntry{key: k, v: verdictOK, expires: r.now().Add(time.Hour)})
		r.mu.Unlock()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.cache) != maxRecheckEntries || r.order.Len() != maxRecheckEntries {
		t.Errorf("cache size %d / %d, want %d", len(r.cache), r.order.Len(), maxRecheckEntries)
	}
}

func TestHasToolError(t *testing.T) {
	tests := []struct {
		body string
		want bool
	}{
		{toolErrBody, true},
		{"  \n" + toolErrBody + "\n", true},
		{"[" + toolErrBody + "]", true},
		{`[1,"x",null,` + toolErrBody + `]`, true},
		{notErrBody, false},
		{`{"result":{"content":[]}}`, false},
		{`[]`, false},
		{`null`, false},
		{`"isError"`, false},
		{`{"result":"isError"}`, false},
		{`{"result":{"isError":"true"}}`, false},
		{`{"error":{"isError":true}}`, false},
		{``, false},
		{`[`, false},
	}
	for _, tt := range tests {
		if got := hasToolError([]byte(tt.body)); got != tt.want {
			t.Errorf("hasToolError(%q) = %v, want %v", tt.body, got, tt.want)
		}
	}
}
