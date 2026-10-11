package proxy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/zigmund/tn-mcp-proxy/internal/audit"
	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

// auditEnv is an env whose audit records go to a separate JSON buffer.
type auditEnv struct {
	*env
	recs *syncBuf
}

func newAuditEnv(t *testing.T, backend http.HandlerFunc, on bool, mutate func(*config.Upstream)) *auditEnv {
	t.Helper()
	recs := &syncBuf{}
	var al *audit.Logger
	if on {
		al = audit.New(slog.New(slog.NewJSONHandler(recs, nil)), &config.Config{Audit: config.Audit{Enabled: true}})
	}
	e := newEnvUp(t, backend, func(up *config.Upstream) {
		up.Credentials[0].Audit = true // X-TN-API-Key; the secret and the SID are not audited
		if mutate != nil {
			mutate(up)
		}
	}, WithAudit(al))
	return &auditEnv{env: e, recs: recs}
}

// records waits until n audit records exist (the record is written when the
// handler returns, a moment after the client saw the response), then checks
// that no more arrive.
func (e *auditEnv) records(t *testing.T, n int) []map[string]any {
	t.Helper()
	read := func() []map[string]any {
		var out []map[string]any
		for _, ln := range strings.Split(strings.TrimSpace(e.recs.String()), "\n") {
			if ln == "" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(ln), &m); err != nil {
				t.Fatalf("record %q: %v", ln, err)
			}
			out = append(out, m)
		}
		return out
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(read()) < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	got := read()
	if len(got) != n {
		t.Fatalf("%d audit records, want %d: %s", len(got), n, e.recs.String())
	}
	return got
}

func (e *auditEnv) noSecrets(t *testing.T, extra ...string) {
	t.Helper()
	for _, s := range append([]string{"secret-456", "sid-789"}, extra...) {
		if strings.Contains(e.recs.String(), s) || strings.Contains(e.logs.String(), s) {
			t.Errorf("%q leaked into the logs:\n%s\n%s", s, e.recs.String(), e.logs.String())
		}
	}
}

func rpc(method, name, args string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{"name":` + name + `,"arguments":` + args + `}}`
}

func TestAuditRequestRecord(t *testing.T) {
	tests := []struct {
		name    string
		forbid  bool
		method  string
		body    string
		backend http.HandlerFunc
		want    map[string]any // exact values; "-" means the key must be absent
	}{
		{"post, inspection off", false, "POST", rpc("tools/call", `"quotes_get"`, `{"q":"ARGVALUE"}`), nil,
			map[string]any{"method": "POST", "status": 200.0, "rpc_method": "-", "tool": "-", "rpc_batch": "-"}},
		{"get", false, "GET", "", nil, map[string]any{"method": "GET", "status": 200.0, "rpc_method": "-"}},
		{"delete", false, "DELETE", "", nil, map[string]any{"method": "DELETE", "status": 200.0}},
		{"tool call", true, "POST", rpc("tools/call", `"quotes_get"`, `{"q":"ARGVALUE"}`), nil,
			map[string]any{"rpc_method": "tools/call", "tool": "quotes_get", "status": 200.0, "rpc_batch": "-"}},
		{"other method", true, "POST", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil,
			map[string]any{"rpc_method": "tools/list", "tool": "-"}},
		{"notification", true, "POST", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil,
			map[string]any{"rpc_method": "notifications/initialized"}},
		{"response message", true, "POST", `{"jsonrpc":"2.0","id":1,"result":{}}`, nil,
			map[string]any{"rpc_method": "-", "tool": "-"}},
		{"get with inspection on", true, "GET", "", nil, map[string]any{"method": "GET", "rpc_method": "-"}},
		{"upstream 500", false, "POST", `{}`, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) },
			map[string]any{"status": 500.0}},
		{"upstream 401", false, "POST", `{}`, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) },
			map[string]any{"status": 401.0}},
		{"long names are clipped", true, "POST", rpc("tools/call", `"`+strings.Repeat("ж", 100)+`"`, `{}`), nil,
			map[string]any{"rpc_method": "tools/call", "tool": strings.Repeat("ж", 64)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newAuditEnv(t, tt.backend, true, func(up *config.Upstream) {
				if tt.forbid {
					forbid(up)
				}
			})
			tok := e.access(t, goodCreds())
			resp := e.do(t, tt.method, "/mcp/tn?q=QUERYVALUE", "Bearer "+tok, map[string]string{"Content-Type": "application/json"}, tt.body)
			_, _ = io.Copy(io.Discard, resp.Body)

			r := e.records(t, 1)[0]
			base := map[string]any{"level": "INFO", "msg": "audit", "event": "request", "client_ip": "127.0.0.1", "upstream": "tn"}
			for k, v := range base {
				if r[k] != v {
					t.Errorf("%s = %v, want %v", k, r[k], v)
				}
			}
			for k, v := range tt.want {
				if v == "-" {
					if _, ok := r[k]; ok {
						t.Errorf("%s = %v, want it absent", k, r[k])
					}
				} else if r[k] != v {
					t.Errorf("%s = %v, want %v", k, r[k], v)
				}
			}
			if c, _ := r["creds"].(map[string]any); len(c) != 1 || c["X-Tn-Api-Key"] != "key-123" {
				t.Errorf("creds = %v", r["creds"])
			}
			e.noSecrets(t, tok, "ARGVALUE", "QUERYVALUE")
		})
	}
}

func TestAuditRequestBatchIsBounded(t *testing.T) {
	e := newAuditEnv(t, nil, true, forbid)
	var msgs []string
	for range 20 {
		msgs = append(msgs, rpc("tools/call", `"t"`, `{}`))
	}
	tok := e.access(t, goodCreds())
	resp := e.do(t, "POST", "/mcp/tn", "Bearer "+tok, nil, "["+strings.Join(msgs, ",")+"]")
	_, _ = io.Copy(io.Discard, resp.Body)

	r := e.records(t, 1)[0]
	if r["rpc_batch"] != 20.0 {
		t.Errorf("rpc_batch = %v", r["rpc_batch"])
	}
	rpcs, _ := r["rpc"].(map[string]any)
	if len(rpcs) != maxAuditCalls {
		t.Errorf("rpc = %v", r["rpc"])
	}
	if c, _ := rpcs["7"].(map[string]any); c["method"] != "tools/call" || c["tool"] != "t" {
		t.Errorf("rpc.7 = %v", rpcs["7"])
	}
	if _, ok := r["rpc_method"]; ok {
		t.Errorf("single-message field on a batch: %v", r)
	}
}

func TestAuditHostileRPCNames(t *testing.T) {
	e := newAuditEnv(t, nil, true, forbid)
	hostile := `x","event":"forged","client_ip":"6.6.6.6","y":"` + "\r\nmsg=audit"
	b, _ := json.Marshal(hostile)
	tok := e.access(t, goodCreds())
	resp := e.do(t, "POST", "/mcp/tn", "Bearer "+tok, nil, rpc("tools/call", string(b), `{}`))
	_, _ = io.Copy(io.Discard, resp.Body)

	r := e.records(t, 1)[0]
	if r["event"] != "request" || r["client_ip"] != "127.0.0.1" || r["tool"] != strings.NewReplacer("\r", "\uFFFD", "\n", "\uFFFD").Replace(hostile) {
		t.Errorf("record = %v", r)
	}
	if n := strings.Count(strings.TrimSpace(e.recs.String()), "\n"); n != 0 {
		t.Errorf("record spans %d lines: %q", n+1, e.recs.String())
	}
}

func TestAuditOffWritesNothing(t *testing.T) {
	e := newAuditEnv(t, nil, false, forbid)
	tok := e.access(t, goodCreds())
	resp := e.do(t, "POST", "/mcp/tn", "Bearer "+tok, nil, rpc("tools/call", `"t"`, `{"api_key":"K"}`)) // refused
	_, _ = io.Copy(io.Discard, resp.Body)
	resp = e.do(t, "POST", "/mcp/tn", "Bearer "+tok, nil, rpc("tools/call", `"t"`, `{}`))
	_, _ = io.Copy(io.Discard, resp.Body)
	time.Sleep(50 * time.Millisecond)
	if e.recs.String() != "" {
		t.Errorf("records with audit off: %s", e.recs.String())
	}
	if l := e.logs.String(); strings.Contains(l, "client_ip") || strings.Contains(l, "creds.") || strings.Contains(l, "key-123") {
		t.Errorf("identification in refusal logs with audit off:\n%s", l)
	}
}

func TestAuditSSELoggedOnce(t *testing.T) {
	e := newAuditEnv(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		for range 3 {
			_, _ = io.WriteString(w, "data: x\n\n")
			w.(http.Flusher).Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}, true, nil)
	tok := e.access(t, goodCreds())
	resp := e.do(t, "GET", "/mcp/tn", "Bearer "+tok, map[string]string{"Accept": "text/event-stream"}, "")
	b, _ := io.ReadAll(resp.Body)
	if strings.Count(string(b), "data: x") != 3 {
		t.Fatalf("stream = %q", b)
	}
	r := e.records(t, 1)[0]
	if r["method"] != "GET" || r["status"] != 200.0 {
		t.Errorf("record = %v", r)
	}
}

// A stream still open must not have been logged yet, and a client that goes
// away without any response is logged once with status 0.
func TestAuditClientGoneBeforeResponse(t *testing.T) {
	started := make(chan struct{})
	e := newAuditEnv(t, func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}, true, nil)
	tok := e.access(t, goodCreds())
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", e.proxy.URL+"/mcp/tn", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-started
	if got := e.recs.String(); got != "" {
		t.Fatalf("logged before the request ended: %s", got)
	}
	cancel()
	<-done
	r := e.records(t, 1)[0]
	if r["status"] != 0.0 || r["method"] != "GET" {
		t.Errorf("record = %v", r)
	}
}

func TestAuditRefusals(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*config.Upstream)
		creds  func() map[string]string
		body   string
		status int
		msg    string
	}{
		{"forbidden argument", forbid, goodCreds, rpc("tools/call", `"t"`, `{"api_key":"K"}`), 400, "tool call with forbidden argument rejected"},
		{"not inspectable", forbid, goodCreds, `not json`, 400, "request body refused: not inspectable"},
		{"allow-list", func(up *config.Upstream) { up.Credentials[0].AllowedValues = []string{"other"} }, goodCreds, `{}`, 401,
			"token credentials not in allowed_values"},
		{"missing credential", nil, func() map[string]string { return map[string]string{"X-Tn-Api-Key": "key-123"} }, `{}`, 401,
			"token lacks required credential"},
		{"invalid credential value", nil, func() map[string]string {
			c := goodCreds()
			c["X-Tn-Api-Key"] = "key-123\r\nforged=1"
			return c
		}, `{}`, 401, "token credential has invalid value"},
		{"upstream 401", nil, goodCreds, `{}`, 401, "upstream rejected credentials"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var backend http.HandlerFunc
			if tt.name == "upstream 401" {
				backend = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) }
			}
			e := newAuditEnv(t, backend, true, tt.mutate)
			tok := e.access(t, tt.creds())
			resp := e.do(t, "POST", "/mcp/tn", "Bearer "+tok, nil, tt.body)
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tt.status)
			}
			var line string
			for _, l := range strings.Split(e.logs.String(), "\n") {
				if strings.Contains(l, "msg=\""+tt.msg) || strings.Contains(l, "msg="+tt.msg) {
					line = l
				}
			}
			if line == "" {
				t.Fatalf("no %q line in:\n%s", tt.msg, e.logs.String())
			}
			if !strings.Contains(line, "client_ip=127.0.0.1") || !strings.Contains(line, "creds.X-Tn-Api-Key=") {
				t.Errorf("refusal lacks identification: %s", line)
			}
			if strings.Contains(e.logs.String(), "\nforged=1") {
				t.Errorf("injected line in the log:\n%s", e.logs.String())
			}
			e.noSecrets(t, tok, "ARGVALUE")
		})
	}
}

func TestAuditRefusalsDoNotAddRequestRecords(t *testing.T) {
	e := newAuditEnv(t, nil, true, forbid)
	tok := e.access(t, goodCreds())
	resp := e.do(t, "POST", "/mcp/tn", "Bearer "+tok, nil, rpc("tools/call", `"t"`, `{"api_key":"K"}`))
	_, _ = io.Copy(io.Discard, resp.Body)
	resp = e.do(t, "POST", "/mcp/tn", "Bearer garbage", nil, `{}`)
	_, _ = io.Copy(io.Discard, resp.Body)
	time.Sleep(50 * time.Millisecond)
	if e.recs.String() != "" {
		t.Errorf("request record for a refused request: %s", e.recs.String())
	}
}

// Method and tool of a batch stay aligned: a message without a tool has an
// empty one, and each value is its own attribute in the text format too.
func TestAuditBatchAlignedInTextFormat(t *testing.T) {
	info, rej := checkToolArguments([]byte(`[{"method":"ping"},`+rpc("tools/call", `"quotes get"`, `{}`)+`]`), []string{"x"})
	if rej != nil {
		t.Fatal(rej)
	}
	var buf syncBuf
	h := &handler{up: testUpstream("http://x"), audit: audit.New(slog.New(slog.NewTextHandler(&buf, nil)), &config.Config{Audit: config.Audit{Enabled: true}})}
	h.auditRequest(context.Background(), "1.2.3.4", 200, "POST", nil, &info)
	out := buf.String()
	for _, want := range []string{`rpc_batch=2`, `rpc.0.method=ping`, `rpc.0.tool=""`, `rpc.1.method=tools/call`, `rpc.1.tool="quotes get"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
}

func TestAuditToolNameParsing(t *testing.T) {
	tests := []struct {
		name, body, wantTool string
		wantInvalid          bool
	}{
		{"plain", rpc("tools/call", `"t"`, `{}`), "t", false},
		{"non-string name leaves none", `{"method":"tools/call","params":{"name":5}}`, "", false},
		{"duplicate: later non-string clears", `{"method":"tools/call","params":{"name":"a","name":5}}`, "", false},
		{"duplicate: later string wins", `{"method":"tools/call","params":{"name":5,"name":"b"}}`, "b", false},
		{"case-variant name refused", `{"method":"tools/call","params":{"Name":"a","arguments":{}}}`, "", true},
		{"case-variant next to name refused", `{"method":"tools/call","params":{"name":"a","NAME":"b"}}`, "", true},
		{"bidi override replaced", rpc("tools/call", `"ok\u202Eevil"`, `{}`), "ok\uFFFDevil", false},
		{"control replaced", rpc("tools/call", `"a\u0007b\u200Bc"`, `{}`), "a\uFFFDb\uFFFDc", false},
		{"name outside tools/call is ignored", `{"method":"ping","params":{"name":"a"}}`, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, rej := checkToolArguments([]byte(tt.body), []string{"api_key"})
			if tt.wantInvalid {
				if rej == nil || rej.code != codeInvalidRequest {
					t.Fatalf("rej = %v, want invalid request", rej)
				}
				return
			}
			if rej != nil {
				t.Fatalf("rej = %v", rej)
			}
			if got := info.calls[0].tool; got != tt.wantTool {
				t.Errorf("tool = %q, want %q", got, tt.wantTool)
			}
		})
	}
}

func TestClip(t *testing.T) {
	if got := clip("ж"+strings.Repeat("a", 3), 2); got != "ж" {
		t.Errorf("clip = %q", got)
	}
	if got := clip("a\xffb", 10); got != "a\uFFFDb" {
		t.Errorf("clip = %q", got)
	}
	// Replacements widen 1-byte controls to 3 bytes; the result still fits n.
	if got := clip(strings.Repeat("\x01", 128), 128); len(got) > 128 || !utf8.ValidString(got) {
		t.Errorf("clip of controls = %d bytes, valid=%v", len(got), utf8.ValidString(got))
	}
}
