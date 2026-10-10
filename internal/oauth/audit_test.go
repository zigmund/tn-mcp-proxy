package oauth

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/audit"
	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/tokens"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// logs returns the JSON log lines.
func (l *lockedBuf) lines(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(l.String()), "\n") {
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("log line %q: %v", ln, err)
		}
		out = append(out, m)
	}
	return out
}

// audits returns the audit records with the given event.
func (l *lockedBuf) audits(t *testing.T, event string) []map[string]any {
	var out []map[string]any
	for _, m := range l.lines(t) {
		if m["msg"] == audit.Message && m["event"] == event {
			out = append(out, m)
		}
	}
	return out
}

// find returns the first record with the given msg.
func (l *lockedBuf) find(t *testing.T, msg string) map[string]any {
	t.Helper()
	for _, m := range l.lines(t) {
		if m["msg"] == msg {
			return m
		}
	}
	t.Fatalf("no %q record in %s", msg, l.String())
	return nil
}

// enableAudit switches the audit log of srv on or off, writing JSON to the
// returned buffer.
func enableAudit(srv *Server, on bool) *lockedBuf {
	buf := &lockedBuf{}
	log := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	srv.log = log
	srv.cfg.Audit = config.Audit{Enabled: on, Retention: "12 months"}
	srv.audit = audit.New(log, srv.cfg)
	return buf
}

func auditUpstream() config.Upstream {
	return config.Upstream{
		Name: "tn", Title: "Tradernet", Path: "/tn", URL: "https://upstream.example.com/mcp",
		Credentials: []config.Credential{
			{Header: "x-api-key", Label: "API key", Secret: true},
			{Header: "x-user", Label: "User", Audit: true},
			{Header: "x-extra", Label: "Extra", Optional: true},
		},
	}
}

func creds(m map[string]any) map[string]any {
	c, _ := m["creds"].(map[string]any)
	return c
}

func TestAuditAuthorizeRecord(t *testing.T) {
	e := newAZ(t, auditUpstream())
	buf := enableAudit(e.srv, true)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	f := goodForm(sealed)
	f.Set("cred_2", "sid-value") // optional, neither secret nor audited
	rec := e.post(f)
	u := mustSeeOther(t, rec)

	recs := buf.audits(t, audit.EventAuthorize)
	if len(recs) != 1 {
		t.Fatalf("%d authorize records in %s", len(recs), buf.String())
	}
	r := recs[0]
	want := map[string]any{
		"level": "INFO", "client_ip": "192.0.2.1", "upstream": "tn",
		"client_id": shortID(e.clientID), "redirect_host": "claude.ai",
	}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("%s = %v, want %v", k, r[k], v)
		}
	}
	if c := creds(r); len(c) != 1 || c["X-User"] != "alice" {
		t.Errorf("creds = %v", c)
	}
	forbidden := []string{"sekret", "sid-value", u.Query().Get("code"), e.clientID, "st&te", "st%26te", azChallenge}
	for _, s := range forbidden {
		if s != "" && strings.Contains(buf.String(), s) {
			t.Errorf("log contains %q: %s", s, buf.String())
		}
	}
}

func TestAuditOffWritesNothing(t *testing.T) {
	e := newAZ(t, auditUpstream())
	buf := enableAudit(e.srv, false)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	mustSeeOther(t, e.post(goodForm(sealed)))
	if buf.String() != "" {
		t.Errorf("log written with audit off: %s", buf.String())
	}
}

func TestAuditAuthorizeRefusals(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*config.Upstream)
		msg   string
	}{
		{"allow-list", func(up *config.Upstream) { up.Credentials[1].AllowedValues = []string{"bob"} }, "authorize refused: credentials not in allowed_values"},
	}
	for _, tt := range tests {
		for _, on := range []bool{true, false} {
			t.Run(tt.name, func(t *testing.T) {
				up := auditUpstream()
				tt.setup(&up)
				e := newAZ(t, up)
				buf := enableAudit(e.srv, on)
				sealed := hidden(t, e.get(e.query(nil)).Body.String())
				if rec := e.post(goodForm(sealed)); rec.Code != http.StatusBadRequest {
					t.Fatalf("status %d", rec.Code)
				}
				m := buf.find(t, tt.msg)
				if on {
					if m["client_ip"] != "192.0.2.1" || creds(m)["X-User"] != "alice" {
						t.Errorf("record = %v", m)
					}
				} else if _, ok := m["client_ip"]; ok || m["creds"] != nil {
					t.Errorf("identification logged with audit off: %v", m)
				}
				if strings.Contains(buf.String(), "sekret") {
					t.Errorf("secret logged: %s", buf.String())
				}
			})
		}
	}
}

func TestAuditAuthorizeUpstreamRejection(t *testing.T) {
	f := newMCPFake(t)
	e := newAZValidated(t, f, func(up *config.Upstream) { up.Credentials[1].Audit = true })
	buf := enableAudit(e.srv, true)
	f.on("tools/call", rejectingTool())
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	if rec := e.post(goodForm(sealed)); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	m := buf.find(t, "credentials rejected by upstream")
	if m["client_ip"] != "192.0.2.1" || creds(m)["X-User"] != "alice" {
		t.Errorf("record = %v", m)
	}
	if len(buf.audits(t, audit.EventAuthorize)) != 0 {
		t.Error("authorize record for a refused submission")
	}
}

func auditTK(t *testing.T) (*tkEnv, *lockedBuf) {
	e := newTK(t)
	up := auditUpstream()
	e.cfg.Upstreams = []config.Upstream{up}
	return e, enableAudit(e.srv, true)
}

func (e *tkEnv) auditCode(t *testing.T) string {
	return e.code(t, e.none, func(c *tokens.Code) {
		c.Creds = map[string]string{"X-Api-Key": "sekret", "X-User": "alice", "X-Extra": "sid-value"}
	})
}

func TestAuditTokenRecords(t *testing.T) {
	e, buf := auditTK(t)
	rawCode := e.auditCode(t)
	access, g0 := e.wantOK(t, e.do(e.codeForm(e.none, rawCode)))
	access2, g1 := e.wantOK(t, e.do(e.refreshForm(e.none, g0)))

	recs := buf.audits(t, audit.EventToken)
	if len(recs) != 2 {
		t.Fatalf("%d token records in %s", len(recs), buf.String())
	}
	fam := recs[0]["family"]
	for i, grant := range []string{"authorization_code", "refresh_token"} {
		r := recs[i]
		if r["grant_type"] != grant || r["client_ip"] != "192.0.2.1" || r["upstream"] != "tn" ||
			r["client_id"] != shortID(e.none) || r["family"] != fam || fam == "" {
			t.Errorf("record %d = %v", i, r)
		}
		if c := creds(r); len(c) != 1 || c["X-User"] != "alice" {
			t.Errorf("record %d creds = %v", i, c)
		}
	}
	for _, s := range []string{"sekret", "sid-value", rawCode, access, access2, g0, g1, tkVerifier, e.none} {
		if strings.Contains(buf.String(), s) {
			t.Errorf("log contains %q: %s", s, buf.String())
		}
	}
}

func TestAuditTokenFailureWritesNoRecord(t *testing.T) {
	e, buf := auditTK(t)
	f := e.codeForm(e.none, e.auditCode(t))
	f.Set("code_verifier", strings.Repeat("x", 50))
	e.wantErr(t, e.do(f), 400, "invalid_grant")
	if n := len(buf.audits(t, audit.EventToken)); n != 0 {
		t.Errorf("%d token records for a refused request", n)
	}
}

func TestAuditRefreshReuseRefusal(t *testing.T) {
	e, buf := auditTK(t)
	_, g0 := e.wantOK(t, e.do(e.codeForm(e.none, e.auditCode(t))))
	e.wantOK(t, e.do(e.refreshForm(e.none, g0)))
	e.wantErr(t, e.do(e.refreshForm(e.none, g0)), 400, "invalid_grant") // reuse

	m := buf.find(t, "refresh token reuse detected; family revoked")
	if m["level"] != "WARN" || m["client_ip"] != "192.0.2.1" || creds(m)["X-User"] != "alice" ||
		m["client_id"] != shortID(e.none) || m["upstream"] != "tn" {
		t.Errorf("record = %v", m)
	}
	if strings.Contains(buf.String(), "sekret") || strings.Contains(buf.String(), g0) {
		t.Errorf("secret or token logged: %s", buf.String())
	}
}

// A hostile audited value must stay inside its field through the real flow.
func TestAuditHostileValueThroughAuthorize(t *testing.T) {
	e := newAZ(t, auditUpstream())
	buf := enableAudit(e.srv, true)
	hostile := `alice","event":"forged","client_ip":"6.6.6.6","x":"`
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	f := goodForm(sealed)
	f.Set("cred_1", hostile)
	mustSeeOther(t, e.post(f))
	recs := buf.audits(t, audit.EventAuthorize)
	if len(recs) != 1 || recs[0]["client_ip"] != "192.0.2.1" || creds(recs[0])["X-User"] != hostile {
		t.Fatalf("records = %v", recs)
	}
	if n := len(buf.lines(t)); n != 1 {
		t.Errorf("%d log lines, want 1: %s", n, buf.String())
	}
}
