package oauth

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/tokens"
)

const (
	rejectedMsg    = "Tradernet rejected these credentials. Check them and try again."
	notAllowedMsg  = "These credentials cannot be used on this server: its operator only allows specific keys."
	unavailableMsg = "Could not verify the credentials with Tradernet right now. Try again later."
	upstreamText   = "Error executing tool get_auth_info: Invalid api key provided"
)

// newAZValidated is newAZ with an upstream that validates against f.
func newAZValidated(t *testing.T, f *mcpFake, mod func(*config.Upstream)) *azEnv {
	t.Helper()
	up := config.Upstream{
		Name: "tn", Title: "Tradernet", Path: "/tn", URL: f.srv.URL + "/mcp",
		Credentials: []config.Credential{
			{Header: "x-api-key", Label: "API key", Secret: true},
			{Header: "x-user", Label: "User"},
			{Header: "x-extra", Label: "Extra", Optional: true},
		},
		Validate: &config.Validate{Tool: "get_auth_info", Timeout: 5 * time.Second},
	}
	if mod != nil {
		mod(&up)
	}
	return newAZ(t, up)
}

func rejectingTool() respFunc {
	return replyJSON(200, `{"content":[{"type":"text","text":"`+upstreamText+`"}],"isError":true}`)
}

func TestAuthorizeValidateAcceptsAndIssuesCode(t *testing.T) {
	f := newMCPFake(t)
	e := newAZValidated(t, f, nil)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	if n := len(f.requests()); n != 0 {
		t.Fatalf("GET contacted the upstream (%d requests)", n)
	}

	u := mustSeeOther(t, e.post(goodForm(sealed)))
	code, err := seal.OpenAs[tokens.Code](e.srv.sealer, seal.KindCode, u.Query().Get("code"))
	if err != nil {
		t.Fatal(err)
	}
	if code.Creds["X-Api-Key"] != "sekret" || code.Creds["X-User"] != "alice" {
		t.Errorf("code creds not the entered ones")
	}

	// The check used exactly the entered (trimmed) credentials on every request;
	// the empty optional one is not sent.
	reqs := f.requests()
	if len(reqs) != 3 {
		t.Fatalf("upstream saw %v, want the 3-step check", f.methods())
	}
	for _, r := range reqs {
		if r.Header.Get("X-Api-Key") != "sekret" || r.Header.Get("X-User") != "alice" {
			t.Errorf("%s: credentials = %q / %q", r.RPC, r.Header.Get("X-Api-Key"), r.Header.Get("X-User"))
		}
		if _, ok := r.Header["X-Extra"]; ok {
			t.Errorf("%s: empty optional credential sent", r.RPC)
		}
	}
	if got := reqs[2].Msg["params"].(map[string]any)["name"]; got != "get_auth_info" {
		t.Errorf("tool = %v", got)
	}
}

func TestAuthorizeValidateRefusals(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*mcpFake)
		status  int
		message string
	}{
		{"tool error", func(f *mcpFake) { f.on("tools/call", rejectingTool()) }, http.StatusBadRequest, rejectedMsg},
		{"401", func(f *mcpFake) { f.on("tools/call", status(401)) }, http.StatusBadRequest, rejectedMsg},
		{"403 at initialize", func(f *mcpFake) { f.on("initialize", status(403)) }, http.StatusBadRequest, rejectedMsg},
		{"jsonrpc error", func(f *mcpFake) {
			f.on("tools/call", func(w http.ResponseWriter, _ *http.Request, id any) { mcpJSON(w, 200, rpcErr(id, -32601)) })
		}, http.StatusServiceUnavailable, unavailableMsg},
		{"500", func(f *mcpFake) { f.on("tools/call", status(500)) }, http.StatusServiceUnavailable, unavailableMsg},
		{"garbage", func(f *mcpFake) {
			f.on("tools/call", func(w http.ResponseWriter, _ *http.Request, _ any) { mcpJSON(w, 200, "not json") })
		}, http.StatusServiceUnavailable, unavailableMsg},
		{"redirect", func(f *mcpFake) {
			f.on("initialize", func(w http.ResponseWriter, r *http.Request, _ any) {
				http.Redirect(w, r, "https://other.example.com/", http.StatusFound)
			})
		}, http.StatusServiceUnavailable, unavailableMsg},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newMCPFake(t)
			tt.setup(f)
			e := newAZValidated(t, f, nil)
			sealed := hidden(t, e.get(e.query(nil)).Body.String())

			rec := e.post(goodForm(sealed))
			mustPage(t, rec, tt.status)
			body := rec.Body.String()
			if got, want := rec.Header().Get("Retry-After"), map[bool]string{true: retryAfterUnavailable}[tt.status == http.StatusServiceUnavailable]; got != want {
				t.Errorf("Retry-After = %q, want %q", got, want)
			}
			if !strings.Contains(body, tt.message) {
				t.Errorf("body lacks %q:\n%s", tt.message, body)
			}
			if !strings.Contains(body, `name="request"`) || hidden(t, body) != sealed {
				t.Error("form not re-rendered with the same sealed request")
			}
			if !strings.Contains(body, `value="alice"`) {
				t.Error("non-secret value not kept")
			}
			for _, leak := range []string{"sekret", "Invalid api key", "upstream-secret-text"} {
				if strings.Contains(body, leak) {
					t.Errorf("body leaks %q", leak)
				}
			}
			if rec.Header().Get("X-Frame-Options") != "DENY" || rec.Header().Get("Cache-Control") != "no-store" {
				t.Error("form lacks security headers")
			}
		})
	}
}

// TestAuthorizeValidateRetry: after a refusal the same form can be resubmitted.
func TestAuthorizeValidateRetry(t *testing.T) {
	f := newMCPFake(t)
	f.on("tools/call", rejectingTool())
	e := newAZValidated(t, f, nil)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())

	mustPage(t, e.post(goodForm(sealed)), http.StatusBadRequest)
	delete(f.h, "tools/call")
	mustSeeOther(t, e.post(goodForm(sealed)))
}

func TestAuthorizeValidateTimeoutFailsClosed(t *testing.T) {
	f := newMCPFake(t)
	f.on("tools/call", func(w http.ResponseWriter, r *http.Request, _ any) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	})
	e := newAZValidated(t, f, func(u *config.Upstream) { u.Validate.Timeout = 200 * time.Millisecond })
	sealed := hidden(t, e.get(e.query(nil)).Body.String())

	start := time.Now()
	rec := e.post(goodForm(sealed))
	mustPage(t, rec, http.StatusServiceUnavailable)
	if !strings.Contains(rec.Body.String(), unavailableMsg) {
		t.Errorf("body lacks %q", unavailableMsg)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("POST took %v", d)
	}
}

func TestAuthorizeValidateTitleFallsBackToName(t *testing.T) {
	f := newMCPFake(t)
	f.on("tools/call", rejectingTool())
	e := newAZValidated(t, f, func(u *config.Upstream) { u.Title = "" })
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	rec := e.post(goodForm(sealed))
	mustPage(t, rec, http.StatusBadRequest)
	if !strings.Contains(rec.Body.String(), "tn rejected these credentials.") {
		t.Errorf("body = %s", rec.Body)
	}
}

func TestAuthorizeWithoutValidateNeverContactsUpstream(t *testing.T) {
	f := newMCPFake(t)
	e := newAZValidated(t, f, func(u *config.Upstream) { u.Validate = nil })
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	mustSeeOther(t, e.post(goodForm(sealed)))
	if n := len(f.requests()); n != 0 {
		t.Errorf("upstream contacted %d times without validate", n)
	}
}

func TestAuthorizeInvalidFormNeverContactsUpstream(t *testing.T) {
	f := newMCPFake(t)
	e := newAZValidated(t, f, nil)
	sealed := hidden(t, e.get(e.query(nil)).Body.String())
	form := goodForm(sealed)
	form.Set("cred_0", "")
	mustPage(t, e.post(form), http.StatusBadRequest)
	if n := len(f.requests()); n != 0 {
		t.Errorf("upstream contacted %d times for an invalid form", n)
	}
}

func TestAuthorizeValidateNoSecretsInLogs(t *testing.T) {
	rpcFail := func(w http.ResponseWriter, _ *http.Request, id any) { mcpJSON(w, 200, rpcErr(id, -32602)) }
	tests := []struct {
		name   string
		setup  func(*mcpFake)
		status int
		msg    string // expected log message
		level  string
	}{
		{"rejected", func(f *mcpFake) { f.on("tools/call", rejectingTool()) }, 400, "credentials rejected by upstream", "level=INFO"},
		{"rpc error", func(f *mcpFake) { f.on("tools/call", rpcFail) }, 503, "credential check unavailable", "level=WARN"},
		{"500", func(f *mcpFake) { f.on("tools/call", status(500)) }, 503, "credential check unavailable", "level=WARN"},
		{"unreachable", func(f *mcpFake) { f.srv.Close() }, 503, "credential check unavailable", "level=WARN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newMCPFake(t)
			tt.setup(f)
			e := newAZValidated(t, f, func(u *config.Upstream) { u.URL += "?token=urlsecret" })
			var buf strings.Builder
			e.srv.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			sealed := hidden(t, e.get(e.query(nil)).Body.String())
			form := goodForm(sealed)
			form.Set("cred_0", "topsecret")
			mustPage(t, e.post(form), tt.status)

			logs := buf.String()
			for _, leak := range []string{"topsecret", "alice", "urlsecret", "Invalid api key", "upstream-secret-text", f.srv.URL} {
				if strings.Contains(logs, leak) {
					t.Errorf("logs leak %q: %s", leak, logs)
				}
			}
			for _, want := range []string{tt.msg, tt.level, "upstream=tn", "step="} {
				if !strings.Contains(logs, want) {
					t.Errorf("logs lack %q: %s", want, logs)
				}
			}
		})
	}
}
