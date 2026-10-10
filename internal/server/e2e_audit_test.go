package server_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/server"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestE2EAuditLog drives the whole flow with audit on and checks the records
// and that nothing sensitive is written, in both log formats, with an audited
// value that tries to forge fields.
func TestE2EAuditLog(t *testing.T) {
	const (
		apiSecret = "secret-BBB-222"
		sid       = "sid-CCC-333"
		clientIP  = "198.51.100.9"
	)
	hostiles := map[string]string{
		"json": `acct","event":"forged","client_ip":"6.6.6.6","x":"`,
		"text": "acct\" event=forged client_ip=6.6.6.6 msg=audit",
	}
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			account := hostiles[format]
			up := newFakeUpstream(t)
			cfg, err := config.Parse([]byte(fmt.Sprintf(`
listen: 127.0.0.1:0
public_url: %s
secrets:
  token_keys: ["`+testKey("e2e-audit")+`"]
audit: { enabled: true, retention: "12 months" }
oauth:
  allowed_redirect_uris: ["%s"]
upstreams:
  - name: fake
    path: /fake/mcp
    url: %s/mcp
    forbidden_arguments: [api_secret]
    credentials:
      - { header: X-Api-Key, label: API key, audit: true }
      - { header: X-Api-Secret, label: API secret, secret: true }
      - { header: X-Sid, label: SID, optional: true }
`, e2ePublicURL, e2eRedirectURI, up.srv.URL)), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			sealer, err := seal.New(cfg.Secrets.Keys)
			if err != nil {
				t.Fatal(err)
			}
			logs := &syncBuffer{}
			var log *slog.Logger
			if format == "json" {
				log = slog.New(slog.NewJSONHandler(logs, nil))
			} else {
				log = slog.New(slog.NewTextHandler(logs, nil))
			}
			h, err := server.Handler(cfg, sealer, log)
			if err != nil {
				t.Fatal(err)
			}
			withIP := func(req *http.Request) *http.Request {
				req.RemoteAddr = clientIP + ":4444"
				return req
			}

			regBody, _ := json.Marshal(map[string]any{
				"client_name": "E2E", "redirect_uris": []string{e2eRedirectURI},
				"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"},
				"response_types": []string{"code"},
			})
			req := httptest.NewRequest(http.MethodPost, e2ePublicURL+"/oauth/register", strings.NewReader(string(regBody)))
			req.Header.Set("Content-Type", "application/json")
			rec := do(t, h, req)
			mustStatus(t, rec, http.StatusCreated, "register")
			var reg struct {
				ClientID string `json:"client_id"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &reg); err != nil {
				t.Fatal(err)
			}

			sum := sha256.Sum256([]byte(e2eVerifier))
			const state = "state-STATE-444"
			aq := url.Values{
				"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {e2eRedirectURI}, "state": {state},
				"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
			}
			rec = do(t, h, withIP(httptest.NewRequest(http.MethodGet, e2ePublicURL+"/oauth/authorize?"+aq.Encode(), nil)))
			mustStatus(t, rec, http.StatusOK, "GET authorize")
			form := url.Values{}
			for _, hm := range hiddenRe.FindAllStringSubmatch(rec.Body.String(), -1) {
				form.Set(hm[1], html.UnescapeString(hm[2]))
			}
			fields := map[string]string{}
			for _, lm := range labelRe.FindAllStringSubmatch(rec.Body.String(), -1) {
				fields[strings.TrimSuffix(strings.TrimSpace(lm[2]), " (optional)")] = lm[1]
			}
			form.Set(fields["API key"], account)
			form.Set(fields["API secret"], apiSecret)
			form.Set(fields["SID"], sid)
			req = httptest.NewRequest(http.MethodPost, e2ePublicURL+"/oauth/authorize", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec = do(t, h, withIP(req))
			// The form rejects control characters, so a value can only try to
			// forge fields with quotes and separators.
			mustStatus(t, rec, http.StatusSeeOther, "POST authorize")
			loc, _ := url.Parse(rec.Header().Get("Location"))
			code := loc.Query().Get("code")

			tokenForm := url.Values{
				"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {e2eRedirectURI},
				"code_verifier": {e2eVerifier}, "client_id": {reg.ClientID},
			}
			post := func(path string, f url.Values) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, e2ePublicURL+path, strings.NewReader(f.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return do(t, h, withIP(r))
			}
			tp := decodeTokens(t, post("/oauth/token", tokenForm))
			tp2 := decodeTokens(t, post("/oauth/token", url.Values{
				"grant_type": {"refresh_token"}, "refresh_token": {tp.RefreshToken}, "client_id": {reg.ClientID},
			}))

			call := func(body string) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, e2ePublicURL+"/fake/mcp", strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Accept", "application/json, text/event-stream")
				r.Header.Set("Authorization", "Bearer "+tp2.AccessToken)
				return do(t, h, withIP(r))
			}
			mustStatus(t, call(initializeBody), http.StatusOK, "proxied call")
			mustStatus(t, call(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"x","arguments":{"api_secret":"ARGSECRET"}}}`),
				http.StatusBadRequest, "forbidden argument")

			out := logs.String()
			for _, s := range []string{apiSecret, sid, code, tp.AccessToken, tp.RefreshToken, tp2.AccessToken, tp2.RefreshToken,
				reg.ClientID, state, e2eVerifier, "ARGSECRET", "aq=", "code_challenge"} {
				if strings.Contains(out, s) {
					t.Errorf("log contains %q:\n%s", s, out)
				}
			}
			if format == "json" {
				var events []string
				refusals := 0
				for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
					var m map[string]any
					if err := json.Unmarshal([]byte(ln), &m); err != nil {
						t.Fatalf("log line %q: %v", ln, err)
					}
					switch m["msg"] {
					case "audit":
						events = append(events, fmt.Sprint(m["event"]))
						if m["client_ip"] != clientIP {
							t.Errorf("record = %v", m)
						}
						if c := m["creds"].(map[string]any); len(c) != 1 || c["X-Api-Key"] != account {
							t.Errorf("creds = %v", c)
						}
					case "tool call with forbidden argument rejected":
						refusals++
						if m["client_ip"] != clientIP || m["argument"] != "api_secret" {
							t.Errorf("refusal = %v", m)
						}
					}
					if _, forged := m["x"]; forged || m["event"] == "forged" {
						t.Errorf("forged field in %v", m)
					}
				}
				want := []string{"authorize", "token", "token", "request"}
				if strings.Join(events, ",") != strings.Join(want, ",") || refusals != 1 {
					t.Errorf("events = %v (refusals %d), want %v and 1 refusal", events, refusals, want)
				}
			} else {
				// Every line starts with the standard time= key.
				for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
					if !strings.HasPrefix(ln, "time=") {
						t.Errorf("stray line %q in:\n%s", ln, out)
					}
				}
				if n := strings.Count(out, " msg=audit event="); n != 4 {
					t.Errorf("%d audit records, want 4:\n%s", n, out)
				}
			}
		})
	}
}
