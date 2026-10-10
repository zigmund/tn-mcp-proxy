package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

var testUp = config.Upstream{
	Name: "tn",
	Credentials: []config.Credential{
		{Header: "X-TN-API-Key", Label: "API key", Audit: true},
		{Header: "X-TN-API-Secret", Label: "API secret", Secret: true},
		{Header: "X-TN-SID", Label: "SID", Optional: true},
	},
}

func enabled() *config.Config {
	return &config.Config{Audit: config.Audit{Enabled: true, Retention: "x"}}
}

func TestNilLoggerIsDisabled(t *testing.T) {
	var l *Logger
	if l.Enabled() {
		t.Error("nil logger enabled")
	}
	l.Record(context.Background(), EventToken, slog.String("a", "b")) // must not panic
	if g := l.Creds(testUp, map[string]string{"X-Tn-Api-Key": "k"}); g.Key != "" {
		t.Errorf("Creds = %v", g)
	}
	if w := l.Who("1.2.3.4", testUp, nil); w != nil {
		t.Errorf("Who = %v", w)
	}
	if New(slog.Default(), &config.Config{}) != nil {
		t.Error("New returned a logger with audit disabled")
	}
}

func TestOnlyAuditedValuesAreRecorded(t *testing.T) {
	creds := map[string]string{"X-Tn-Api-Key": "KEYVAL", "X-Tn-Api-Secret": "SECRETVAL", "X-Tn-Sid": "SIDVAL"}
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			var buf bytes.Buffer
			l := New(newLog(&buf, format), enabled())
			l.Record(context.Background(), EventRequest, slog.String("client_ip", "1.2.3.4"), l.Creds(testUp, creds))
			out := buf.String()
			if !strings.Contains(out, "KEYVAL") {
				t.Errorf("audited value missing: %s", out)
			}
			for _, bad := range []string{"SECRETVAL", "SIDVAL"} {
				if strings.Contains(out, bad) {
					t.Errorf("%s leaked: %s", bad, out)
				}
			}
		})
	}
}

func TestWhoAndHeaderCasing(t *testing.T) {
	var buf bytes.Buffer
	l := New(newLog(&buf, "json"), enabled())
	l.log.Info("refused", l.Who("9.9.9.9", testUp, map[string]string{"x-tn-api-key": "lower"})...)
	var m struct {
		ClientIP string            `json:"client_ip"`
		Creds    map[string]string `json:"creds"`
	}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.ClientIP != "9.9.9.9" || m.Creds["X-Tn-Api-Key"] != "lower" {
		t.Errorf("record = %s", buf.String())
	}
}

// Values are user controlled: whatever they contain must stay inside their own
// field in both formats.
func TestInjectionIsContained(t *testing.T) {
	values := []string{
		"v\"} ,\"event\":\"forged\",\"x\":{\"y\":\"",
		"v\nmsg=audit event=forged level=ERROR",
		"v\r\ntime=2000-01-01T00:00:00Z level=INFO msg=audit event=forged",
		"v\" event=forged client_ip=6.6.6.6 \"",
		"v  \x00\x1b[31mred",
		"creds.X-TN-API-Key=forged",
	}
	for _, v := range values {
		t.Run("json", func(t *testing.T) {
			var buf bytes.Buffer
			l := New(newLog(&buf, "json"), enabled())
			l.Record(context.Background(), EventAuthorize, slog.String("client_ip", "1.2.3.4"), l.Creds(testUp, map[string]string{"X-Tn-Api-Key": v}))
			if n := strings.Count(buf.String(), "\n"); n != 1 {
				t.Fatalf("%d lines: %q", n, buf.String())
			}
			var m map[string]any
			if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
				t.Fatalf("invalid json: %v: %q", err, buf.String())
			}
			if len(m) != 6 || m["event"] != EventAuthorize || m["client_ip"] != "1.2.3.4" { // time, level, msg, event, client_ip, creds
				t.Errorf("fields = %v", m)
			}
			creds := m["creds"].(map[string]any)
			if got := creds["X-Tn-Api-Key"]; len(creds) != 1 || (got != v && !strings.ContainsAny(v, "\x00\u2028")) {
				t.Errorf("creds = %v, want the single value %q", creds, v)
			}
		})
		t.Run("text", func(t *testing.T) {
			var buf bytes.Buffer
			l := New(newLog(&buf, "text"), enabled())
			l.Record(context.Background(), EventAuthorize, slog.String("client_ip", "1.2.3.4"), l.Creds(testUp, map[string]string{"X-Tn-Api-Key": v}))
			out := buf.String()
			if n := strings.Count(out, "\n"); n != 1 || !strings.HasSuffix(out, "\n") {
				t.Fatalf("%d lines: %q", n, out)
			}
			// The value is exactly one quoted token that ends the line: nothing
			// of it can be read as another field.
			const key = ` creds.X-Tn-Api-Key=`
			i := strings.Index(out, key)
			if i < 0 || strings.Count(out[:i], "=") != 5 { // time, level, msg, event, client_ip
				t.Fatalf("unexpected prefix in %q", out)
			}
			q, err := strconv.QuotedPrefix(out[i+len(key):])
			if err != nil || out[i+len(key)+len(q):] != "\n" {
				t.Fatalf("value is not one quoted token: %q", out)
			}
			if got, err := strconv.Unquote(q); err != nil || got != v {
				t.Errorf("value = %q (%v), want %q", got, err, v)
			}
		})
	}
}

func newLog(buf *bytes.Buffer, format string) *slog.Logger {
	if format == "text" {
		return slog.New(slog.NewTextHandler(buf, nil))
	}
	return slog.New(slog.NewJSONHandler(buf, nil))
}
