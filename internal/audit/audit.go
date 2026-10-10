// Package audit writes the opt-in audit log: info-level records that tie a
// client IP to the values of the credentials an operator marked audit: true,
// so "who used account X through this server, and when" can be answered.
//
// Records have msg "audit" and an event field. They never carry secret
// credential values, tokens, codes, bodies, argument values or query strings:
// the only user-controlled strings that reach a record are the audited
// credential values themselves, the IP, and (clipped) JSON-RPC method and tool
// names, all written through slog, which quotes or escapes them in both the
// JSON and the text format.
//
// A nil *Logger is valid and disabled, so call sites need no checks.
package audit

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

// Message is the msg of every audit record.
const Message = "audit"

// Event names.
const (
	EventAuthorize = "authorize"
	EventToken     = "token"
	EventRequest   = "request"
)

// Logger writes audit records.
type Logger struct{ log *slog.Logger }

// New returns a Logger writing to log, or nil (disabled) when cfg does not
// enable the audit log. A nil log means slog.Default().
func New(log *slog.Logger, cfg *config.Config) *Logger {
	if cfg == nil || !cfg.Audit.Enabled {
		return nil
	}
	if log == nil {
		log = slog.Default()
	}
	return &Logger{log: log}
}

// Enabled reports whether records are written.
func (l *Logger) Enabled() bool { return l != nil }

// Record writes one audit record of the given event at info level.
func (l *Logger) Record(ctx context.Context, event string, attrs ...slog.Attr) {
	if l == nil {
		return
	}
	all := make([]slog.Attr, 0, len(attrs)+1)
	all = append(all, slog.String("event", event))
	all = append(all, attrs...)
	l.log.LogAttrs(ctx, slog.LevelInfo, Message, all...)
}

// Creds returns the "creds" group holding the values of the audited
// credentials of up, keyed by header name. creds maps header names (any
// casing) to values, as stored in tokens. It is the zero Attr, which slog
// omits, when audit is off or nothing is audited. Secret credentials and
// credentials without audit: true are never included.
func (l *Logger) Creds(up config.Upstream, creds map[string]string) slog.Attr {
	if l == nil {
		return slog.Attr{}
	}
	var attrs []any
	for _, cr := range up.AuditedCredentials() {
		if v, ok := lookup(creds, cr.Header); ok && v != "" {
			attrs = append(attrs, slog.String(http.CanonicalHeaderKey(cr.Header), v))
		}
	}
	if len(attrs) == 0 {
		return slog.Attr{}
	}
	return slog.Group("creds", attrs...)
}

// Who returns the extra log arguments that identify the actor of a refusal:
// the client IP and the audited values. It is nil when audit is off, so the
// refusal logs are unchanged then. Pass it as log.Info(msg, append(args,
// l.Who(...)...)...).
func (l *Logger) Who(ip string, up config.Upstream, creds map[string]string) []any {
	if l == nil {
		return nil
	}
	out := []any{slog.String("client_ip", ip)}
	if g := l.Creds(up, creds); g.Key != "" {
		out = append(out, g)
	}
	return out
}

func lookup(m map[string]string, header string) (string, bool) {
	canon := http.CanonicalHeaderKey(header)
	if v, ok := m[canon]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, header) {
			return v, true
		}
	}
	return "", false
}
