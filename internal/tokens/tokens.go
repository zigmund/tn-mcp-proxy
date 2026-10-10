// Package tokens defines the payloads sealed into OAuth access and refresh
// tokens. They are shared by the oauth package (which issues them) and the
// proxy package (which opens access tokens).
//
// The payloads carry upstream credentials: never log them. Both types redact
// themselves when formatted or passed to slog, as a safety net only.
//
// JSON keys are deliberately short because tokens travel in HTTP headers.
// Expiry is not part of the payload; it lives in the seal envelope.
package tokens

import (
	"log/slog"
)

const redacted = "[redacted]"

// Access is the payload of an access token (seal.KindAccess).
type Access struct {
	Upstream string            `json:"u"` // upstream name
	ClientID string            `json:"c"` // DCR client_id the token was issued to
	Creds    map[string]string `json:"h"` // canonical header name -> value
}

// Refresh is the payload of a refresh token (seal.KindRefresh).
type Refresh struct {
	Upstream string            `json:"u"` // upstream name
	ClientID string            `json:"c"` // DCR client_id the token was issued to
	Creds    map[string]string `json:"h"` // canonical header name -> value
}

// String redacts the credentials.
func (Access) String() string { return redacted }

// GoString redacts the credentials for %#v.
func (Access) GoString() string { return "tokens.Access{" + redacted + "}" }

// LogValue implements slog.LogValuer with a redacted value.
func (Access) LogValue() slog.Value { return slog.StringValue(redacted) }

// String redacts the credentials.
func (Refresh) String() string { return redacted }

// GoString redacts the credentials for %#v.
func (Refresh) GoString() string { return "tokens.Refresh{" + redacted + "}" }

// LogValue implements slog.LogValuer with a redacted value.
func (Refresh) LogValue() slog.Value { return slog.StringValue(redacted) }
