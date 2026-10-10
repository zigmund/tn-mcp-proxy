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

// Code is the payload of an authorization code (seal.KindCode). The code
// expires through the seal envelope (oauth.code_ttl). The token endpoint
// must check, besides authenticity and expiry, that the presenting client
// equals ClientID, that redirect_uri equals RedirectURI and that the PKCE
// code_verifier hashes (S256) to CodeChallenge. Codes are not single-use by
// themselves (the proxy is stateless); JTI is reserved for optional replay
// tracking and is not enforced.
type Code struct {
	ClientID      string            `json:"c"`  // DCR client_id the code was issued to
	RedirectURI   string            `json:"r"`  // redirect_uri of the authorization request
	CodeChallenge string            `json:"ch"` // PKCE S256 challenge, base64url
	Upstream      string            `json:"u"`  // upstream name
	Creds         map[string]string `json:"h"`  // canonical header name -> value
	JTI           string            `json:"j"`  // random unique id
}

// String redacts the credentials.
func (Code) String() string { return redacted }

// GoString redacts the credentials for %#v.
func (Code) GoString() string { return "tokens.Code{" + redacted + "}" }

// LogValue implements slog.LogValuer with a redacted value.
func (Code) LogValue() slog.Value { return slog.StringValue(redacted) }

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
