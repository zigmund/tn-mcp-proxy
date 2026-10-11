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

// Refresh is the payload of a refresh token (seal.KindRefresh). Refresh
// tokens are single-use and form chains: Family (random 128-bit, created at
// code exchange) is shared by every token of one login, and Gen counts
// rotations (0 for the first token). The token endpoint tracks the highest
// redeemed Gen per Family in an in-memory cache until Exp; presenting a Gen
// that is not newer revokes the whole family. The cache is per-process, so a
// restart forgets it.
//
// Start is the unix time of the original login (the code exchange) and is
// copied unchanged on every rotation. Exp slides with each refresh, but the
// token endpoint caps it, and refuses the chain, at Start plus
// oauth.max_session_ttl (or at End when the user chose a session length), so a
// chain cannot be kept alive forever unless the user chose so. Start == 0
// marks a token issued before the field existed; the token endpoint treats
// the moment of its next refresh as the start of the chain (one-time
// migration).
type Refresh struct {
	Upstream string            `json:"u"` // upstream name
	ClientID string            `json:"c"` // DCR client_id the token was issued to
	Creds    map[string]string `json:"h"` // canonical header name -> value
	Family   string            `json:"f"` // random chain id
	Gen      int64             `json:"g"` // generation within the chain, starting at 0
	Exp      int64             `json:"e"` // expiry, unix seconds (mirrors the seal envelope; bounds the cache entry)
	Start    int64             `json:"s"` // login time, unix seconds; constant across the chain, 0 for legacy tokens
	// End is the absolute session end the user chose at login, copied unchanged
	// on every rotation: a unix time (> 0), or SessionUnlimited for no absolute
	// end (the idle refresh expiry still applies). 0, the zero value and what
	// tokens issued before the choice existed (or without one) carry, means
	// "no choice": the end is Start plus oauth.max_session_ttl. Unlimited must
	// therefore never be the zero value.
	End int64 `json:"z,omitempty"`
}

// SessionUnlimited is the marker for "no absolute session end" in Code.Session
// and Refresh.End. It is deliberately not 0, which means "no choice made".
const SessionUnlimited int64 = -1

// Code is the payload of an authorization code (seal.KindCode). The code
// expires through the seal envelope (oauth.code_ttl). The token endpoint
// must check, besides authenticity and expiry, that the presenting client
// equals ClientID, that redirect_uri equals RedirectURI and that the PKCE
// code_verifier hashes (S256) to CodeChallenge. Codes are single-use: the
// token endpoint records JTI in an in-memory cache until Exp and rejects a
// second redemption. The cache is per-process, so a restart forgets it.
type Code struct {
	ClientID      string            `json:"c"`  // DCR client_id the code was issued to
	RedirectURI   string            `json:"r"`  // redirect_uri of the authorization request
	CodeChallenge string            `json:"ch"` // PKCE S256 challenge, base64url
	Upstream      string            `json:"u"`  // upstream name
	Creds         map[string]string `json:"h"`  // canonical header name -> value
	JTI           string            `json:"j"`  // random unique id, enforced single-use by the token endpoint
	Exp           int64             `json:"e"`  // expiry, unix seconds (mirrors the seal envelope; bounds the replay cache entry)
	// Session is the session length the user chose on the authorize form, in
	// seconds (> 0), or SessionUnlimited. 0 means no choice was offered; the
	// token endpoint then applies oauth.max_session_ttl. The length counts from
	// the code exchange, where it becomes Refresh.End.
	Session int64 `json:"d,omitempty"`
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
