package oauth

import (
	"encoding/base64"
	"math"
	"strings"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/tokens"
)

// msgCredsTooLong is the generic form error for credentials that individually
// pass the per-value limit but together would not fit in a sealed token.
const msgCredsTooLong = "The credentials together are too long."

// credsFit reports whether creds can be sealed into every token the flow
// derives from them: the authorization code, the access token and the refresh
// token. The size is measured with the real encoder (seal.EncodedSize) against
// seal.MaxTokenSize, with every other field at its worst case (maximal
// numbers, full-length random ids), so a submit that passes here cannot fail
// later with server_error when the code is sealed or at the token endpoint.
// The refresh token is normally the largest.
func credsFit(up config.Upstream, req authRequest, creds map[string]string) bool {
	id := strings.Repeat("x", base64.RawURLEncoding.EncodedLen(16)) // an id from newID
	payloads := []any{
		tokens.Code{
			ClientID: req.ClientID, RedirectURI: req.RedirectURI, CodeChallenge: req.CodeChallenge,
			Upstream: up.Name, Creds: creds, JTI: id, Exp: math.MaxInt64,
		},
		tokens.Access{Upstream: up.Name, ClientID: req.ClientID, Creds: creds},
		tokens.Refresh{
			Upstream: up.Name, ClientID: req.ClientID, Creds: creds, Family: id,
			Gen: math.MaxInt64, Exp: math.MaxInt64, Start: math.MaxInt64,
		},
	}
	for _, p := range payloads {
		n, err := seal.EncodedSize(p)
		if err != nil || n > seal.MaxTokenSize {
			return false
		}
	}
	return true
}
