package oauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/zigmund/tn-mcp-proxy/internal/seal"
)

// Token endpoint authentication methods (RFC 7591 / RFC 8414).
const (
	authNone              = "none"
	authClientSecretPost  = "client_secret_post"
	authClientSecretBasic = "client_secret_basic"
)

// purposeClientSecret domain-separates client secret MACs from other MACs.
const purposeClientSecret = "client_secret"

// client is the record sealed into a DCR client_id (seal.KindClient, no expiry).
// Keys are short because the whole record travels in every authorize request.
type client struct {
	RedirectURIs []string `json:"r"`
	Name         string   `json:"n,omitempty"`
	AuthMethod   string   `json:"m"`
	IssuedAt     int64    `json:"i"`
}

var (
	// errInvalidClient marks an unknown, tampered or unauthenticated client.
	// Callers map it (errors.Is) to the invalid_client OAuth error.
	errInvalidClient = errors.New("invalid client")
	// errMalformedRequest marks an unparsable token request body; callers map
	// it to invalid_request.
	errMalformedRequest = errors.New("malformed request")
)

// clientAuthError is returned by authenticateClient for every client
// authentication failure. It matches errInvalidClient via errors.Is. The
// token endpoint answers it with 401 invalid_client, adding
// "WWW-Authenticate: Basic" when Basic is true (RFC 6749 §5.2). Reason is for
// logs only and must not be sent to the client.
type clientAuthError struct {
	Basic  bool
	Reason string
}

func (e *clientAuthError) Error() string        { return "client authentication failed: " + e.Reason }
func (e *clientAuthError) Is(target error) bool { return target == errInvalidClient }

// openClient opens a client_id. Any invalid, tampered, foreign-kind or
// foreign-key id yields errInvalidClient. Any other error (for example
// seal.ErrPayload) is a server-side fault and must surface as a 500.
func (s *Server) openClient(clientID string) (client, error) {
	c, err := seal.OpenAs[client](s.sealer, seal.KindClient, clientID)
	switch {
	case err == nil:
		return c, nil
	case errors.Is(err, seal.ErrInvalid), errors.Is(err, seal.ErrExpired):
		return client{}, errInvalidClient
	default:
		return client{}, fmt.Errorf("opening client id: %w", err)
	}
}

// allowsRedirect reports whether uri exactly matches one of the redirect URIs
// registered for c. It only checks the record; the authorize endpoint must use
// Server.redirectAllowed, which also honours the current config.
func (c client) allowsRedirect(uri string) bool {
	return uri != "" && slices.Contains(c.RedirectURIs, uri)
}

// redirectAllowed is the check the authorize endpoint must use: uri has to be
// registered for c AND still be in cfg.OAuth.AllowedRedirectURIs, so removing
// a URI from the config revokes it for already-registered clients (their
// stateless ids cannot be revoked otherwise).
func (s *Server) redirectAllowed(c client, uri string) bool {
	return c.allowsRedirect(uri) && slices.Contains(s.cfg.OAuth.AllowedRedirectURIs, uri)
}

// clientSecret derives the secret for a client_id: a MAC over the id under the
// primary key. Rotating the keys changes it (and invalidates the ids anyway).
func (s *Server) clientSecret(clientID string) string {
	return base64.RawURLEncoding.EncodeToString(s.sealer.MAC(purposeClientSecret, []byte(clientID)))
}

// authenticateClient authenticates the client of a token request.
//
// It calls r.ParseForm itself (it is idempotent, so the token
// endpoint may call it too); query parameters are deliberately ignored for
// credentials. The caller should wrap r.Body in http.MaxBytesReader first.
//
// The credential location detects the method: Basic header ->
// client_secret_basic, non-empty client_secret form field ->
// client_secret_post, only client_id -> none. A "none" client must use none; a
// secret client must present its secret but may do so via Basic or the form.
// Supplying both is rejected. Secrets are verified in constant time with
// Sealer.VerifyMAC (so ids sealed under a still-configured older key keep
// working).
//
// Errors: *clientAuthError (matches errInvalidClient) for any authentication
// failure; errMalformedRequest when ParseForm fails (a malformed URL query,
// which ParseForm also parses, or an invalid or oversized body); other errors
// are server faults.
func (s *Server) authenticateClient(r *http.Request) (clientID string, c client, err error) {
	if err := r.ParseForm(); err != nil {
		return "", client{}, fmt.Errorf("%w: %v", errMalformedRequest, err)
	}
	formID := r.PostForm.Get("client_id")
	formSecret := r.PostForm.Get("client_secret")
	hasFormSecret := formSecret != "" // an empty client_secret counts as absent

	var method, secret string
	basic := false
	switch auth := r.Header.Get("Authorization"); {
	case auth != "":
		basic = true
		if hasFormSecret {
			return "", client{}, &clientAuthError{Basic: true, Reason: "multiple authentication methods"}
		}
		id, sec, ok := parseBasic(auth)
		if !ok {
			return "", client{}, &clientAuthError{Basic: true, Reason: "malformed Basic credentials"}
		}
		if formID != "" && formID != id {
			return "", client{}, &clientAuthError{Basic: true, Reason: "client_id mismatch"}
		}
		clientID, secret, method = id, sec, authClientSecretBasic
	case hasFormSecret:
		clientID, secret, method = formID, formSecret, authClientSecretPost
	default:
		clientID, method = formID, authNone
	}
	fail := func(reason string) (string, client, error) {
		return "", client{}, &clientAuthError{Basic: basic, Reason: reason}
	}
	if clientID == "" {
		return fail("missing client_id")
	}
	c, err = s.openClient(clientID)
	if err != nil {
		if errors.Is(err, errInvalidClient) {
			return fail("unknown client_id")
		}
		return "", client{}, err
	}
	// "none" is strict. Secret clients may present the secret in either
	// location: some clients do not honour the registered method.
	if (c.AuthMethod == authNone) != (method == authNone) {
		s.log.Debug("client auth method mismatch", "registered", c.AuthMethod, "used", method)
		return fail("method " + method + " does not match registered " + c.AuthMethod)
	}
	if c.AuthMethod != method {
		s.log.Debug("client authenticated with other secret method", "registered", c.AuthMethod, "used", method)
	}
	if method != authNone {
		got, derr := base64.RawURLEncoding.Strict().DecodeString(secret)
		if derr != nil || !s.sealer.VerifyMAC(purposeClientSecret, []byte(clientID), got) {
			return fail("bad client_secret")
		}
	}
	return clientID, c, nil
}

// parseBasic decodes an "Authorization: Basic" value. Per RFC 6749 §2.3.1 the
// id and secret are form-urlencoded before being joined with ':'.
func parseBasic(header string) (id, secret string, ok bool) {
	scheme, rest, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
	if err != nil {
		return "", "", false
	}
	encID, encSecret, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	id, err1 := url.QueryUnescape(encID)
	secret, err2 := url.QueryUnescape(encSecret)
	if err1 != nil || err2 != nil {
		return "", "", false
	}
	return id, secret, true
}
