package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/audit"
	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/tokens"
)

const (
	maxTokenBody = 16 << 10 // request body cap; real requests are under 1 KiB

	// RFC 7636 §4.1: code_verifier is 43-128 characters of the unreserved set.
	minVerifierLen = 43
	maxVerifierLen = 128

	// maxStartSkew is how far in the future a refresh token's Start may be
	// (clock steps between restarts or hosts) before it is rejected.
	maxStartSkew = 5 * time.Minute

	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"
)

// OAuth error codes of the token endpoint (RFC 6749 §5.2).
const (
	codeInvalidClient        = "invalid_client"
	codeInvalidGrant         = "invalid_grant"
	codeUnsupportedGrantType = "unsupported_grant_type"
)

// tokenParams are the parameters the token endpoint reads. Each may occur at
// most once (RFC 6749 §3.2); a repeat is an invalid_request.
var tokenParams = []string{
	"grant_type", "code", "redirect_uri", "code_verifier", "refresh_token",
	"resource", "client_id", "client_secret",
}

// tokenResponse is the RFC 6749 §5.1 success body. scope is omitted: scopes
// are not used.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type tokenErrorBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// handleToken serves POST /oauth/token (authorization_code and refresh_token
// grants).
//
// CORS: no Access-Control-* headers and no preflight handling. claude.ai
// calls the endpoint from its servers, and the request carries client
// credentials and a PKCE verifier, so there is no reason to let arbitrary web
// pages read responses; browser-only clients are out of scope. This matches
// the authorize endpoint (the registration endpoint is the open one).
//
// Every response, including errors, is "Cache-Control: no-store" (RFC 6749
// §5.1). Descriptions never contain request values, and nothing sensitive is
// logged.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")

	if r.Method != http.MethodPost {
		h.Set("Allow", http.MethodPost)
		s.tokenError(w, http.StatusMethodNotAllowed, codeInvalidRequest, "use POST")
		return
	}
	if s.sealer == nil {
		s.log.Error("token requested without a sealer")
		s.tokenError(w, http.StatusInternalServerError, codeServerError, "internal error")
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/x-www-form-urlencoded" {
		s.tokenError(w, http.StatusBadRequest, codeInvalidRequest, "Content-Type must be application/x-www-form-urlencoded")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenBody)
	// Parsing here (authenticateClient's own call then no-ops) lets an
	// oversized body be told apart from a malformed one.
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			s.tokenError(w, http.StatusRequestEntityTooLarge, codeInvalidRequest, "request body too large")
			return
		}
		s.tokenError(w, http.StatusBadRequest, codeInvalidRequest, "malformed request body")
		return
	}

	clientID, c, err := s.authenticateClient(r)
	if err != nil {
		s.clientAuthFailed(w, err)
		return
	}
	// Only the body counts; query parameters are ignored.
	form := r.PostForm
	for _, k := range tokenParams {
		if len(form[k]) > 1 {
			s.tokenError(w, http.StatusBadRequest, codeInvalidRequest, "duplicate parameter: "+k)
			return
		}
	}

	switch form.Get("grant_type") {
	case grantAuthorizationCode:
		s.exchangeCode(w, r, form, clientID, c)
	case grantRefreshToken:
		s.refresh(w, r, form, clientID)
	case "":
		s.tokenError(w, http.StatusBadRequest, codeInvalidRequest, "grant_type is required")
	default:
		s.tokenError(w, http.StatusBadRequest, codeUnsupportedGrantType, "grant_type must be authorization_code or refresh_token")
	}
}

// clientAuthFailed maps an authenticateClient error to its response.
func (s *Server) clientAuthFailed(w http.ResponseWriter, err error) {
	var ae *clientAuthError
	switch {
	case errors.Is(err, errInvalidClient):
		if errors.As(err, &ae) {
			s.log.Debug("token client authentication failed", "reason", ae.Reason)
			if ae.Basic {
				w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
			}
		}
		s.tokenError(w, http.StatusUnauthorized, codeInvalidClient, "client authentication failed")
	case errors.Is(err, errMalformedRequest):
		s.tokenError(w, http.StatusBadRequest, codeInvalidRequest, "malformed request")
	default:
		s.log.Error("authenticating client", "err", err)
		s.tokenError(w, http.StatusInternalServerError, codeServerError, "internal error")
	}
}

// exchangeCode redeems an authorization code. Single-use is claimed only
// after every other check passed, so a request that fails validation (for
// example a wrong verifier) does not burn the code of the legitimate client.
func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request, form url.Values, clientID string, c client) {
	rawCode, redirectURI, verifier := form.Get("code"), form.Get("redirect_uri"), form.Get("code_verifier")
	switch {
	case rawCode == "":
		s.tokenError(w, http.StatusBadRequest, codeInvalidRequest, "code is required")
		return
	case redirectURI == "":
		s.tokenError(w, http.StatusBadRequest, codeInvalidRequest, "redirect_uri is required")
		return
	case verifier == "":
		s.tokenError(w, http.StatusBadRequest, codeInvalidRequest, "code_verifier is required")
		return
	}

	code, err := seal.OpenAs[tokens.Code](s.sealer, seal.KindCode, rawCode)
	if !s.grantOpened(w, err, "authorization code") {
		return
	}
	// Every mismatch below is the same invalid_grant: the response must not
	// reveal which property of a stolen or foreign code was wrong.
	grant := func(reason string) {
		s.log.Debug("authorization code rejected", "reason", reason)
		s.tokenError(w, http.StatusBadRequest, codeInvalidGrant, "invalid authorization code")
	}
	if code.JTI == "" || code.Exp == 0 {
		// Unreachable for codes we issued; never accept an untrackable one.
		grant("code without jti or expiry")
		return
	}
	if code.ClientID != clientID {
		grant("client mismatch")
		return
	}
	if code.RedirectURI != redirectURI {
		grant("redirect_uri mismatch")
		return
	}
	if !validVerifier(verifier) || !pkceMatches(verifier, code.CodeChallenge) {
		grant("PKCE verification failed")
		return
	}
	// The config may have changed since issue. SIGHUP reloads only TLS, so the
	// config is fixed for the life of a process and this re-validation matters
	// across restarts (a code can outlive a restart that changed the allowlist).
	if !s.redirectAllowed(c, code.RedirectURI) {
		grant("redirect_uri no longer allowed")
		return
	}
	up, ok := s.upstreamByName(code.Upstream)
	if !ok {
		grant("upstream no longer configured")
		return
	}
	if !s.checkResource(w, form, up) {
		return
	}
	// Before the single-use claim: a code minted under another allow-list must
	// not be redeemed into tokens that the proxy would refuse anyway.
	if !up.CredsAllowed(code.Creds) {
		grant("credentials not in allowed_values")
		return
	}

	// Likewise before the claim: a choice the config no longer offers (a restart
	// may have changed it) is refused instead of being turned into a lifetime
	// the operator did not allow.
	if !s.sessionChoiceOffered(code.Session) {
		grant("session choice no longer offered")
		return
	}

	switch err := s.codes.claim(code.JTI, time.Unix(code.Exp, 0), s.now()); {
	case err == nil:
	case errors.Is(err, errReplayed):
		grant("code replayed")
		return
	default:
		s.cacheFull(w, "authorization code", &s.codes.full)
		return
	}
	// A new login chain starts here; it only enters the family cache when
	// its first refresh token is redeemed.
	fam, err := newID()
	if err != nil {
		s.log.Error("generating family id", "err", err)
		s.tokenError(w, http.StatusInternalServerError, codeServerError, "internal error")
		return
	}
	now := s.now()
	var end int64 // 0: no choice, the end is start + max_session_ttl
	switch {
	case code.Session == tokens.SessionUnlimited:
		end = tokens.SessionUnlimited
	case code.Session > 0:
		end = now.Unix() + code.Session
	}
	if s.issueAt(w, now, up.Name, clientID, code.Creds, fam, 0, now.Unix(), end) {
		s.auditToken(r, grantAuthorizationCode, up, clientID, fam, code.Creds, now.Unix(), end)
	}
}

// refresh redeems a refresh token. Refresh tokens are rotated (every success
// returns a new pair with a fresh sliding expiry, capped at the absolute
// session end: the user's choice when the token carries one, else start +
// oauth.max_session_ttl) and single-use with reuse
// detection by family: see familyCache.use. The token is spent before the
// new pair is sealed, so a sealing failure, or a client that loses the
// response, leaves a spent token and requires re-authorization; the
// alternative (claim after issue) would let concurrent requests both succeed.
func (s *Server) refresh(w http.ResponseWriter, r *http.Request, form url.Values, clientID string) {
	raw := form.Get("refresh_token")
	if raw == "" {
		s.tokenError(w, http.StatusBadRequest, codeInvalidRequest, "refresh_token is required")
		return
	}
	rt, err := seal.OpenAs[tokens.Refresh](s.sealer, seal.KindRefresh, raw)
	if !s.grantOpened(w, err, "refresh token") {
		return
	}
	grant := func(reason string) {
		s.log.Debug("refresh token rejected", "reason", reason)
		s.tokenError(w, http.StatusBadRequest, codeInvalidGrant, "invalid refresh token")
	}
	if rt.Family == "" || rt.Exp == 0 || rt.Gen < 0 {
		// Unreachable for tokens we issued; never accept an untrackable one.
		grant("token without family or expiry")
		return
	}
	if rt.ClientID != clientID {
		grant("client mismatch")
		return
	}
	up, ok := s.upstreamByName(rt.Upstream)
	if !ok {
		grant("upstream no longer configured")
		return
	}
	if !s.checkResource(w, form, up) {
		return
	}
	if !up.CredsAllowed(rt.Creds) {
		grant("credentials not in allowed_values")
		return
	}
	// The proxy's re-check confirmed these credentials as rejected (cached
	// verdict only; no upstream call here). Refusing makes the client re-run
	// the authorization flow instead of refreshing into another 401.
	if s.verdicts != nil && s.verdicts.Rejected(up.Name, rt.Creds) {
		grant("credentials rejected by upstream")
		return
	}
	now := s.now()
	start := rt.Start
	if start == 0 {
		// Legacy token issued before Start existed: one-time migration. The
		// chain starts now, so it gets one fresh max_session_ttl window and
		// every later rotation carries a real Start.
		start = now.Unix()
	}
	if start < 0 || start > now.Unix()+int64(maxStartSkew/time.Second) {
		// Start is minted by this server, so a value in the future means a
		// forged or corrupt payload (or a big clock step back). Bounding it
		// by now+skew also keeps the sum below from overflowing.
		grant("session start out of range")
		return
	}
	if rt.End < tokens.SessionUnlimited {
		// Minted by this server: only 0, SessionUnlimited and unix times exist.
		grant("session end out of range")
		return
	}
	// Fail closed on a config that got stricter since issue: only ever lower.
	sessEnd := s.boundSessionEnd(start, rt.End)
	if end, capped := s.sessionCap(start, sessEnd); capped && now.Unix() >= end.Unix() {
		// Absolute lifetime reached; same generic answer as any other dead token.
		grant("session lifetime exceeded")
		return
	}
	// The entry must outlive every token it covers, also when the TTL was
	// lowered since rt was issued (the cache additionally never shortens it).
	newExp := s.cappedExp(now, s.refreshTTL(), start, sessEnd)
	if old := time.Unix(rt.Exp, 0); old.After(newExp) {
		newExp = old
	}
	reuse, err := s.families.use(rt.Family, rt.Gen, newExp, now)
	// Report evictions on every path.
	if n := s.families.takeEvictions(now); n > 0 {
		// Rate limited by the cache; counts only, never ids.
		s.log.Warn("refresh family cache full, evicting least recently used families",
			"evicted_since_last_log", n)
	}
	switch {
	case err == nil:
	case errors.Is(err, errFamilyRevoked):
		if reuse {
			// Never log the token itself.
			// Short non-reversible digests only: for public clients the client_id
			// is the sole client authenticator, and the family id is the key
			// of the reuse-detection state.
			s.log.Warn("refresh token reuse detected; family revoked", append([]any{
				"upstream", up.Name, "client_id", shortID(clientID), "family", shortID(rt.Family),
			}, s.audit.Who(s.clientIP(r), up, rt.Creds)...)...)
		}
		grant("family revoked")
		return
	case errors.Is(err, errRevocationsFull):
		// The revocation set holds only live entries: an unknown family (a new
		// login, or an active chain evicted from the LRU) might be a revoked
		// one with no record, so fail closed.
		s.cacheFull(w, "refresh token", &s.families.full)
		return
	default:
		// Unreachable (use returns only the two errors above); still never
		// issue a token untracked.
		s.cacheFull(w, "refresh token", &s.families.full)
		return
	}
	if s.issueAt(w, now, up.Name, clientID, rt.Creds, rt.Family, rt.Gen+1, start, sessEnd) {
		s.auditToken(r, grantRefreshToken, up, clientID, rt.Family, rt.Creds, start, sessEnd)
	}
}

// cacheFull answers a token request that cannot be tracked because a cache
// is full of live entries: fail closed with 503 (not invalid_grant: the
// client did nothing wrong). There is no Retry-After because no honest
// value exists: entries free up only as tokens expire (minutes for codes,
// days for refresh families).
func (s *Server) cacheFull(w http.ResponseWriter, what string, fc *fullCounter) {
	// At most one line a minute, with the number of refusals since the last.
	if n := fc.take(s.now()); n > 0 {
		s.log.Error("single-use cache full; rejecting requests", "kind", what, "rejected_since_last_log", n)
	}
	s.tokenError(w, http.StatusServiceUnavailable, codeServerError, "temporarily unavailable")
}

// grantOpened reports whether a code or refresh token opened. Otherwise it
// has written the response. what names the token in log lines only.
func (s *Server) grantOpened(w http.ResponseWriter, err error, what string) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, seal.ErrInvalid), errors.Is(err, seal.ErrExpired):
		// Includes the wrong kind (a refresh token used as a code and vice
		// versa), which fails authentication through the AAD.
		s.log.Debug(what+" rejected", "reason", "invalid or expired")
		s.tokenError(w, http.StatusBadRequest, codeInvalidGrant, "invalid or expired "+what)
	case errors.Is(err, seal.ErrPayload):
		// Authentic but undecodable (for example after a deploy changed the
		// payload): a server-side anomaly whose client fix is to re-authorize.
		s.log.Error(what+" payload mismatch", "err", err)
		s.tokenError(w, http.StatusBadRequest, codeInvalidGrant, "invalid "+what)
	default:
		s.log.Error("opening "+what, "err", err)
		s.tokenError(w, http.StatusInternalServerError, codeServerError, "internal error")
	}
	return false
}

// checkResource enforces RFC 8707 on a token request: when resource is
// present it must be the resource URI of up. Absent is fine.
func (s *Server) checkResource(w http.ResponseWriter, form url.Values, up config.Upstream) bool {
	res := form.Get("resource")
	if res == "" || res == up.ResourceURL(s.cfg.PublicURL) {
		return true
	}
	s.tokenError(w, http.StatusBadRequest, codeInvalidTarget, "resource does not match the grant")
	return false
}

// auditToken writes the audit record of an issued token pair. Digests only:
// the client_id and family id are never written raw. The session attribute is
// the user's choice in canonical form, present only for tokens that carry one.
func (s *Server) auditToken(r *http.Request, grant string, up config.Upstream, clientID, family string, creds map[string]string, start, end int64) {
	attrs := []slog.Attr{
		slog.String("grant_type", grant),
		slog.String("client_ip", s.clientIP(r)),
		slog.String("upstream", up.Name),
		slog.String("client_id", shortID(clientID)),
		slog.String("family", shortID(family)),
		s.audit.Creds(up, creds),
	}
	switch {
	case end == tokens.SessionUnlimited:
		attrs = append(attrs, slog.String("session", config.SessionUnlimited))
	case end > 0:
		attrs = append(attrs, slog.String("session", config.SessionChoice{Duration: time.Duration(end-start) * time.Second}.String()))
	}
	s.audit.Record(r.Context(), audit.EventToken, attrs...)
}

// issueAt seals a fresh access and refresh token pair and writes the
// response. It takes an explicit clock reading, so the refresh token's expiry
// equals the one already recorded in the family cache. start is the unix time
// of the login and end the session end (see tokens.Refresh); both expiries are
// capped at the session end (see sessionCap), and the caller guarantees now is
// before that. It reports whether the tokens were issued.
func (s *Server) issueAt(w http.ResponseWriter, now time.Time, upstream, clientID string, creds map[string]string, fam string, gen, start, end int64) bool {
	accessTTL, refreshTTL := s.cfg.OAuth.AccessTokenTTL, s.refreshTTL()
	if accessTTL <= 0 {
		accessTTL = config.DefaultAccessTokenTTL
	}
	accessExp := s.cappedExp(now, accessTTL, start, end)
	access, err := s.sealer.Seal(seal.KindAccess, tokens.Access{Upstream: upstream, ClientID: clientID, Creds: creds}, accessExp)
	var refresh string
	if err == nil {
		refreshExp := s.cappedExp(now, refreshTTL, start, end)
		refresh, err = s.sealer.Seal(seal.KindRefresh, tokens.Refresh{
			Upstream: upstream, ClientID: clientID, Creds: creds, Family: fam, Gen: gen, Exp: refreshExp.Unix(), Start: start, End: end,
		}, refreshExp)
	}
	if err != nil {
		// Never log the payload: it carries credentials.
		s.log.Error("sealing tokens", "err", err)
		s.tokenError(w, http.StatusInternalServerError, codeServerError, "internal error")
		return false
	}
	s.log.Debug("tokens issued", "upstream", upstream)
	s.writeTokenJSON(w, http.StatusOK, tokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		// Whole-second difference, like the gate in refresh: at least 1 for any
		// request that passed it, and the TTL itself when uncapped.
		ExpiresIn:    accessExp.Unix() - now.Unix(),
		RefreshToken: refresh,
	})
	return true
}

// cappedExp returns now+ttl, but never later than the end of the session that
// began at start (unix seconds) and carries the choice end (see sessionCap).
// An unlimited session has no end: only ttl applies.
func (s *Server) cappedExp(now time.Time, ttl time.Duration, start, end int64) time.Time {
	exp := now.Add(ttl)
	if limit, capped := s.sessionCap(start, end); capped && limit.Before(exp) {
		return limit
	}
	return exp
}

// sessionCap returns the absolute end of a session and whether it has one. end
// is tokens.Refresh.End: a unix time, tokens.SessionUnlimited (no end), or 0
// for a token without a choice, whose session ends at start plus
// oauth.max_session_ttl. Zero is never read as unlimited.
func (s *Server) sessionCap(start, end int64) (time.Time, bool) {
	switch {
	case end == tokens.SessionUnlimited:
		return time.Time{}, false
	case end > 0:
		return time.Unix(end, 0), true
	}
	return time.Unix(start+int64(s.maxSessionTTL()/time.Second), 0), true
}

// boundSessionEnd clamps the session end carried by a refresh token to what the
// current config allows, so that lowering or removing choices shortens
// existing logins at their next refresh. It only ever lowers: it never
// extends a session and never maps a choice back to 0 (start +
// max_session_ttl could be later). 0 (no choice) stays 0. With an unlimited
// choice configured the end is kept; otherwise the limit is start plus the
// longest finite choice, or max_session_ttl when no choices are configured.
func (s *Server) boundSessionEnd(start, end int64) int64 {
	if end == 0 {
		return 0
	}
	sessions := s.cfg.OAuth.Sessions
	longest := s.maxSessionTTL()
	if len(sessions) > 0 {
		longest = 0
		for _, c := range sessions {
			if c.Unlimited {
				return end
			}
			longest = max(longest, c.Duration)
		}
	}
	limit := start + int64(longest/time.Second)
	if end == tokens.SessionUnlimited || end > limit {
		return limit
	}
	return end
}

// sessionChoiceOffered reports whether v, a tokens.Code.Session, is acceptable
// now: 0 (no choice) always, otherwise only a value the config offers.
func (s *Server) sessionChoiceOffered(v int64) bool {
	if v == 0 {
		return true
	}
	for _, c := range s.cfg.OAuth.Sessions {
		if sessionClaim(c) == v {
			return true
		}
	}
	return false
}

// sessionClaim is the tokens.Code.Session value of a choice.
func sessionClaim(c config.SessionChoice) int64 {
	if c.Unlimited {
		return tokens.SessionUnlimited
	}
	return int64(c.Duration / time.Second)
}

func (s *Server) maxSessionTTL() time.Duration {
	if ttl := s.cfg.OAuth.MaxSessionTTL; ttl > 0 {
		return ttl
	}
	return config.DefaultMaxSessionTTL
}

func (s *Server) refreshTTL() time.Duration {
	if ttl := s.cfg.OAuth.RefreshTokenTTL; ttl > 0 {
		return ttl
	}
	return config.DefaultRefreshTokenTTL
}

func (s *Server) tokenError(w http.ResponseWriter, status int, code, desc string) {
	s.writeTokenJSON(w, status, tokenErrorBody{Error: code, Description: desc})
}

func (s *Server) writeTokenJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil { // unreachable: plain string structs
		s.log.Error("encoding token response", "err", err)
		status, body = http.StatusInternalServerError, []byte(`{"error":"server_error"}`)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// validVerifier checks the RFC 7636 §4.1 shape of a code_verifier.
func validVerifier(v string) bool {
	if len(v) < minVerifierLen || len(v) > maxVerifierLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		b := v[i]
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') &&
			b != '-' && b != '.' && b != '_' && b != '~' {
			return false
		}
	}
	return true
}

// pkceMatches reports whether BASE64URL(SHA256(verifier)) equals challenge,
// in constant time.
func pkceMatches(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

// shortID returns the first 8 hex characters of the SHA-256 of id: enough to
// correlate log lines, useless for recovering or replaying the identifier.
func shortID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:4])
}
