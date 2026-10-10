package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/credcheck"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/tokens"
)

const (
	maxAuthorizeBody = 32 << 10                     // POST form size cap
	maxStateLen      = 1024                         // bytes; state is echoed verbatim
	maxCredLen       = config.MaxCredentialValueLen // bytes per credential value
	pkceChallengeLen = 43                           // base64url(SHA-256), unpadded
	// formTTL bounds how long a rendered form may sit before it is submitted.
	// It is independent of oauth.code_ttl, which only starts at submission.
	formTTL = 15 * time.Minute
	// retryAfterUnavailable is the Retry-After (seconds) of a 503 when the
	// upstream could not verify the credentials.
	retryAfterUnavailable = "30"
	// requestField is the hidden form field holding the sealed request.
	requestField = "request"
)

// OAuth error codes (RFC 6749 §4.1.2.1, RFC 8707).
const (
	codeInvalidRequest          = "invalid_request"
	codeUnsupportedResponseType = "unsupported_response_type"
	codeInvalidTarget           = "invalid_target"
	codeServerError             = "server_error"
)

var (
	//go:embed templates/style.css
	styleCSS string
	//go:embed templates/authorize.html
	authorizeHTML string
	//go:embed templates/error.html
	errorHTML string

	authorizeTmpl = template.Must(template.New("authorize").Parse(authorizeHTML))
	errorTmpl     = template.Must(template.New("error").Parse(errorHTML))

	// styleSrc is the CSP source for the one inline stylesheet, so the policy
	// needs neither 'unsafe-inline' nor a per-request nonce.
	styleSrc = func() string {
		sum := sha256.Sum256([]byte(styleCSS))
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}()
)

// authRequest is the validated authorization request. It is sealed
// (seal.KindAuthRequest) into the form's hidden field, which binds the GET
// parameters to the POST: nothing the user's browser sends back can alter it.
type authRequest struct {
	ClientID      string `json:"c"`
	RedirectURI   string `json:"r"`
	CodeChallenge string `json:"ch"`
	State         string `json:"s,omitempty"`
	Upstream      string `json:"u"`
}

// authFailure is a failed authorize request. When RedirectURI is empty it is
// shown on an error page (the redirect target is not established, so
// redirecting would make this an open redirector); otherwise the user agent
// is redirected back to the client with the error.
type authFailure struct {
	Status      int // error page status
	Code        string
	Description string
	RedirectURI string
	State       string
}

func pageFailure(status int, msg string) *authFailure {
	return &authFailure{Status: status, Description: msg}
}

// redirectFailure is only for requests whose client and redirect_uri have
// been verified.
func redirectFailure(uri, state, code, desc string) *authFailure {
	return &authFailure{Code: code, Description: desc, RedirectURI: uri, State: state}
}

type formField struct {
	ID       string
	Label    string
	Secret   bool
	Optional bool
	Value    string // never set for secret fields
}

type formPage struct {
	CSS           template.CSS
	Action        string
	UpstreamTitle string
	ClientName    string
	RedirectHost  string
	Request       string
	Fields        []formField
	Error         string
}

// handleAuthorize serves GET (render the credentials form) and POST (issue a
// code). Method filtering is done by the mux patterns. No CORS headers are
// set: this endpoint is only ever navigated to, never fetched cross-origin.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if s.sealer == nil {
		s.log.Error("authorization requested without a sealer")
		s.writeErrorPage(w, http.StatusInternalServerError, "Internal server error.")
		return
	}
	var fail *authFailure
	if r.Method == http.MethodPost {
		fail = s.authorizeSubmit(w, r)
	} else {
		fail = s.authorizeForm(w, r)
	}
	if fail != nil {
		s.writeFailure(w, r, fail)
	}
}

// authorizeForm validates the request and renders the form.
//
// Order matters: errors found before the client and its redirect_uri are
// verified go to an error page; only afterwards may errors be redirected.
func (s *Server) authorizeForm(w http.ResponseWriter, r *http.Request) *authFailure {
	q := r.URL.Query()
	clientID, ok := single(q, "client_id")
	if !ok || clientID == "" {
		return pageFailure(http.StatusBadRequest, "The request is missing a valid client_id.")
	}
	c, fail := s.lookupClient(clientID)
	if fail != nil {
		return fail
	}
	redirectURI, ok := single(q, "redirect_uri")
	if !ok || !s.redirectAllowed(c, redirectURI) {
		return pageFailure(http.StatusBadRequest, "The redirect_uri is missing or not allowed for this application.")
	}

	// From here on the client and redirect target are trusted.
	state, stateOK := single(q, "state")
	rfail := func(code, desc string) *authFailure { return redirectFailure(redirectURI, state, code, desc) }
	if !stateOK || len(state) > maxStateLen {
		state = "" // never echo a state we refuse to accept
		return rfail(codeInvalidRequest, "invalid state parameter")
	}
	if v, ok := single(q, "response_type"); !ok || v != "code" {
		return rfail(codeUnsupportedResponseType, "response_type must be code")
	}
	challenge, ok1 := single(q, "code_challenge")
	method, ok2 := single(q, "code_challenge_method")
	if !ok1 || !ok2 || challenge == "" {
		return rfail(codeInvalidRequest, "code_challenge is required (PKCE S256)")
	}
	if method != "S256" {
		return rfail(codeInvalidRequest, "code_challenge_method must be S256")
	}
	if !validChallenge(challenge) {
		return rfail(codeInvalidRequest, "malformed code_challenge")
	}
	resource := q["resource"]
	if len(resource) > 1 {
		return rfail(codeInvalidTarget, "only one resource is supported")
	}
	var res string
	if len(resource) == 1 {
		res = resource[0]
	}
	up, ok := s.resolveUpstream(res)
	if !ok {
		return rfail(codeInvalidTarget, "unknown resource")
	}

	req := authRequest{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: challenge,
		State:         state,
		Upstream:      up.Name,
	}
	sealed, err := s.sealer.Seal(seal.KindAuthRequest, req, s.now().Add(formTTL))
	if err != nil {
		s.log.Error("sealing authorize request", "err", err)
		return pageFailure(http.StatusInternalServerError, "Internal server error.")
	}
	s.writeForm(w, http.StatusOK, c, up, req, sealed, nil, "")
	return nil
}

// authorizeSubmit handles the form POST. It trusts nothing but the sealed
// request: the client and redirect are re-validated against the current
// config, and the credentials are the only values taken from the form.
//
// CSRF: the endpoint relies on no ambient authority (no cookies or session),
// and the credentials come from the form itself, so a forged cross-site POST
// can only submit credentials the attacker already has, and the resulting
// code goes to an allowlisted redirect URI whose client checks its own state.
// With validate configured the form is also a credential-validity oracle (one
// authenticated upstream call per submit); the per-IP authorize rate limit
// bounds it, and a code is only ever issued for credentials the upstream accepts.
// The sealed field binds all request parameters (and expires), so the POST
// cannot be steered elsewhere. As defence in depth a browser-declared
// cross-site POST (Sec-Fetch-Site) is refused.
func (s *Server) authorizeSubmit(w http.ResponseWriter, r *http.Request) *authFailure {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return pageFailure(http.StatusForbidden, "Cross-site form submission is not allowed.")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthorizeBody)
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return pageFailure(http.StatusRequestEntityTooLarge, "The submitted form is too large.")
		}
		return pageFailure(http.StatusBadRequest, "The submitted form is malformed.")
	}
	sealed := r.PostForm.Get(requestField)
	req, err := seal.OpenAs[authRequest](s.sealer, seal.KindAuthRequest, sealed)
	switch {
	case err == nil:
	case errors.Is(err, seal.ErrInvalid), errors.Is(err, seal.ErrExpired):
		return pageFailure(http.StatusBadRequest, "This authorization request is invalid or has expired.")
	default:
		s.log.Error("opening authorize request", "err", err)
		return pageFailure(http.StatusInternalServerError, "Internal server error.")
	}

	c, fail := s.lookupClient(req.ClientID)
	if fail != nil {
		return fail
	}
	if !s.redirectAllowed(c, req.RedirectURI) {
		return pageFailure(http.StatusBadRequest, "The redirect_uri is no longer allowed for this application.")
	}
	up, ok := s.upstreamByName(req.Upstream)
	if !ok || !validChallenge(req.CodeChallenge) {
		return redirectFailure(req.RedirectURI, req.State, codeInvalidTarget, "unknown resource")
	}

	creds, values, msg := collectCreds(up, r.PostForm)
	if msg != "" {
		s.writeForm(w, http.StatusBadRequest, c, up, req, sealed, values, msg)
		return nil
	}

	// Before any upstream call and before sealing: input too long for a token.
	if !credsFit(up, req, creds) {
		s.writeForm(w, http.StatusBadRequest, c, up, req, sealed, values, msgCredsTooLong)
		return nil
	}

	// Allow-list: the same generic message as a rejected credential, so the
	// form does not reveal that one exists. No upstream call for foreign keys.
	if !up.CredsAllowed(creds) {
		s.log.Info("authorize refused: credentials not in allowed_values", "upstream", up.Name)
		s.writeForm(w, http.StatusBadRequest, c, up, req, sealed, values, s.rejectedMsg(up))
		return nil
	}

	if msg, status := s.validateCreds(r.Context(), up, creds); msg != "" {
		if status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", retryAfterUnavailable)
		}
		s.writeForm(w, status, c, up, req, sealed, values, msg)
		return nil
	}

	jti, err := newID()
	if err != nil {
		s.log.Error("generating code id", "err", err)
		return redirectFailure(req.RedirectURI, req.State, codeServerError, "internal error")
	}
	ttl := s.cfg.OAuth.CodeTTL
	if ttl <= 0 {
		ttl = config.DefaultCodeTTL
	}
	exp := s.now().Add(ttl)
	code, err := s.sealer.Seal(seal.KindCode, tokens.Code{
		ClientID:      req.ClientID,
		RedirectURI:   req.RedirectURI,
		CodeChallenge: req.CodeChallenge,
		Upstream:      up.Name,
		Creds:         creds,
		JTI:           jti,
		Exp:           exp.Unix(),
	}, exp)
	if err != nil {
		// Never log the payload: it carries credentials.
		s.log.Error("sealing authorization code", "err", err)
		return redirectFailure(req.RedirectURI, req.State, codeServerError, "internal error")
	}
	s.log.Debug("authorization code issued", "upstream", up.Name, "client_name", c.Name)
	s.redirect(w, r, req.RedirectURI, req.State, url.Values{"code": {code}})
	return nil
}

// validateCreds runs the upstream's credential check, if configured. A
// non-empty msg means no code may be issued: the form is re-rendered with that
// message and status (400 rejected, 503 no verdict, so the check fails closed).
func (s *Server) validateCreds(ctx context.Context, up config.Upstream, creds map[string]string) (msg string, status int) {
	if up.Validate == nil {
		return "", 0
	}
	err := s.checker.Check(ctx, up, creds)
	if err == nil {
		return "", 0
	}
	logCheck(s.log, up.Name, err)
	title := upstreamTitle(up)
	if errors.Is(err, credcheck.ErrRejected) {
		return s.rejectedMsg(up), http.StatusBadRequest
	}
	return "Could not verify the credentials with " + title + " right now. Try again later.", http.StatusServiceUnavailable
}

func upstreamTitle(up config.Upstream) string {
	if up.Title == "" {
		return up.Name
	}
	return up.Title
}

// rejectedMsg is the form error for credentials that must not get a token.
func (s *Server) rejectedMsg(up config.Upstream) string {
	return upstreamTitle(up) + " rejected these credentials. Check them and try again."
}

// lookupClient opens a client_id, mapping failures to page failures.
func (s *Server) lookupClient(clientID string) (client, *authFailure) {
	c, err := s.openClient(clientID)
	switch {
	case err == nil:
		return c, nil
	case errors.Is(err, errInvalidClient):
		return client{}, pageFailure(http.StatusBadRequest, "The client_id is not recognized. Register the application again.")
	default:
		s.log.Error("opening client id", "err", err)
		return client{}, pageFailure(http.StatusInternalServerError, "Internal server error.")
	}
}

// resolveUpstream maps an RFC 8707 resource indicator to an upstream. An empty
// resource selects the only upstream, and is ambiguous otherwise.
func (s *Server) resolveUpstream(resource string) (config.Upstream, bool) {
	ups := s.cfg.Upstreams
	if resource == "" {
		if len(ups) == 1 {
			return ups[0], true
		}
		return config.Upstream{}, false
	}
	for _, u := range ups {
		if u.ResourceURL(s.cfg.PublicURL) == resource {
			return u, true
		}
	}
	return config.Upstream{}, false
}

func (s *Server) upstreamByName(name string) (config.Upstream, bool) {
	for _, u := range s.cfg.Upstreams {
		if u.Name == name {
			return u, true
		}
	}
	return config.Upstream{}, false
}

// collectCreds reads the credential fields of up from form. It returns the
// header->value map, the non-secret values for re-rendering, and a user-facing
// message when validation fails (the message never contains a value).
func collectCreds(up config.Upstream, form url.Values) (creds, values map[string]string, msg string) {
	creds = make(map[string]string, len(up.Credentials))
	values = make(map[string]string, len(up.Credentials))
	for i, cr := range up.Credentials {
		id := credFieldID(i)
		v := strings.TrimSpace(form.Get(id))
		if !cr.Secret {
			values[id] = v
		}
		switch {
		case v == "" && cr.Optional:
			continue
		case v == "":
			msg = credLabel(cr) + " is required."
		case len(v) > maxCredLen:
			msg = credLabel(cr) + " is too long."
		case !validCredValue(v):
			msg = credLabel(cr) + " contains invalid characters."
		}
		if msg != "" {
			return nil, values, msg
		}
		creds[http.CanonicalHeaderKey(cr.Header)] = v
	}
	return creds, values, ""
}

// validCredValue rejects control characters (header injection) and invalid UTF-8.
func validCredValue(v string) bool {
	if !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func credFieldID(i int) string { return "cred_" + strconv.Itoa(i) }

func credLabel(cr config.Credential) string {
	if cr.Label != "" {
		return cr.Label
	}
	return cr.Header
}

// writeForm renders the credentials form with the security headers.
func (s *Server) writeForm(w http.ResponseWriter, status int, c client, up config.Upstream, req authRequest, sealed string, values map[string]string, msg string) {
	fields := make([]formField, len(up.Credentials))
	for i, cr := range up.Credentials {
		id := credFieldID(i)
		fields[i] = formField{ID: id, Label: credLabel(cr), Secret: cr.Secret, Optional: cr.Optional, Value: values[id]}
	}
	title := up.Title
	if title == "" {
		title = up.Name
	}
	host, formAction := "", "'self'"
	if u, err := url.Parse(req.RedirectURI); err == nil {
		host = u.Host
		// form-action covers the redirect after submission too: Chrome
		// enforces it on the redirect to the redirect_uri, so that origin
		// must be listed.
		if u.Scheme != "" && u.Host != "" {
			formAction += " " + u.Scheme + "://" + u.Host
		}
	}
	s.renderPage(w, status, formAction, authorizeTmpl, formPage{
		CSS:           template.CSS(styleCSS),
		Action:        PathAuthorize,
		UpstreamTitle: title,
		ClientName:    c.Name,
		RedirectHost:  host,
		Request:       sealed,
		Fields:        fields,
		Error:         msg,
	})
}

// renderPage executes tmpl into a buffer first, so a template error yields a
// clean 500 instead of a truncated page with a success status.
func (s *Server) renderPage(w http.ResponseWriter, status int, formAction string, tmpl *template.Template, data any) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		s.log.Error("rendering authorize page", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	setPageHeaders(w, formAction)
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func setPageHeaders(w http.ResponseWriter, formAction string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src "+styleSrc+
		"; form-action "+formAction+"; frame-ancestors 'none'; base-uri 'none'")
}

func (s *Server) writeErrorPage(w http.ResponseWriter, status int, msg string) {
	s.renderPage(w, status, "'none'", errorTmpl, struct {
		CSS     template.CSS
		Message string
	}{template.CSS(styleCSS), msg})
}

// writeFailure renders an error page or redirects the error to the client.
func (s *Server) writeFailure(w http.ResponseWriter, r *http.Request, f *authFailure) {
	if f.RedirectURI == "" {
		if f.Status >= 500 {
			s.log.Warn("authorize request failed", "status", f.Status)
		} else {
			s.log.Debug("authorize request rejected", "reason", f.Description)
		}
		s.writeErrorPage(w, f.Status, f.Description)
		return
	}
	s.log.Debug("authorize request rejected", "error", f.Code, "reason", f.Description)
	s.redirect(w, r, f.RedirectURI, f.State, url.Values{"error": {f.Code}, "error_description": {f.Description}})
}

// redirect sends the user agent to the (already verified) redirect URI with
// params, state (when present) and the issuer (RFC 9207).
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, redirectURI, state string, params url.Values) {
	u, err := url.Parse(redirectURI)
	if err != nil { // unreachable: it is allowlisted config
		s.writeErrorPage(w, http.StatusInternalServerError, "Internal server error.")
		return
	}
	q := u.Query()
	// Stale values in the registered URI's query must not survive.
	for _, k := range []string{"code", "error", "error_description", "state", "iss"} {
		q.Del(k)
	}
	for k, v := range params {
		q[k] = v
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", s.cfg.PublicURL)
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// 303 after a POST so the browser never re-sends the credentials.
	status := http.StatusFound
	if r.Method == http.MethodPost {
		status = http.StatusSeeOther
	}
	http.Redirect(w, r, u.String(), status)
}

// single returns the only value of key; ok is false if it occurs more than
// once (RFC 6749 §3.1: parameters must not be repeated).
func single(q url.Values, key string) (string, bool) {
	v := q[key]
	switch len(v) {
	case 0:
		return "", true
	case 1:
		return v[0], true
	}
	return "", false
}

// validChallenge reports whether c is a base64url SHA-256 digest, the only
// shape an S256 code_challenge can have.
func validChallenge(c string) bool {
	if len(c) != pkceChallengeLen {
		return false
	}
	return strings.IndexFunc(c, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_'
	}) < 0
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("reading random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
