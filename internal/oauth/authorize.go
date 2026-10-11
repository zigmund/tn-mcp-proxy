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
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zigmund/tn-mcp-proxy/internal/audit"
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
	// acceptTermsField is the terms-of-use checkbox; acceptTermsValue is what
	// the form's checkbox sends when ticked.
	acceptTermsField = "accept_terms"
	acceptTermsValue = "on"
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
	Description string  // English, for logs and redirect error_description
	Message     message // what the error page shows, in the page's language
	RedirectURI string
	State       string
}

// pageFailure is an error page showing the catalog message id.
func pageFailure(status int, id string, args ...any) *authFailure {
	m := uiMsg(id, args...)
	return &authFailure{Status: status, Message: m, Description: newLocale(defaultLang).Msg(m)}
}

// redirectFailure is only for requests whose client and redirect_uri have
// been verified.
func redirectFailure(uri, state, code, desc string) *authFailure {
	return &authFailure{Code: code, Description: desc, RedirectURI: uri, State: state}
}

type formField struct {
	ID       string
	Label    string
	Lang     string // language of Label when it differs from the page's, else empty
	Secret   bool
	Optional bool
	Value    string // never set for secret fields
}

// auditNotice is the "What this server logs" panel; nil when audit is off.
type auditNotice struct {
	Logged      []slot            // one sentence per audited credential
	NeverLogged []config.LangText // labels of the credentials the server never logs
}

// termsView is the terms block of the form. A Lang field is set only when that
// part is not in the page language, so the template can mark it.
type termsView struct {
	Paragraphs []string
	TextLang   string
	URL        string
	URLLang    string
}

// formPage is the data of templates/authorize.html. Every user-visible string
// not from the operator's config or the request is a catalog message resolved
// through L, never built into the data.
type formPage struct {
	CSS           template.CSS
	L             locale
	Action        string
	UpstreamTitle string
	ClientName    string
	RedirectHost  string
	Request       string
	Fields        []formField
	Error         message // zero when there is no banner
	Audit         *auditNotice
	Notice        []string // operator notice paragraphs, plain text
	NoticeLang    string   // language of Notice when it differs from the page's
	LangLinks     []langLink
	Terms         *termsView // nil when no terms are configured
	TermsInvalid  bool       // the terms checkbox was not ticked
	Contact       string     // visible text of the operator contact
	ContactHref   string     // mailto: or https: link target
}

// errorPage is the data of templates/error.html.
type errorPage struct {
	CSS     template.CSS
	L       locale
	Message message
}

// handleAuthorize serves GET (render the credentials form) and POST (issue a
// code). Method filtering is done by the mux patterns. No CORS headers are
// set: this endpoint is only ever navigated to, never fetched cross-origin.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	l := newLocale(negotiateLang(r, ""))
	if s.sealer == nil {
		s.log.Error("authorization requested without a sealer")
		s.writeErrorPage(w, http.StatusInternalServerError, l, uiMsg(msgInternal))
		return
	}
	var fail *authFailure
	if r.Method == http.MethodPost {
		fail = s.authorizeSubmit(w, r, &l)
	} else {
		fail = s.authorizeForm(w, r, l)
	}
	if fail != nil {
		s.writeFailure(w, r, l, fail)
	}
}

// authorizeForm validates the request and renders the form.
//
// Order matters: errors found before the client and its redirect_uri are
// verified go to an error page; only afterwards may errors be redirected.
func (s *Server) authorizeForm(w http.ResponseWriter, r *http.Request, l locale) *authFailure {
	q := r.URL.Query()
	clientID, ok := single(q, "client_id")
	if !ok || clientID == "" {
		return pageFailure(http.StatusBadRequest, msgClientIDMissing)
	}
	c, fail := s.lookupClient(clientID)
	if fail != nil {
		return fail
	}
	redirectURI, ok := single(q, "redirect_uri")
	if !ok || !s.redirectAllowed(c, redirectURI) {
		return pageFailure(http.StatusBadRequest, msgRedirectBad)
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
		return pageFailure(http.StatusInternalServerError, msgInternal)
	}
	s.writeForm(w, http.StatusOK, l, formArgs{Client: c, Up: up, Req: req, Sealed: sealed})
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
//
// l is the page language chosen from the URL and Accept-Language; the form's
// hidden lang field refines it once the body is parsed. It is display only.
func (s *Server) authorizeSubmit(w http.ResponseWriter, r *http.Request, l *locale) *authFailure {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return pageFailure(http.StatusForbidden, msgCrossSite)
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthorizeBody)
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return pageFailure(http.StatusRequestEntityTooLarge, msgFormTooLarge)
		}
		return pageFailure(http.StatusBadRequest, msgFormMalformed)
	}
	*l = newLocale(negotiateLang(r, r.PostForm.Get(langParam)))
	sealed := r.PostForm.Get(requestField)
	req, err := seal.OpenAs[authRequest](s.sealer, seal.KindAuthRequest, sealed)
	switch {
	case err == nil:
	case errors.Is(err, seal.ErrInvalid), errors.Is(err, seal.ErrExpired):
		return pageFailure(http.StatusBadRequest, msgRequestExpired)
	default:
		s.log.Error("opening authorize request", "err", err)
		return pageFailure(http.StatusInternalServerError, msgInternal)
	}

	c, fail := s.lookupClient(req.ClientID)
	if fail != nil {
		return fail
	}
	if !s.redirectAllowed(c, req.RedirectURI) {
		return pageFailure(http.StatusBadRequest, msgRedirectGone)
	}
	up, ok := s.upstreamByName(req.Upstream)
	if !ok || !validChallenge(req.CodeChallenge) {
		return redirectFailure(req.RedirectURI, req.State, codeInvalidTarget, "unknown resource")
	}

	creds, values, msg := collectCreds(up, r.PostForm, l.Lang())
	form := func(status int, msg message) {
		s.writeForm(w, status, *l, formArgs{Client: c, Up: up, Req: req, Sealed: sealed, Values: values, Msg: msg,
			TermsInvalid: msg.ID == msgTermsRequired})
	}

	// Terms come first: a missing acceptance costs nothing (no sizing, no
	// allow-list lookup, no upstream call, no global-ceiling charge), and the
	// answer does not depend on the credentials.
	if s.cfg.OAuth.Page.TermsEnabled() && r.PostForm.Get(acceptTermsField) != acceptTermsValue {
		form(http.StatusBadRequest, uiMsg(msgTermsRequired))
		return nil
	}
	if msg.ID != "" {
		form(http.StatusBadRequest, msg)
		return nil
	}

	// Before any upstream call and before sealing: input too long for a token.
	if !credsFit(up, req, creds) {
		form(http.StatusBadRequest, uiMsg(msgCredsTooLong))
		return nil
	}

	// Allow-list: an explicit "cannot be used on this server" message, distinct
	// from an upstream rejection (the upstream was never asked, and the
	// operator must be able to tell the two apart). It reveals that a list
	// exists; that is intended. No upstream call for foreign keys.
	if !up.CredsAllowed(creds) {
		s.log.Info("authorize refused: credentials not in allowed_values",
			append([]any{"upstream", up.Name}, s.audit.Who(s.clientIP(r), up, creds)...)...)
		form(http.StatusBadRequest, uiMsg(msgCredsNotAllowed))
		return nil
	}

	if msg, status := s.validateCreds(r.Context(), up, creds, s.audit.Who(s.clientIP(r), up, creds)); msg.ID != "" {
		if status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", retryAfterUnavailable)
		}
		form(status, msg)
		return nil
	}

	// Only a submission that is about to get a code is charged against the
	// global ceiling (it bounds live codes); everything above is bounded by the
	// per-IP limits charged up front.
	if !s.chargeGlobalAuthorize(w) {
		return pageFailure(http.StatusTooManyRequests, msgTooManyRequests)
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
	attrs := []slog.Attr{
		slog.String("client_ip", s.clientIP(r)),
		slog.String("upstream", up.Name),
		slog.String("client_id", shortID(req.ClientID)),
		slog.String("redirect_host", redirectHost(req.RedirectURI)),
		slog.String("lang", l.Lang()),
		s.audit.Creds(up, creds),
	}
	if v, ok := s.cfg.OAuth.Page.TermsFor(l.Lang()); ok {
		// The language of the text the user accepted: a submit without
		// acceptance never gets here.
		attrs = append(attrs, slog.String("terms_lang", v.TextLang))
	}
	s.audit.Record(r.Context(), audit.EventAuthorize, attrs...)
	s.redirect(w, r, *l, req.RedirectURI, req.State, url.Values{"code": {code}})
	return nil
}

// redirectHost returns the host (with port, if any) of a redirect URI.
func redirectHost(uri string) string {
	if u, err := url.Parse(uri); err == nil {
		return u.Host
	}
	return ""
}

// validateCreds runs the upstream's credential check, if configured. A
// non-empty msg means no code may be issued: the form is re-rendered with that
// message and status (400 rejected, 503 no verdict, so the check fails closed).
// who is the audit identification (client IP and audited values) for the
// refusal log line; nil when audit is off.
func (s *Server) validateCreds(ctx context.Context, up config.Upstream, creds map[string]string, who []any) (msg message, status int) {
	if up.Validate == nil {
		return message{}, 0
	}
	err := s.checker.Check(ctx, up, creds)
	if err == nil {
		return message{}, 0
	}
	logCheck(s.log, up.Name, err, who...)
	if errors.Is(err, credcheck.ErrRejected) {
		return rejectedMessage(up), http.StatusBadRequest
	}
	return uiMsg(msgCredsNoVerdict, upstreamTitle(up)), http.StatusServiceUnavailable
}

func upstreamTitle(up config.Upstream) string {
	if up.Title == "" {
		return up.Name
	}
	return up.Title
}

// rejectedMessage is the form error for credentials that must not get a token.
func rejectedMessage(up config.Upstream) message {
	return uiMsg(msgCredsRejected, upstreamTitle(up))
}

// lookupClient opens a client_id, mapping failures to page failures.
func (s *Server) lookupClient(clientID string) (client, *authFailure) {
	c, err := s.openClient(clientID)
	switch {
	case err == nil:
		return c, nil
	case errors.Is(err, errInvalidClient):
		return client{}, pageFailure(http.StatusBadRequest, msgClientUnknown)
	default:
		s.log.Error("opening client id", "err", err)
		return client{}, pageFailure(http.StatusInternalServerError, msgInternal)
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
func collectCreds(up config.Upstream, form url.Values, lang string) (creds, values map[string]string, msg message) {
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
			msg = uiMsg(msgCredRequired, credLabel(cr, lang))
		case len(v) > maxCredLen:
			msg = uiMsg(msgCredTooLong, credLabel(cr, lang))
		case !validCredValue(v):
			msg = uiMsg(msgCredInvalid, credLabel(cr, lang))
		}
		if msg.ID != "" {
			return nil, values, msg
		}
		creds[http.CanonicalHeaderKey(cr.Header)] = v
	}
	return creds, values, message{}
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

// credLabel is the label of cr in lang (see config.Credential.LabelIn).
func credLabel(cr config.Credential, lang string) string { return cr.LabelIn(lang).Text }

// formArgs is what writeForm renders: who asks, for which upstream, the sealed
// request, the non-secret values to refill, and the banner (zero for none).
type formArgs struct {
	Client client
	Up     config.Upstream
	Req    authRequest
	Sealed string
	Values map[string]string
	Msg    message
	// TermsInvalid marks the terms checkbox as the cause of Msg.
	TermsInvalid bool
}

// writeForm renders the credentials form with the security headers.
func (s *Server) writeForm(w http.ResponseWriter, status int, l locale, a formArgs) {
	c, up, req, sealed, values, msg := a.Client, a.Up, a.Req, a.Sealed, a.Values, a.Msg
	fields := make([]formField, len(up.Credentials))
	for i, cr := range up.Credentials {
		id := credFieldID(i)
		lt := cr.LabelIn(l.Lang())
		fields[i] = formField{ID: id, Label: lt.Text, Lang: otherLang(l, lt.Lang), Secret: cr.Secret, Optional: cr.Optional, Value: values[id]}
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
	page := s.cfg.OAuth.Page
	data := formPage{
		CSS:           template.CSS(styleCSS),
		L:             l,
		Action:        PathAuthorize,
		UpstreamTitle: title,
		ClientName:    c.Name,
		RedirectHost:  host,
		Request:       sealed,
		Fields:        fields,
		Error:         msg,
		Notice:        page.NoticeParagraphs(l.Lang()),
		NoticeLang:    otherLang(l, page.NoticeIn(l.Lang()).Lang),
		LangLinks:     langLinks(l, req, up.ResourceURL(s.cfg.PublicURL)),
		TermsInvalid:  a.TermsInvalid,
		Contact:       page.ContactText(),
		ContactHref:   page.ContactHref(),
	}
	if s.cfg.Audit.Enabled {
		an := &auditNotice{
			NeverLogged: nonPageLang(l, up.NeverLoggedLabels(l.Lang())),
		}
		for _, lt := range up.AuditedLabels(l.Lang()) {
			an.Logged = append(an.Logged, l.Slot("audit.your", lt))
		}
		data.Audit = an
	}
	if v, ok := page.TermsFor(l.Lang()); ok {
		data.Terms = &termsView{
			Paragraphs: v.Paragraphs, TextLang: otherLang(l, v.TextLang), URL: v.URL,
		}
		if v.URL != "" {
			data.Terms.URLLang = otherLang(l, v.URLLang)
		}
	}
	s.renderPage(w, status, formAction, authorizeTmpl, data)
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

func (s *Server) writeErrorPage(w http.ResponseWriter, status int, l locale, m message) {
	s.renderPage(w, status, "'none'", errorTmpl, errorPage{
		CSS: template.CSS(styleCSS), L: l, Message: m,
	})
}

// writeFailure renders an error page or redirects the error to the client.
func (s *Server) writeFailure(w http.ResponseWriter, r *http.Request, l locale, f *authFailure) {
	if f.RedirectURI == "" {
		if f.Status >= 500 {
			s.log.Warn("authorize request failed", "status", f.Status)
		} else {
			s.log.Debug("authorize request rejected", "reason", f.Description)
		}
		s.writeErrorPage(w, f.Status, l, f.Message)
		return
	}
	s.log.Debug("authorize request rejected", "error", f.Code, "reason", f.Description)
	s.redirect(w, r, l, f.RedirectURI, f.State, url.Values{"error": {f.Code}, "error_description": {f.Description}})
}

// redirect sends the user agent to the (already verified) redirect URI with
// params, state (when present) and the issuer (RFC 9207).
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, l locale, redirectURI, state string, params url.Values) {
	u, err := url.Parse(redirectURI)
	if err != nil { // unreachable: it is allowlisted config
		s.writeErrorPage(w, http.StatusInternalServerError, l, uiMsg(msgInternal))
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

// otherLang is lang when it is not the page's language, else empty: the
// templates add a lang attribute only for text in another language.
func otherLang(l locale, lang string) string {
	if lang == l.Lang() {
		return ""
	}
	return lang
}

// nonPageLang returns lts with Lang cleared for the ones in the page language.
func nonPageLang(l locale, lts []config.LangText) []config.LangText {
	out := make([]config.LangText, len(lts))
	for i, lt := range lts {
		out[i] = config.LangText{Text: lt.Text, Lang: otherLang(l, lt.Lang)}
	}
	return out
}
