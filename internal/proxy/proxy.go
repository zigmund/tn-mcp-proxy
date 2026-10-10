// Package proxy implements the protected-resource side of the facade: a
// reverse proxy for one upstream MCP server that authenticates requests with a
// sealed access token and injects the upstream credentials as headers.
//
// The handler never logs or forwards the bearer token or the credentials.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/zigmund/tn-mcp-proxy/internal/audit"
	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
	"github.com/zigmund/tn-mcp-proxy/internal/tokens"
)

// Upstream transport limits. There is deliberately no overall request timeout
// and no response header timeout: SSE streams and slow tool calls are
// legitimately long. Only connection setup is bounded.
const (
	dialTimeout         = 10 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
	keepAlive           = 30 * time.Second
	maxIdlePerHost      = 64

	// maxRequestBody is the default cap on the client request body forwarded
	// upstream; limits.max_request_body overrides it.
	maxRequestBody = config.DefaultMaxRequestBody
)

// forwardedHeaders is the allow-list of client request headers relayed
// upstream (canonical form); everything else is dropped. It is what MCP
// Streamable HTTP needs, so a token holder cannot steer the upstream with
// arbitrary headers. Content-Length and Transfer-Encoding are managed by
// net/http from the request, not copied. Origin is forwarded because MCP
// servers validate it (DNS-rebinding protection) and the decision is theirs.
// Hop-by-hop headers are removed by ReverseProxy before this list applies.
// Adding any header, in particular a new Mcp-* header from a newer MCP spec
// draft, needs a deliberate decision.
var forwardedHeaders = []string{
	"Accept", "Accept-Encoding", "Content-Type", "Mcp-Session-Id",
	"Mcp-Protocol-Version", "Last-Event-Id", "User-Agent", "Origin",
}

// allowHeader lists the MCP Streamable HTTP methods: POST for messages, GET
// for the SSE stream, DELETE to end a session. The values are also sent in
// the Allow header of 405 responses.
const allowHeader = "GET, POST, DELETE"

type credsKey struct{}

// ipKey carries the client IP in the request context, set only when audit is
// on, for the refusals logged from response callbacks (the outbound request
// no longer has the client's forwarding headers).
type ipKey struct{}

type handler struct {
	up     config.Upstream
	target *url.URL
	meta   string // resource_metadata URL advertised in challenges
	sealer *seal.Sealer
	log    *slog.Logger
	rp     *httputil.ReverseProxy
	hdrs   []credHeader
	// rechecker is non-nil when validate.recheck_on_tool_error is set: a tool
	// error in a 200 response triggers a credential re-check, and a rejection
	// becomes 401 invalid_token. Nil means the feature is off.
	rechecker *Rechecker
	// limits holds the rate, concurrency and body limits; never nil after New.
	limits *Limits
	// audit writes the audit records; nil when audit.enabled is off.
	audit *audit.Logger
}

// Option configures a handler.
type Option func(*handler)

// WithRechecker shares one Rechecker (verdict cache, in-flight dedup and the
// concurrency cap) between handlers. Without it each handler with
// recheck_on_tool_error gets its own.
func WithRechecker(r *Rechecker) Option {
	return func(h *handler) {
		if r != nil {
			h.rechecker = r
		}
	}
}

// WithAudit makes the handler write the audit log: one "request" record per
// proxied request, and the client IP and audited credential values on its
// refusal logs. A nil logger means audit is off.
func WithAudit(a *audit.Logger) Option {
	return func(h *handler) { h.audit = a }
}

// WithLimits shares one Limits (per-IP budget, per-grant state and the global
// in-flight cap) between handlers. Without it each handler gets its own with
// the default limits.
func WithLimits(l *Limits) Option {
	return func(h *handler) {
		if l != nil {
			h.limits = l
		}
	}
}

type credHeader struct {
	name     string // canonical
	optional bool
}

// New returns the handler for one upstream. The server mounts it at exactly
// up.Path. publicURL is the externally visible base URL (no trailing slash
// required).
func New(up config.Upstream, publicURL string, s *seal.Sealer, log *slog.Logger, opts ...Option) (http.Handler, error) {
	if s == nil {
		return nil, errors.New("proxy: nil sealer")
	}
	if log == nil {
		log = slog.Default()
	}
	target, err := url.Parse(up.URL)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		return nil, fmt.Errorf("proxy: upstream %q: invalid url", up.Name)
	}
	if up.Path == "" {
		return nil, fmt.Errorf("proxy: upstream %q: empty path", up.Name)
	}
	h := &handler{
		up:     up,
		target: target,
		meta:   strings.TrimRight(publicURL, "/") + "/.well-known/oauth-protected-resource" + up.Path,
		sealer: s,
		log:    log.With("upstream", up.Name),
	}
	for _, c := range up.Credentials {
		h.hdrs = append(h.hdrs, credHeader{name: http.CanonicalHeaderKey(c.Header), optional: c.Optional})
	}
	for _, o := range opts {
		o(h)
	}
	if up.Validate != nil && up.Validate.RecheckOnToolError {
		if h.rechecker == nil {
			h.rechecker = NewRechecker(log)
		}
	} else {
		h.rechecker = nil // the feature is configured per upstream
	}
	if h.limits == nil {
		h.limits = NewLimits(config.ProxyLimits{}, log)
	}
	h.rp = &httputil.ReverseProxy{
		Rewrite:        h.rewrite,
		ModifyResponse: h.modifyResponse,
		ErrorHandler:   h.errorHandler,
		FlushInterval:  -1, // flush every write: SSE events must not be buffered
		Transport:      newTransport(h.limits.maxConns()),
		ErrorLog:       slog.NewLogLogger(h.log.Handler(), slog.LevelWarn),
	}
	return h, nil
}

// newTransport builds the upstream transport. maxConns > 0 sets
// MaxConnsPerHost; requests beyond it would queue inside the transport, which
// is why the handler enforces the same number as a global in-flight cap first
// and answers 503 instead.
func newTransport(maxConns int) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	// Credentials travel in request headers: never route upstream traffic
	// through an HTTP(S)_PROXY from the environment, which would see them
	// (in clear text for an http upstream, as CONNECT target for https).
	t.Proxy = nil
	t.DialContext = (&net.Dialer{Timeout: dialTimeout, KeepAlive: keepAlive}).DialContext
	t.TLSHandshakeTimeout = tlsHandshakeTimeout
	t.MaxIdleConnsPerHost = maxIdlePerHost
	t.MaxConnsPerHost = maxConns
	t.DisableCompression = true // pass bytes through opaquely; no gzip delaying SSE
	return t
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only the exact mount path is served: no sub-paths, and no encoded or
	// unclean variants (a non-empty RawPath means the client used escapes).
	if r.URL.Path != h.up.Path || (r.URL.RawPath != "" && r.URL.RawPath != h.up.Path) {
		http.NotFound(w, r)
		return
	}
	// Decided before authentication: no token parsing, no upstream contact.
	// HEAD and OPTIONS (CORS preflight) are not relayed either; the OAuth
	// endpoints, not the MCP endpoint, serve browser-facing CORS.
	switch r.Method {
	case http.MethodPost, http.MethodGet, http.MethodDelete:
	default:
		h.log.Debug("method not allowed", "method", r.Method)
		w.Header().Set("Allow", allowHeader)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Upgrade") != "" {
		http.Error(w, "upgrade not supported", http.StatusBadRequest)
		return
	}
	// Order: method and path (above, free) -> per-IP rate (before the token is
	// opened, so unauthenticated floods are cut cheaply) -> authentication ->
	// body size -> content encoding -> per-grant rate -> per-grant concurrency -> global in-flight
	// cap. A refusal gives back everything taken before it.
	ipKeys, ok := h.limits.chargeIP(w, r)
	if !ok {
		return
	}
	creds, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	maxBody := h.limits.maxBody()
	if r.ContentLength > maxBody {
		h.limits.refundIP(ipKeys) // a cheap rejection, not abuse of the budget
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if hasContentEncoding(r.Header) {
		// Content-Encoding is not forwarded, so the upstream would receive
		// unlabelled compressed bytes; nor can such a body be inspected.
		h.limits.refundIP(ipKeys)
		h.log.Debug("request with content-encoding refused")
		http.Error(w, "content-encoding not supported", http.StatusUnsupportedMediaType)
		return
	}
	release, ok := h.limits.admit(w, ipKeys, grantKey(h.up.Name, h.grantCreds(creds)))
	if !ok {
		return
	}
	// Held until the response, a long-lived SSE stream included, has ended or
	// the client has gone: ReverseProxy.ServeHTTP returns then.
	defer release()
	info, ok := h.inspectToolArguments(w, r, maxBody, creds)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	ctx := context.WithValue(r.Context(), credsKey{}, creds)
	if h.audit.Enabled() {
		ip := h.limits.clientIP(r)
		ctx = context.WithValue(ctx, ipKey{}, ip)
		rec := &statusRecorder{ResponseWriter: w}
		w = rec
		// Deferred, so that the record is written exactly once when the
		// handler returns, whatever the outcome: a long-lived SSE stream
		// included, and an aborted copy (panic) too.
		defer func() { h.auditRequest(ctx, ip, rec.status, r.Method, creds, info) }()
	}
	h.rp.ServeHTTP(w, r.WithContext(ctx))
}

// who returns the audit identification of a refusal for request r, or nil when
// audit is off.
func (h *handler) who(r *http.Request, creds map[string]string) []any {
	if !h.audit.Enabled() {
		return nil
	}
	return h.audit.Who(h.limits.clientIP(r), h.up, creds)
}

// whoCtx is who for a response callback: creds and IP come from the context.
func (h *handler) whoCtx(ctx context.Context) []any {
	if !h.audit.Enabled() {
		return nil
	}
	creds, _ := ctx.Value(credsKey{}).(map[string]string)
	ip, _ := ctx.Value(ipKey{}).(string)
	return h.audit.Who(ip, h.up, creds)
}

// auditRequest writes the "request" audit record. status is 0 when no
// response was written (the client left first). info is nil when the body was
// not inspected, in which case the JSON-RPC fields are omitted.
func (h *handler) auditRequest(ctx context.Context, ip string, status int, method string, creds map[string]string, info *bodyInfo) {
	attrs := []slog.Attr{
		slog.String("client_ip", ip),
		slog.String("upstream", h.up.Name),
		slog.String("method", method),
		slog.Int("status", status),
		h.audit.Creds(h.up, creds),
	}
	if info != nil {
		switch {
		case info.batch > 0:
			// One group per call, so method and tool stay aligned and every
			// value is its own attribute in both log formats.
			calls := make([]any, 0, len(info.calls))
			for i, c := range info.calls {
				calls = append(calls, slog.Group(strconv.Itoa(i), slog.String("method", c.method), slog.String("tool", c.tool)))
			}
			attrs = append(attrs, slog.Int("rpc_batch", info.batch), slog.Group("rpc", calls...))
		case len(info.calls) == 1:
			if c := info.calls[0]; c.method != "" {
				attrs = append(attrs, slog.String("rpc_method", c.method))
				if c.tool != "" {
					attrs = append(attrs, slog.String("tool", c.tool))
				}
			}
		}
	}
	h.audit.Record(context.WithoutCancel(ctx), audit.EventRequest, attrs...)
}

// statusRecorder captures the final status code. It forwards Flush and exposes
// the wrapped writer through Unwrap, which ReverseProxy needs to stream SSE.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.ResponseWriter.WriteHeader(code)
	// First final status wins; 1xx other than 101 are interim responses.
	if r.status == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
		r.status = code
	}
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(p)
}

func (r *statusRecorder) Flush() { _ = r.FlushError() }

// FlushError implements the optional interface ReverseProxy looks for, so a
// flush error reaches it.
func (r *statusRecorder) FlushError() error {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return http.NewResponseController(r.ResponseWriter).Flush()
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// hasContentEncoding reports whether the request declares any encoding other
// than identity, in any header line or comma-separated list element.
func hasContentEncoding(hdr http.Header) bool {
	for _, v := range hdr.Values("Content-Encoding") {
		for _, enc := range strings.Split(v, ",") {
			if enc = strings.TrimSpace(enc); enc != "" && !strings.EqualFold(enc, "identity") {
				return true
			}
		}
	}
	return false
}

// grantCreds returns the credentials that identify the grant for the per-grant
// limits: the required ones only. Optional credentials are not checked by
// validate (get_auth_info ignores X-TN-SID, for one), so a client could vary
// them freely and would otherwise get a fresh budget for every value.
func (h *handler) grantCreds(creds map[string]string) map[string]string {
	out := make(map[string]string, len(creds))
	for _, c := range h.hdrs {
		if c.optional {
			continue
		}
		if v, ok := creds[c.name]; ok {
			out[c.name] = v
		}
	}
	return out
}

// authenticate validates the bearer token and returns the credentials to
// inject. On failure it has already written the response.
func (h *handler) authenticate(w http.ResponseWriter, r *http.Request) (map[string]string, bool) {
	raw, present := bearer(r.Header.Get("Authorization"))
	if !present {
		h.challenge(w, "", "")
		return nil, false
	}
	acc, err := seal.OpenAs[tokens.Access](h.sealer, seal.KindAccess, raw)
	switch {
	case errors.Is(err, seal.ErrExpired):
		h.challenge(w, "invalid_token", "token expired")
		return nil, false
	case errors.Is(err, seal.ErrInvalid):
		h.challenge(w, "invalid_token", "token invalid")
		return nil, false
	case errors.Is(err, seal.ErrPayload):
		// Authentic token with an unexpected payload shape (e.g. after a
		// deploy changed it): a server-side anomaly, but the client's fix is
		// to re-authorize, so answer 401.
		h.log.Error("access token payload mismatch", "err", err)
		h.challenge(w, "invalid_token", "token invalid")
		return nil, false
	case err != nil: // broken Sealer: a server bug
		h.log.Error("opening access token", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, false
	}
	if acc.Upstream != h.up.Name {
		h.challenge(w, "invalid_token", "token not valid for this resource")
		return nil, false
	}

	// Only configured headers are injected; extras in the token are ignored.
	creds := make(map[string]string, len(h.hdrs))
	for _, c := range h.hdrs {
		v := lookup(acc.Creds, c.name)
		switch {
		case v == "" && c.optional:
			continue
		case v == "":
			h.log.Warn("token lacks required credential", append([]any{"header", c.name}, h.who(r, acc.Creds)...)...)
			h.challenge(w, "invalid_token", "token lacks required credentials")
			return nil, false
		case strings.ContainsAny(v, "\r\n\x00"):
			// Only the audited values of the token, escaped by slog.
			h.log.Warn("token credential has invalid value", append([]any{"header", c.name}, h.who(r, acc.Creds)...)...)
			h.challenge(w, "invalid_token", "token lacks required credentials")
			return nil, false
		}
		creds[c.name] = v
	}
	// Operator allow-list: a value removed from allowed_values cuts existing
	// tokens off. Same answer as any other invalid token.
	if !h.up.CredsAllowed(creds) {
		h.log.Info("token credentials not in allowed_values", append([]any{"upstream", h.up.Name}, h.who(r, creds)...)...)
		h.challenge(w, "invalid_token", "token invalid")
		return nil, false
	}
	return creds, true
}

// lookup finds the canonical header name in m, tolerating non-canonical keys.
func lookup(m map[string]string, canonical string) string {
	if v, ok := m[canonical]; ok {
		return v
	}
	for k, v := range m {
		if http.CanonicalHeaderKey(k) == canonical {
			return v
		}
	}
	return ""
}

// bearer extracts the token from an Authorization header. present is false
// when the header is absent or uses another scheme.
func bearer(h string) (token string, present bool) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(h), " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	// An empty token yields present=true and fails validation as invalid.
	// Hardening: anything but exactly one token (embedded whitespace or
	// control characters, as in "Bearer a b") is treated as empty. The sealer
	// would reject such a value with the same 401 anyway; this keeps the
	// parser's contract tight. The token grammar is otherwise left to the sealer.
	rest = strings.TrimSpace(rest)
	if strings.IndexFunc(rest, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", true
	}
	return rest, true
}

// challenge writes a 401 with an RFC 6750 / RFC 9728 WWW-Authenticate header.
// code and desc are fixed strings (never request data), so no escaping needed.
func (h *handler) challenge(w http.ResponseWriter, code, desc string) {
	w.Header().Set("WWW-Authenticate", h.challengeValue(code, desc))
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (h *handler) challengeValue(code, desc string) string {
	v := "Bearer "
	if code != "" {
		v += fmt.Sprintf("error=%q, error_description=%q, ", code, desc)
	}
	return v + fmt.Sprintf("resource_metadata=%q", h.meta)
}

// rewrite builds the upstream request: fixed upstream URL, only the
// allow-listed client headers, and credentials from the token.
func (h *handler) rewrite(pr *httputil.ProxyRequest) {
	creds, _ := pr.In.Context().Value(credsKey{}).(map[string]string)
	out := pr.Out

	// Fixed upstream URL (path and RawPath intact). The client's query is
	// forwarded only when the upstream URL has none of its own; Out's query
	// is already cleaned of unparsable parameters by ReverseProxy.
	u := *h.target
	if u.RawQuery == "" {
		u.RawQuery = out.URL.RawQuery
	}
	out.URL = &u
	out.Host = h.target.Host

	// Allow-list: rebuild the headers from the outbound request. Anything not
	// listed (client IP headers, overrides, cookies, inbound auth, spoofed
	// credential headers, ...) is dropped.
	hd := make(http.Header, len(forwardedHeaders)+len(h.hdrs))
	// Copy from Out: ReverseProxy already removed hop-by-hop headers and the
	// ones named in Connection, so they cannot pass even if allow-listed.
	for _, k := range forwardedHeaders {
		if v, ok := out.Header[k]; ok {
			hd[k] = slices.Clone(v)
		}
	}
	if _, ok := hd["User-Agent"]; !ok {
		// None sent: keep it empty rather than Go's default UA. ReverseProxy
		// also sets this; it is explicit here because the headers are rebuilt.
		hd["User-Agent"] = nil
	}
	// Tool error inspection must be able to read POST responses, and the
	// proxy decodes only gzip: offer upstream nothing else. GET (the SSE
	// stream) is never inspected and keeps the client's value.
	if h.rechecker != nil && out.Method == http.MethodPost {
		hd.Set("Accept-Encoding", narrowAcceptEncoding(strings.Join(hd.Values("Accept-Encoding"), ",")))
	}
	out.Header = hd
	for k, v := range creds {
		hd.Set(k, v)
	}
}

func (h *handler) modifyResponse(resp *http.Response) error {
	resp.Header.Del("Set-Cookie")
	h.log.Debug("upstream response", "status", resp.StatusCode)
	if resp.StatusCode == http.StatusUnauthorized {
		// The upstream rejected the stored credentials. Replace its challenge
		// with ours so the client re-runs authorization and the user can
		// enter new keys.
		h.log.Warn("upstream rejected credentials", h.whoCtx(resp.Request.Context())...)
		resp.Header.Set("WWW-Authenticate", h.challengeValue("invalid_token", "upstream rejected credentials"))
		return nil
	}
	return h.inspectToolError(resp)
}

func (h *handler) errorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	var mbe *http.MaxBytesError
	var ne net.Error
	switch {
	case errors.Is(err, context.Canceled):
		h.log.Debug("client went away", "err", err)
		return // nobody is listening; write nothing
	case errors.As(err, &mbe):
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	// url.Error embeds the full URL, which may carry a query secret.
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	h.log.Warn("upstream request failed", "err", err)
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
		return
	}
	http.Error(w, "bad gateway", http.StatusBadGateway)
}
