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
	"strings"
	"time"

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

	// maxRequestBody caps the client request body forwarded upstream.
	maxRequestBody = 10 << 20
)

type credsKey struct{}

type handler struct {
	up     config.Upstream
	target *url.URL
	meta   string // resource_metadata URL advertised in challenges
	sealer *seal.Sealer
	log    *slog.Logger
	rp     *httputil.ReverseProxy
	hdrs   []credHeader
}

type credHeader struct {
	name     string // canonical
	optional bool
}

// New returns the handler for one upstream. The server mounts it at exactly
// up.Path. publicURL is the externally visible base URL (no trailing slash
// required).
func New(up config.Upstream, publicURL string, s *seal.Sealer, log *slog.Logger) (http.Handler, error) {
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
	h.rp = &httputil.ReverseProxy{
		Rewrite:        h.rewrite,
		ModifyResponse: h.modifyResponse,
		ErrorHandler:   h.errorHandler,
		FlushInterval:  -1, // flush every write: SSE events must not be buffered
		Transport:      newTransport(),
		ErrorLog:       slog.NewLogLogger(h.log.Handler(), slog.LevelWarn),
	}
	return h, nil
}

func newTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{Timeout: dialTimeout, KeepAlive: keepAlive}).DialContext
	t.TLSHandshakeTimeout = tlsHandshakeTimeout
	t.MaxIdleConnsPerHost = maxIdlePerHost
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
	if r.Header.Get("Upgrade") != "" {
		http.Error(w, "upgrade not supported", http.StatusBadRequest)
		return
	}
	creds, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if r.ContentLength > maxRequestBody {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	h.rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), credsKey{}, creds)))
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
			h.log.Warn("token lacks required credential", "header", c.name)
			h.challenge(w, "invalid_token", "token lacks required credentials")
			return nil, false
		case strings.ContainsAny(v, "\r\n\x00"):
			h.log.Warn("token credential has invalid value", "header", c.name) // never the value
			h.challenge(w, "invalid_token", "token lacks required credentials")
			return nil, false
		}
		creds[c.name] = v
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
	return strings.TrimSpace(rest), true
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

// rewrite builds the upstream request: fixed upstream URL, credentials from
// the token, and no client-identifying or inbound auth headers.
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

	hd := out.Header
	for _, k := range []string{"Authorization", "Cookie", "Proxy-Authorization", "X-Real-Ip"} {
		hd.Del(k)
	}
	// ReverseProxy already dropped Forwarded and X-Forwarded-For/Host/Proto;
	// drop the remaining X-Forwarded-* (Port, Server, ...) too.
	for k := range hd {
		if strings.HasPrefix(strings.ToLower(k), "x-forwarded-") {
			delete(hd, k)
		}
	}
	for _, c := range h.hdrs {
		hd.Del(c.name) // drop whatever the client sent, even for optional headers
	}
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
		h.log.Warn("upstream rejected credentials")
		resp.Header.Set("WWW-Authenticate", h.challengeValue("invalid_token", "upstream rejected credentials"))
	}
	return nil
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
