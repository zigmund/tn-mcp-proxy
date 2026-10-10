// Package oauth implements the OAuth 2.1 authorization server endpoints and
// discovery metadata that front header-authenticated MCP upstreams.
package oauth

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/credcheck"
	"github.com/zigmund/tn-mcp-proxy/internal/httplog"
	"github.com/zigmund/tn-mcp-proxy/internal/ratelimit"
	"github.com/zigmund/tn-mcp-proxy/internal/seal"
)

// Endpoint paths. public_url is an origin, so these are served at the host root.
const (
	PathAuthorize              = "/oauth/authorize"
	PathToken                  = "/oauth/token"
	PathRegister               = "/oauth/register"
	PathAuthServerMetadata     = "/.well-known/oauth-authorization-server"
	PathOIDCMetadata           = "/.well-known/openid-configuration"
	PathResourceMetadataPrefix = "/.well-known/oauth-protected-resource"
)

// Server hosts all OAuth endpoints. Later endpoints (register, authorize,
// token) are added to Register without changing the constructor.
type Server struct {
	cfg    *config.Config
	sealer *seal.Sealer
	log    *slog.Logger
	now    func() time.Time // overridable in tests
	// codes and families make authorization codes and refresh tokens
	// single-use (per process, see replayCache and familyCache).
	codes    *replayCache
	families *familyCache
	// clientIP resolves the client address for rate limiting; limits is nil
	// when rate limiting is disabled.
	clientIP func(*http.Request) string
	limits   map[string]*ratelimit.Limiter
	// checker verifies credentials on authorize for upstreams with validate.
	checker *credcheck.Checker
}

// Option configures a Server.
type Option func(*Server)

// WithClientIP sets the client IP resolver used for rate limiting. The default
// trusts only loopback proxies; the server passes the shared httplog.Resolver
// so that logs and limits agree.
func WithClientIP(fn func(*http.Request) string) Option {
	return func(s *Server) {
		if fn != nil {
			s.clientIP = fn
		}
	}
}

// New builds a Server. A nil sealer is tolerated only for metadata-only use:
// endpoints that seal or open tokens fail with a server error.
func New(cfg *config.Config, sealer *seal.Sealer, log *slog.Logger, opts ...Option) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		cfg: cfg, sealer: sealer, log: log, now: time.Now,
		codes: newReplayCache(maxReplayEntries), families: newFamilyCache(maxFamilyEntries),
		clientIP: httplog.NewResolver(cfg.TrustedNets).ClientIP,
		checker:  credcheck.New(),
	}
	for _, o := range opts {
		o(s)
	}
	s.limits = newLimiters(cfg.OAuth.RateLimit, cfg.OAuth.CodeTTL, func() time.Time { return s.now() })
	return s
}

// Register mounts the implemented endpoints on mux.
func (s *Server) Register(mux *http.ServeMux) {
	// Static discovery documents are rendered once here, at startup.
	for _, d := range buildMetadata(s.cfg) {
		mux.Handle("GET "+d.path, d) // also matches HEAD
		mux.Handle("OPTIONS "+d.path, preflight("GET, HEAD, OPTIONS"))
	}
	// GET (also matches HEAD) has its own, more generous per-IP limit.
	mux.Handle("GET "+PathAuthorize, s.limitMethod(formKey, http.MethodGet, s.denyAuthorize, http.HandlerFunc(s.handleAuthorize)))
	mux.Handle("POST "+PathAuthorize, s.limit("authorize", s.denyAuthorize, http.HandlerFunc(s.handleAuthorize)))
	mux.Handle("POST "+PathRegister, s.limit("register", s.denyRegister, http.HandlerFunc(s.handleRegister)))
	mux.Handle("OPTIONS "+PathRegister, preflight("POST, OPTIONS"))
	// All methods are routed so that even a 405 carries the token headers.
	mux.Handle(PathToken, s.limit("token", s.denyToken, http.HandlerFunc(s.handleToken)))
}
