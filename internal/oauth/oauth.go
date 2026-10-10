// Package oauth implements the OAuth 2.1 authorization server endpoints and
// discovery metadata that front header-authenticated MCP upstreams.
package oauth

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
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
}

// New builds a Server. A nil sealer is tolerated only for metadata-only use:
// endpoints that seal or open tokens fail with a server error.
func New(cfg *config.Config, sealer *seal.Sealer, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{cfg: cfg, sealer: sealer, log: log, now: time.Now, codes: newReplayCache(maxReplayEntries), families: newFamilyCache(maxFamilyEntries)}
}

// Register mounts the implemented endpoints on mux.
func (s *Server) Register(mux *http.ServeMux) {
	// Static discovery documents are rendered once here, at startup.
	for _, d := range buildMetadata(s.cfg) {
		mux.Handle("GET "+d.path, d) // also matches HEAD
		mux.Handle("OPTIONS "+d.path, preflight("GET, HEAD, OPTIONS"))
	}
	mux.HandleFunc("GET "+PathAuthorize, s.handleAuthorize) // also matches HEAD
	mux.HandleFunc("POST "+PathAuthorize, s.handleAuthorize)
	mux.HandleFunc("POST "+PathRegister, s.handleRegister)
	mux.Handle("OPTIONS "+PathRegister, preflight("POST, OPTIONS"))
	// All methods are routed so that even a 405 carries the token headers.
	mux.HandleFunc(PathToken, s.handleToken)
}
