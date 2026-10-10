// Package oauth implements the OAuth 2.1 authorization server endpoints and
// discovery metadata that front header-authenticated MCP upstreams.
package oauth

import (
	"log/slog"
	"net/http"

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
	cfg *config.Config
	// sealer is unused until register/authorize/token land; it is part of New
	// now so those endpoints do not change the constructor signature.
	sealer *seal.Sealer
	log    *slog.Logger
}

// New builds a Server. sealer may be nil until the endpoints that need it exist.
func New(cfg *config.Config, sealer *seal.Sealer, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{cfg: cfg, sealer: sealer, log: log}
}

// Register mounts the implemented endpoints on mux.
func (s *Server) Register(mux *http.ServeMux) {
	// Static discovery documents are rendered once here, at startup.
	for _, d := range buildMetadata(s.cfg) {
		mux.Handle("GET "+d.path, d) // also matches HEAD
		mux.Handle("OPTIONS "+d.path, http.HandlerFunc(preflight))
	}
}
