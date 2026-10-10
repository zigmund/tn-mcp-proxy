package oauth

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

// ProtectedResourceMetadata is the RFC 9728 document.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name,omitempty"`
}

// AuthServerMetadata is the RFC 8414 document. Scopes are not used, so
// scopes_supported is omitted.
type AuthServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// metadataDoc is a precomputed static JSON document served at path.
type metadataDoc struct {
	path string
	body []byte
}

// ServeHTTP serves the document; method filtering is done by the mux pattern.
func (d metadataDoc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "public, max-age=300")
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Content-Length", strconv.Itoa(len(d.body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(d.body)
}

// preflight answers CORS preflight requests for browser-based MCP clients.
func preflight(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "MCP-Protocol-Version, Content-Type, Authorization")
	h.Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusNoContent)
}

func buildMetadata(cfg *config.Config) []metadataDoc {
	var docs []metadataDoc
	add := func(path string, v any) {
		// Marshalling plain string structs cannot fail.
		b, _ := json.Marshal(v)
		docs = append(docs, metadataDoc{path: path, body: append(b, '\n')})
	}

	// token_endpoint_auth_methods_supported must match what the register and
	// token endpoints actually implement.
	as := AuthServerMetadata{
		Issuer:                            cfg.PublicURL,
		AuthorizationEndpoint:             cfg.PublicURL + PathAuthorize,
		TokenEndpoint:                     cfg.PublicURL + PathToken,
		RegistrationEndpoint:              cfg.PublicURL + PathRegister,
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_post", "client_secret_basic"},
	}
	add(PathAuthServerMetadata, as)
	// Fallback for MCP 2025-06-18 clients; this is not a full OIDC provider.
	add(PathOIDCMetadata, as)

	for i, u := range cfg.Upstreams {
		prm := ProtectedResourceMetadata{
			Resource:               u.ResourceURL(cfg.PublicURL),
			AuthorizationServers:   []string{cfg.PublicURL},
			BearerMethodsSupported: []string{"header"},
			ResourceName:           u.Title,
		}
		add(PathResourceMetadataPrefix+u.Path, prm)
		// Fallback for clients probing the root: only unambiguous with one upstream.
		if i == 0 && len(cfg.Upstreams) == 1 {
			add(PathResourceMetadataPrefix, prm)
		}
	}
	return docs
}
