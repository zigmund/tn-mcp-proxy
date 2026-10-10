package proxy

import "github.com/zigmund/tn-mcp-proxy/internal/oauth"

// The OAuth server reads the shared verdict cache through this interface.
var _ oauth.RejectionSource = (*Rechecker)(nil)
