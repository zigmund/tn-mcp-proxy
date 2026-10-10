package main

import (
	"log/slog"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

// warnNoAllowList logs one warning per upstream without any allowed_values
// list. It never logs credential values.
func warnNoAllowList(log *slog.Logger, cfg *config.Config) {
	for _, u := range cfg.Upstreams {
		if u.HasAllowList() {
			continue
		}
		log.Warn("upstream has no allowed_values: anyone with valid upstream credentials can obtain a token and act through this server's IP; set allowed_values on a non-secret credential to restrict access",
			"upstream", u.Name)
	}
}
