package main

import (
	"log/slog"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
)

// warnNoAllowList logs one warning per upstream without any allowed_values
// list, and one per upstream that has a list but no forbidden_arguments. It
// never logs credential values.
func warnNoAllowList(log *slog.Logger, cfg *config.Config) {
	for _, u := range cfg.Upstreams {
		if !u.HasAllowList() {
			log.Warn("upstream has no allowed_values: anyone with valid upstream credentials can obtain a token and act through this server's IP; set allowed_values on a non-secret credential to restrict access",
				"upstream", u.Name)
			continue
		}
		if len(u.ForbiddenArguments) == 0 {
			log.Warn("upstream has allowed_values but no forbidden_arguments: the allow-list gates token issuance only, so token holders can still pass credentials as tool arguments if the upstream accepts them; set forbidden_arguments (for example api_key, api_secret)",
				"upstream", u.Name)
		}
	}
}
