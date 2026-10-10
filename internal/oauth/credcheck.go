package oauth

import (
	"errors"
	"log/slog"

	"github.com/zigmund/tn-mcp-proxy/internal/credcheck"
)

// logCheck logs a non-OK outcome of credChecker.check. Only fixed vocabulary
// and the transport error are logged: never credentials or upstream text. The
// error may contain the upstream host or IP, but never the URL path, query or
// userinfo (the *url.Error wrapper is stripped).
func logCheck(log *slog.Logger, upstream string, err error) {
	var ce *credcheck.CheckError
	if !errors.As(err, &ce) {
		log.Warn("credential check failed", "upstream", upstream)
		return
	}
	if errors.Is(ce, credcheck.ErrRejected) {
		log.Info("credentials rejected by upstream", "upstream", upstream, "step", ce.Step, "reason", ce.Reason)
		return
	}
	attrs := []any{"upstream", upstream, "step", ce.Step, "reason", ce.Reason}
	if ce.Cause != nil {
		attrs = append(attrs, "err", ce.Cause)
	}
	log.Warn("credential check unavailable", attrs...)
}
