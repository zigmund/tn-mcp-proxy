package server

import (
	"net/http"
	"strings"
	"time"
)

// oauthReadTimeout bounds how long a client may take to deliver the whole
// request (headers already received) of an OAuth or well-known endpoint. Their
// bodies are small forms or JSON documents, so a slow body is an attack, not a
// use case. It is a variable only so tests can shorten it.
var oauthReadTimeout = 10 * time.Second

// hstsValue is sent when built-in TLS is on: one year, no includeSubDomains
// (the proxy cannot know what else lives on the domain).
const hstsValue = "max-age=31536000"

// isOAuthPath reports whether p belongs to the authorization server: the
// /oauth tree and the /.well-known discovery documents. The proxied MCP paths
// are deliberately excluded: they carry long-lived SSE streams and slow tool
// calls, so no absolute read deadline may apply to them.
func isOAuthPath(p string) bool {
	return p == "/oauth" || strings.HasPrefix(p, "/oauth/") || strings.HasPrefix(p, "/.well-known/")
}

// withOAuthReadDeadline sets a per-request read deadline on OAuth and
// well-known requests. A writer that cannot set deadlines (tests, wrappers
// without Unwrap) is tolerated: the request proceeds without one.
func withOAuthReadDeadline(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isOAuthPath(r.URL.Path) {
			_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(oauthReadTimeout))
		}
		next.ServeHTTP(w, r)
	})
}

// withHSTS adds Strict-Transport-Security to every response. The header is
// written at WriteHeader time, replacing (not appending to) any value a
// proxied upstream response carries.
func withHSTS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&hstsWriter{ResponseWriter: w}, r)
	})
}

type hstsWriter struct {
	http.ResponseWriter
	wrote bool
}

func (h *hstsWriter) WriteHeader(code int) {
	// Informational (1xx) responses other than 101 are followed by the final one.
	if code < 200 && code != http.StatusSwitchingProtocols {
		h.ResponseWriter.WriteHeader(code)
		return
	}
	if !h.wrote {
		h.wrote = true
		h.Header().Set("Strict-Transport-Security", hstsValue)
	}
	h.ResponseWriter.WriteHeader(code)
}

func (h *hstsWriter) Write(b []byte) (int, error) {
	if !h.wrote {
		h.WriteHeader(http.StatusOK)
	}
	return h.ResponseWriter.Write(b)
}

// Flush implements http.Flusher (SSE through the reverse proxy needs it).
func (h *hstsWriter) Flush() {
	if !h.wrote {
		h.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(h.ResponseWriter).Flush()
}

// Unwrap returns the underlying writer for http.ResponseController.
func (h *hstsWriter) Unwrap() http.ResponseWriter { return h.ResponseWriter }
