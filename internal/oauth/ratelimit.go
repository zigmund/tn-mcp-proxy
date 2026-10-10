package oauth

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/ratelimit"
)

// Rate-limit error reported to token and registration clients. RFC 6749 has
// no dedicated code for throttling; temporarily_unavailable (§4.1.2.1) is the
// closest registered one and clients treat it as retryable.
const (
	codeRateLimited = "temporarily_unavailable"
	descRateLimited = "rate limit exceeded"
)

// newLimiters builds one limiter (a separate bucket set) per rate-limited
// endpoint, or nil when rate limiting is disabled. Zero config values mean
// the defaults, so a Config that skipped config.Parse still gets limits.
func newLimiters(rl config.RateLimit, now func() time.Time) map[string]*ratelimit.Limiter {
	if rl.Disabled {
		return nil
	}
	rl = rl.Resolved()
	mk := func(l config.Limit) *ratelimit.Limiter {
		return ratelimit.New(l.PerMinute, l.Burst, ratelimit.WithClock(now))
	}
	return map[string]*ratelimit.Limiter{
		"register":  mk(rl.Register),
		"authorize": mk(rl.Authorize),
		"token":     mk(rl.Token),
	}
}

// limit wraps next with the per-IP limiter named name. Only POST requests are
// counted: other methods are cheap 405s (or, for authorize, not routed here).
// A denied request gets 429 with Retry-After via deny.
func (s *Server) limit(name string, deny func(w http.ResponseWriter, r *http.Request), next http.Handler) http.Handler {
	lim := s.limits[name]
	if lim == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		ip := s.clientIP(r)
		ok, wait := lim.Allow(ratelimit.Key(ip))
		if ok {
			next.ServeHTTP(w, r)
			return
		}
		// Client IP only: never the query, headers or body.
		s.log.Debug("rate limit exceeded", "endpoint", name, "remote", ip, "retry_after", wait.String())
		w.Header().Set("Retry-After", retryAfterSeconds(wait))
		deny(w, r)
	})
}

// retryAfterSeconds renders d as whole seconds, rounded up, at least 1.
func retryAfterSeconds(d time.Duration) string {
	return strconv.Itoa(max(1, int(math.Ceil(d.Seconds()))))
}

func (s *Server) denyRegister(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*") // as handleRegister
	w.Header().Set("Access-Control-Expose-Headers", "Retry-After")
	writeRegisterError(w, http.StatusTooManyRequests, codeRateLimited, descRateLimited)
}

func (s *Server) denyToken(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	s.tokenError(w, http.StatusTooManyRequests, codeRateLimited, descRateLimited)
}

func (s *Server) denyAuthorize(w http.ResponseWriter, _ *http.Request) {
	s.writeErrorPage(w, http.StatusTooManyRequests, "Too many requests. Please wait a moment and try again.")
}
