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

// Limiter names in Server.limits. An IPv6 client is charged against one
// limiter per tier (/64, /56, /48), named name, name+tier56 and name+tier48;
// the unkeyed ceiling on authorize is globalKey.
const (
	tier56       = "/56"
	tier48       = "/48"
	authorizeKey = "authorize"
	// formKey is the limiter of GET /oauth/authorize (rendering the form seals
	// a request, so it is throttled too, far more generously than the POST).
	formKey   = "authorize_form"
	globalKey = "authorize/global"

	// globalLogInterval bounds how often the ceiling being hit is logged.
	globalLogInterval = time.Minute
)

// globalAuthorizeDefault derives the ceiling on code issuance from the code
// cache size and code_ttl, so the cache cannot fill: a code occupies a slot
// from its redemption until its expiry, so at most burst + perMinute*ttl
// (rounded up to whole minutes) slots are live, which is at most half of
// maxReplayEntries (a quarter of it per ttl, plus one minute of burst). A
// longer code_ttl therefore lowers the rate.
func globalAuthorizeDefault(codeTTL time.Duration) config.Limit {
	if codeTTL <= 0 {
		codeTTL = config.DefaultCodeTTL
	}
	mins := max(1, int(math.Ceil(codeTTL.Minutes())))
	per := max(1, maxReplayEntries/4/mins)
	return config.Limit{PerMinute: per, Burst: per}
}

// warnGlobalOversized warns when a configured authorize_global lets more codes
// be live within code_ttl than half the code cache (burst + per_minute *
// ceil(minutes(code_ttl))), which gives up the guarantee that the cache cannot
// fill. The derived default always satisfies it for code_ttl up to about 17
// days (beyond that even 1 per minute exceeds the bound).
func (s *Server) warnGlobalOversized() {
	g := s.cfg.OAuth.RateLimit.AuthorizeGlobal
	if g.PerMinute == 0 || s.cfg.OAuth.RateLimit.Disabled {
		return
	}
	ttl := s.cfg.OAuth.CodeTTL
	if ttl <= 0 {
		ttl = config.DefaultCodeTTL
	}
	mins := max(1, int(math.Ceil(ttl.Minutes())))
	if live := max(g.Burst, g.PerMinute) + g.PerMinute*mins; live > maxReplayEntries/2 {
		s.log.Warn("oauth.rate_limit.authorize_global allows more live codes than half the code cache; the cache may fill",
			"possible_live_codes", live, "code_cache_capacity", maxReplayEntries)
	}
}

// newLimiters builds the limiters of every rate-limited endpoint (separate
// bucket sets, IPv6 tiers scaled by ratelimit.Scale56/Scale48, plus the global
// authorize ceiling), or nil when rate limiting is disabled. Zero config
// values mean the defaults, so a Config that skipped config.Parse still gets
// limits.
func newLimiters(rl config.RateLimit, codeTTL time.Duration, now func() time.Time) map[string]*ratelimit.Limiter {
	if rl.Disabled {
		return nil
	}
	g := rl.AuthorizeGlobal
	rl = rl.Resolved()
	mk := func(l config.Limit, scale int) *ratelimit.Limiter {
		return ratelimit.New(l.PerMinute*scale, l.Burst*scale, ratelimit.WithClock(now))
	}
	m := make(map[string]*ratelimit.Limiter, 13)
	for name, l := range map[string]config.Limit{"register": rl.Register, authorizeKey: rl.Authorize, "token": rl.Token, formKey: rl.AuthorizeForm} {
		m[name] = mk(l, 1)
		m[name+tier56] = mk(l, ratelimit.Scale56)
		m[name+tier48] = mk(l, ratelimit.Scale48)
	}
	d := globalAuthorizeDefault(codeTTL)
	if g.PerMinute == 0 {
		g.PerMinute = d.PerMinute
	}
	if g.Burst == 0 {
		g.Burst = g.PerMinute
	}
	m[globalKey] = mk(g, 1)
	return m
}

// limit is limitMethod for POST requests: only POSTs are counted, other
// methods pass through (cheap 405s).
func (s *Server) limit(name string, deny func(w http.ResponseWriter, r *http.Request), next http.Handler) http.Handler {
	return s.limitMethod(name, http.MethodPost, deny, next)
}

// limitMethod wraps next with the per-IP limiter named name, counting only
// requests of the given method (HEAD counts as GET).
// A client is charged at every tier of its address (see ratelimit.Keys); the
// request passes only if all allow it, and a refused one costs no tokens. A
// denied request gets 429 with Retry-After via deny. The global authorize
// ceiling is not charged here but by chargeGlobalAuthorize, once a submission
// is about to get a code.
func (s *Server) limitMethod(name, method string, deny func(w http.ResponseWriter, r *http.Request), next http.Handler) http.Handler {
	lim := s.limits[name]
	if lim == nil {
		return next
	}
	tiers := []*ratelimit.Limiter{lim, s.limits[name+tier56], s.limits[name+tier48]}
	if tiers[1] == nil || tiers[2] == nil { // hand-built maps in tests
		tiers = tiers[:1]
	}
	if name == authorizeKey {
		s.warnGlobalOversized()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := r.Method
		if m == http.MethodHead {
			m = http.MethodGet
		}
		if m != method {
			next.ServeHTTP(w, r)
			return
		}
		ip := s.clientIP(r)
		keys := ratelimit.Keys(ip)
		ok, wait := ratelimit.Charge(tiers, keys)
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

// chargeGlobalAuthorize takes one token from the unkeyed ceiling on code
// issuance. It is called by the authorize submit handler right before a code is
// sealed, i.e. only for submissions that passed parsing, the size budget, the
// allow-list and the upstream check, so requests that can never yield a code
// cannot exhaust it. When the ceiling is empty it sets Retry-After on w and
// returns false: the caller answers 429 like the per-IP limit does. Each
// submission is charged at most once (it is the only call site).
func (s *Server) chargeGlobalAuthorize(w http.ResponseWriter) bool {
	global := s.limits[globalKey]
	if global == nil {
		return true
	}
	ok, wait := global.Allow("")
	if ok {
		return true
	}
	if n := global.TakeDenied(s.now(), globalLogInterval); n > 0 {
		// Counts only; the clients are not identifiable (and not at fault).
		s.log.Warn("global authorize ceiling reached; delaying new logins",
			"endpoint", authorizeKey, "denied_since_last_log", n, "retry_after", wait.String())
	}
	w.Header().Set("Retry-After", retryAfterSeconds(wait))
	return false
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

func (s *Server) denyAuthorize(w http.ResponseWriter, r *http.Request) {
	s.writeErrorPage(w, http.StatusTooManyRequests, uiMsg(msgTooManyRequests))
}
