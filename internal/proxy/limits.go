package proxy

import (
	"crypto/sha256"
	"log/slog"
	"math"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/httplog"
	"github.com/zigmund/tn-mcp-proxy/internal/ratelimit"
)

// limitLogInterval bounds how often a limit being hit is logged above debug.
const limitLogInterval = time.Minute

// Limits enforces the limits of config.ProxyLimits on proxied requests. One
// value is shared by all upstream handlers (WithLimits), so the per-IP budget
// and the global in-flight cap span upstreams; per-token state is keyed by
// grant, which includes the upstream name.
//
// A nil limiter or slot pool means that limit is off.
type Limits struct {
	cfg      config.ProxyLimits
	log      *slog.Logger
	now      func() time.Time
	clientIP func(*http.Request) string

	ip       []*ratelimit.Limiter // /32 or /64, /56, /48 tiers; nil when off
	token    *ratelimit.Limiter
	perToken *ratelimit.Concurrency
	global   *ratelimit.Concurrency
}

// LimitsOption configures NewLimits.
type LimitsOption func(*Limits)

// WithClientIP sets the client IP resolver used for the per-IP limit. The
// default trusts loopback peers only; the server passes the resolver built
// from trusted_proxies so the limiter and the access log agree.
func WithClientIP(fn func(*http.Request) string) LimitsOption {
	return func(l *Limits) {
		if fn != nil {
			l.clientIP = fn
		}
	}
}

// WithLimitsClock overrides the time source (for tests).
func WithLimitsClock(now func() time.Time) LimitsOption {
	return func(l *Limits) { l.now = now }
}

// NewLimits builds the limiters for cfg. Zero values mean the defaults (see
// config.ProxyLimits.Resolved), so a hand-built config still gets limits.
func NewLimits(cfg config.ProxyLimits, log *slog.Logger, opts ...LimitsOption) *Limits {
	if log == nil {
		log = slog.Default()
	}
	l := &Limits{cfg: cfg.Resolved(), log: log, now: time.Now, clientIP: httplog.ClientIP}
	for _, o := range opts {
		o(l)
	}
	c := l.cfg
	mk := func(lim config.Limit, scale int) *ratelimit.Limiter {
		return ratelimit.New(lim.PerMinute*scale, lim.Burst*scale, ratelimit.WithClock(l.now))
	}
	if c.IP.PerMinute > 0 {
		// Same tiers as the OAuth endpoints: an IPv6 client is also charged
		// against its /56 and /48 with proportionally larger budgets.
		l.ip = []*ratelimit.Limiter{mk(c.IP, 1), mk(c.IP, ratelimit.Scale56), mk(c.IP, ratelimit.Scale48)}
	}
	if c.Token.PerMinute > 0 {
		l.token = mk(c.Token, 1)
	}
	if c.MaxConcurrentPerToken > 0 {
		l.perToken = ratelimit.NewConcurrency(c.MaxConcurrentPerToken)
	}
	if c.MaxInFlight > 0 {
		l.global = ratelimit.NewConcurrency(c.MaxInFlight)
	}
	return l
}

// maxBody returns the request body cap in bytes.
func (l *Limits) maxBody() int64 { return int64(l.cfg.MaxRequestBody) }

// maxConns returns the Transport.MaxConnsPerHost value: the global in-flight
// cap, or 0 (unlimited) when that is off. Each in-flight request uses at most
// one connection, so with the cap enforced first the transport never queues.
func (l *Limits) maxConns() int { return max(l.cfg.MaxInFlight, 0) }

// chargeIP takes one token per tier for the client IP, before the bearer token
// is opened, so garbage and unauthenticated floods are rejected cheaply. It
// returns the keys to refund if a later check refuses the request. On denial
// it writes the 429.
func (l *Limits) chargeIP(w http.ResponseWriter, r *http.Request) (keys []string, ok bool) {
	if l.ip == nil {
		return nil, true
	}
	ip := l.clientIP(r)
	keys = ratelimit.Keys(ip)
	ok, wait := ratelimit.Charge(l.ip, keys)
	if ok {
		return keys, true
	}
	// Client IP only: never the query, headers or body.
	l.log.Debug("proxy rate limit exceeded", "limit", "ip", "remote", ip, "retry_after", wait.String())
	l.reportDenied("ip", l.ip[0])
	l.tooMany(w, wait)
	return nil, false
}

func (l *Limits) refundIP(keys []string) {
	for i := range min(len(l.ip), len(keys)) {
		l.ip[i].Refund(keys[i])
	}
}

// admit runs the checks that need the authenticated grant, in this order:
// per-grant rate, per-grant concurrency, global in-flight cap. Each later
// check that refuses the request gives back what the earlier ones took (the
// IP tokens passed in as ipKeys included), so a refused request costs nothing
// and never holds a slot. On success the returned release must be called when
// the response (a held SSE stream included) has finished. On denial admit has
// written the response.
func (l *Limits) admit(w http.ResponseWriter, ipKeys []string, grant string) (release func(), ok bool) {
	if l.token != nil {
		if ok, wait := l.token.Allow(grant); !ok {
			l.refundIP(ipKeys)
			l.log.Debug("proxy rate limit exceeded", "limit", "token", "retry_after", wait.String())
			l.reportDenied("token", l.token)
			l.tooMany(w, wait)
			return nil, false
		}
	}
	undo := func() {
		if l.token != nil {
			l.token.Refund(grant)
		}
		l.refundIP(ipKeys)
	}
	var relTok, relGlobal func()
	if l.perToken != nil {
		var ok bool
		if relTok, ok = l.perToken.Acquire(grant); !ok {
			undo()
			l.log.Debug("proxy concurrency limit exceeded", "limit", "token_concurrency")
			l.reportConcurrencyDenied("token_concurrency", l.perToken)
			l.tooMany(w, time.Second)
			return nil, false
		}
	}
	if l.global != nil {
		var ok bool
		if relGlobal, ok = l.global.Acquire(""); !ok {
			if relTok != nil {
				relTok()
			}
			undo()
			l.log.Debug("proxy in-flight cap reached", "limit", "max_in_flight")
			l.reportConcurrencyDenied("max_in_flight", l.global)
			w.Header().Set("Retry-After", "1")
			http.Error(w, "server busy", http.StatusServiceUnavailable)
			return nil, false
		}
	}
	return func() {
		if relGlobal != nil {
			relGlobal()
		}
		if relTok != nil {
			relTok()
		}
	}, true
}

func (l *Limits) tooMany(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", retryAfterSeconds(wait))
	http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
}

// reportDenied logs, at most once a minute per limit and with a count only
// (the clients are not identified), that a rate limit refused requests.
func (l *Limits) reportDenied(name string, lim *ratelimit.Limiter) {
	if n := lim.TakeDenied(l.now(), limitLogInterval); n > 0 {
		l.log.Warn("proxy rate limit refused requests", "limit", name, "denied_since_last_log", n)
	}
}

func (l *Limits) reportConcurrencyDenied(name string, c *ratelimit.Concurrency) {
	if n := c.TakeDenied(l.now(), limitLogInterval); n > 0 {
		l.log.Warn("proxy concurrency limit refused requests", "limit", name, "denied_since_last_log", n)
	}
}

// retryAfterSeconds renders d as whole seconds, rounded up, at least 1.
func retryAfterSeconds(d time.Duration) string {
	return strconv.Itoa(max(1, int(math.Ceil(d.Seconds()))))
}

// grantKey identifies a grant for the per-token limits without using (or
// retaining) the bearer token or any credential value as a key: a SHA-256 over
// the upstream name and the credential headers the proxy injects. It is
// stable across access token refreshes and independent of client_id, so
// registering more OAuth clients (dynamic client registration is open) does
// not buy a fresh budget for the same credentials. Access tokens carry no
// refresh family id, and adding one would change the token format. The value
// is binary, held only in memory, and never logged.
func grantKey(upstream string, creds map[string]string) string {
	h := sha256.New()
	field := func(s string) {
		var n [8]byte
		for i, v := 0, uint64(len(s)); i < 8; i, v = i+1, v>>8 {
			n[i] = byte(v)
		}
		h.Write(n[:]) // length prefix: no ambiguity between adjacent fields
		h.Write([]byte(s))
	}
	field(upstream)
	names := make([]string, 0, len(creds))
	for k := range creds {
		names = append(names, k)
	}
	slices.Sort(names)
	for _, k := range names {
		field(k)
		field(creds[k])
	}
	return string(h.Sum(nil))
}
