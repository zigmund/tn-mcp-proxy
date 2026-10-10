package proxy

import (
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/zigmund/tn-mcp-proxy/internal/config"
	"github.com/zigmund/tn-mcp-proxy/internal/credcheck"
)

// Re-check cost control. A tool error only triggers a credential re-check; the
// re-check is an MCP session with the upstream (initialize, initialized,
// tools/call, DELETE), so it is cached, deduplicated and capped.
const (
	// recheckTTL is how long an accepted or rejected verdict is reused. A burst
	// of tool errors from one token costs at most one check per TTL.
	recheckTTL = 60 * time.Second
	// unavailableTTL remembers "no verdict" for as long as a real verdict, so
	// during an upstream outage a failing token still costs at most one check
	// session per minute (saturation, which is not cached, aside). The price is
	// that a revocation is noticed up to a minute after the upstream recovers.
	unavailableTTL = recheckTTL
	// maxRecheckEntries bounds the verdict cache (about 100 bytes each).
	maxRecheckEntries = 4096
	// maxConcurrentRechecks bounds simultaneous upstream check sessions. When
	// saturated a re-check is skipped and the response passes through.
	maxConcurrentRechecks = 8
)

type verdict int

const (
	verdictUnknown  verdict = iota // no answer: outage, timeout, saturation, client gone
	verdictOK                      // the upstream accepts the credentials
	verdictRejected                // the upstream refuses the credentials
)

type cacheEntry struct {
	key     [sha256.Size]byte
	v       verdict
	expires time.Time
}

// flight is one in-progress check shared by concurrent callers.
type flight struct {
	done chan struct{}
	v    verdict // valid after done is closed
}

// Rechecker decides whether credentials are still accepted by an upstream. It
// is safe for concurrent use and shared by all upstream handlers of a server.
// State is in memory only and bounded: a verdict cache keyed by an HMAC of the
// upstream name and credentials (plaintext credentials are never retained or
// logged), one in-flight check per key, and a global cap on concurrent checks.
type Rechecker struct {
	checker *credcheck.Checker
	version string // reported to upstreams by the checker
	log     *slog.Logger
	now     func() time.Time
	macKey  [32]byte
	sem     chan struct{}

	mu      sync.Mutex
	cache   map[[sha256.Size]byte]*list.Element // values are *cacheEntry
	order   *list.List                          // oldest insertion first
	flights map[[sha256.Size]byte]*flight
}

// RecheckerOption configures a Rechecker.
type RecheckerOption func(*Rechecker)

// WithRecheckerVersion sets the binary version the re-check requests report
// to the upstream (User-Agent and MCP clientInfo). An empty version means "dev".
func WithRecheckerVersion(v string) RecheckerOption {
	return func(r *Rechecker) { r.version = v }
}

// NewRechecker returns a Rechecker with its own credential checker. A nil log
// means slog.Default().
func NewRechecker(log *slog.Logger, opts ...RecheckerOption) *Rechecker {
	if log == nil {
		log = slog.Default()
	}
	r := &Rechecker{
		log:     log,
		now:     time.Now,
		sem:     make(chan struct{}, maxConcurrentRechecks),
		cache:   map[[sha256.Size]byte]*list.Element{},
		order:   list.New(),
		flights: map[[sha256.Size]byte]*flight{},
	}
	for _, o := range opts {
		o(r)
	}
	r.checker = credcheck.New(r.version)
	_, _ = rand.Read(r.macKey[:]) // never fails since Go 1.24 (it aborts the program instead)
	return r
}

// cacheKey is HMAC-SHA256(upstream name, canonical credentials) under a
// per-process random key, so the cache never holds plaintext credentials.
func (r *Rechecker) cacheKey(name string, creds map[string]string) [sha256.Size]byte {
	keys := make([]string, 0, len(creds))
	canon := make(map[string]string, len(creds))
	for k, v := range creds {
		ck := http.CanonicalHeaderKey(k)
		canon[ck] = v
		keys = append(keys, ck)
	}
	sort.Strings(keys)
	m := hmac.New(sha256.New, r.macKey[:])
	write := func(s string) {
		// Length-prefixed so that field boundaries are unambiguous.
		var n [8]byte
		l := uint64(len(s))
		for i := range n {
			n[i] = byte(l >> (8 * i))
		}
		m.Write(n[:])
		m.Write([]byte(s))
	}
	write(name)
	for _, k := range keys {
		write(k)
		write(canon[k])
	}
	var out [sha256.Size]byte
	m.Sum(out[:0])
	return out
}

// recheck returns the upstream's verdict on creds. Anything but a clear answer
// is verdictUnknown and the caller must leave the response alone. ctx is the
// client request's context: if it ends while waiting, the caller gives up but a
// started check runs on (bounded by validate.timeout) for the benefit of later
// callers.
func (r *Rechecker) recheck(ctx context.Context, up config.Upstream, creds map[string]string) verdict {
	if up.Validate == nil {
		return verdictUnknown
	}
	key := r.cacheKey(up.Name, creds)

	r.mu.Lock()
	if el, ok := r.cache[key]; ok {
		e := el.Value.(*cacheEntry)
		if r.now().Before(e.expires) {
			r.mu.Unlock()
			r.log.Debug("credential recheck cached", "upstream", up.Name)
			return e.v
		}
		r.removeLocked(el)
	}
	f, running := r.flights[key]
	if !running {
		select {
		case r.sem <- struct{}{}:
			f = &flight{done: make(chan struct{})}
			r.flights[key] = f
		default:
			r.mu.Unlock()
			r.log.Debug("credential recheck skipped: too many concurrent checks", "upstream", up.Name)
			return verdictUnknown
		}
	}
	r.mu.Unlock()

	if !running {
		// Detached from the client: the check must not be cut short by one
		// caller leaving, as others may be waiting on it. The checker bounds it.
		go r.run(context.WithoutCancel(ctx), up, creds, key, f)
	}
	select {
	case <-f.done:
		return f.v
	case <-ctx.Done():
		return verdictUnknown
	}
}

// Rejected reports whether a live cached verdict says the upstream refuses
// creds. It only reads the cache (keyed exactly like recheck): it never
// contacts the upstream, starts a check or waits for one, so it is cheap
// enough for the token endpoint. No entry, an expired entry, "accepted" and
// "no verdict" all answer false.
func (r *Rechecker) Rejected(upstream string, creds map[string]string) bool {
	key := r.cacheKey(upstream, creds)
	r.mu.Lock()
	defer r.mu.Unlock()
	el, ok := r.cache[key]
	if !ok {
		return false
	}
	e := el.Value.(*cacheEntry)
	return e.v == verdictRejected && r.now().Before(e.expires)
}

// run executes one check, publishes its verdict and releases the slot.
func (r *Rechecker) run(ctx context.Context, up config.Upstream, creds map[string]string, key [sha256.Size]byte, f *flight) {
	err := r.checker.Check(ctx, up, creds)
	ttl := recheckTTL
	switch {
	case err == nil:
		f.v = verdictOK
		r.log.Debug("credential recheck accepted", "upstream", up.Name)
	case errors.Is(err, credcheck.ErrRejected):
		f.v = verdictRejected
		r.log.Debug("credential recheck rejected", "upstream", up.Name)
	default:
		f.v = verdictUnknown
		ttl = unavailableTTL
		var ce *credcheck.CheckError
		attrs := []any{"upstream", up.Name}
		if errors.As(err, &ce) {
			// Fixed vocabulary only: never credentials or upstream text.
			attrs = append(attrs, "step", ce.Step, "reason", ce.Reason)
			if ce.Cause != nil {
				attrs = append(attrs, "err", ce.Cause)
			}
		}
		r.log.Warn("credential recheck unavailable", attrs...)
	}

	r.mu.Lock()
	delete(r.flights, key)
	e := &cacheEntry{key: key, v: f.v, expires: r.now().Add(ttl)}
	for r.order.Len() >= maxRecheckEntries {
		r.removeLocked(r.order.Front())
	}
	r.cache[key] = r.order.PushBack(e)
	r.mu.Unlock()
	<-r.sem
	close(f.done)
}

func (r *Rechecker) removeLocked(el *list.Element) {
	e := r.order.Remove(el).(*cacheEntry)
	delete(r.cache, e.key)
}
