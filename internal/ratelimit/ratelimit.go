// Package ratelimit implements a small keyed token-bucket limiter with a
// bounded key map. It has no background goroutines: idle entries are evicted
// lazily when the map is full.
package ratelimit

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

const (
	// DefaultMaxKeys bounds the number of tracked keys.
	DefaultMaxKeys = 10_000

	// sweepInterval is the minimum time between full scans for refilled
	// entries; it keeps a flood of new keys from costing O(n) per request.
	sweepInterval = time.Minute
)

// Limiter is a set of token buckets, one per key. Each bucket holds up to
// burst tokens and refills at perMinute tokens per minute; a request takes one
// token. It is safe for concurrent use.
//
// The key map never exceeds the configured maximum. When it is full, entries
// whose bucket has fully refilled are dropped (they are indistinguishable from
// new ones); if it is still full, the least recently seen key is evicted. So a
// new key is always admitted with a full bucket: the limiter neither fails
// closed nor grows without bound, at the price that a flood of distinct keys
// can reset the buckets of the oldest ones.
type Limiter struct {
	rate   float64 // tokens per second
	burst  float64
	maxKey int
	now    func() time.Time

	mu        sync.Mutex
	entries   map[string]*list.Element // value: *entry
	lru       *list.List               // front = most recently seen
	lastSweep time.Time
}

type entry struct {
	key    string
	tokens float64
	last   time.Time
}

// Option configures a Limiter.
type Option func(*Limiter)

// WithClock overrides the time source (for tests).
func WithClock(now func() time.Time) Option { return func(l *Limiter) { l.now = now } }

// WithMaxKeys overrides the key bound; values below 1 are ignored.
func WithMaxKeys(n int) Option {
	return func(l *Limiter) {
		if n >= 1 {
			l.maxKey = n
		}
	}
}

// New returns a Limiter allowing perMinute requests per minute per key with
// bursts of up to burst. Both must be positive; smaller values are raised to 1.
func New(perMinute, burst int, opts ...Option) *Limiter {
	l := &Limiter{
		rate:    float64(max(perMinute, 1)) / 60,
		burst:   float64(max(burst, 1)),
		maxKey:  DefaultMaxKeys,
		now:     time.Now,
		entries: make(map[string]*list.Element),
		lru:     list.New(),
	}
	for _, o := range opts {
		o(l)
	}
	return l
}

// Allow takes one token for key. When none is available it returns false and
// how long to wait until one is.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	el, found := l.entries[key]
	if !found {
		l.makeRoom(now)
		el = l.lru.PushFront(&entry{key: key, tokens: l.burst, last: now})
		l.entries[key] = el
	} else {
		l.lru.MoveToFront(el)
	}
	e := el.Value.(*entry) //nolint:forcetypeassert // only *entry is stored
	l.refill(e, now)
	if e.tokens >= 1 {
		e.tokens--
		return true, 0
	}
	wait := time.Duration((1 - e.tokens) / l.rate * float64(time.Second))
	return false, max(wait, time.Millisecond)
}

// Len returns the number of tracked keys.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func (l *Limiter) refill(e *entry, now time.Time) {
	if d := now.Sub(e.last); d > 0 {
		e.tokens = min(l.burst, e.tokens+d.Seconds()*l.rate)
	}
	e.last = now // a clock step back only delays the refill
}

// makeRoom frees one slot when the map is full. Caller holds mu.
func (l *Limiter) makeRoom(now time.Time) {
	if len(l.entries) < l.maxKey {
		return
	}
	if now.Sub(l.lastSweep) >= sweepInterval || now.Before(l.lastSweep) {
		l.lastSweep = now
		for el := l.lru.Back(); el != nil; {
			prev := el.Prev()
			e := el.Value.(*entry) //nolint:forcetypeassert // only *entry is stored
			if e.tokens+now.Sub(e.last).Seconds()*l.rate >= l.burst {
				l.remove(el)
			}
			el = prev
		}
		if len(l.entries) < l.maxKey {
			return
		}
	}
	if el := l.lru.Back(); el != nil {
		l.remove(el)
	}
}

func (l *Limiter) remove(el *list.Element) {
	e := el.Value.(*entry) //nolint:forcetypeassert // only *entry is stored
	delete(l.entries, e.key)
	l.lru.Remove(el)
}

// Key maps a client IP (as text) to a limiter key: IPv4 and IPv4-mapped IPv6
// addresses map to themselves, other IPv6 addresses to their /64 prefix, since
// one attacker typically controls a whole /64. Text that is not an IP is
// returned unchanged.
func Key(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	p, err := a.Prefix(64)
	if err != nil { // unreachable: 64 is valid for IPv6
		return a.String()
	}
	return p.String()
}
