package oauth

import (
	"container/list"
	"errors"
	"sync"
	"time"
)

const (
	// maxReplayEntries caps the used-code cache. Anyone can mint codes
	// through open DCR plus the credentials form, so the cache must not grow
	// with attacker effort. An entry is a ~22-byte key plus a timestamp
	// (under 100 bytes with map overhead), so the cap bounds it near 5 MiB.
	// It is a constant rather than config on purpose: it protects the
	// process and has no sensible tuning other than "bigger than legitimate
	// traffic", which is a handful of live codes at any moment.
	maxReplayEntries = 50_000

	// maxFamilyEntries caps the refresh-token family cache: one entry per
	// login chain that has refreshed at least once, living until its newest
	// refresh token expires (30 days by default) or until evicted as the
	// least recently used when full. About 200 bytes each (including the
	// list element) bounds it near 20 MiB; a legitimate deployment has a
	// handful of chains.
	maxFamilyEntries = 100_000

	// Sweep cadence: a full scan is O(n), so it runs at most once a minute
	// normally and at most once a second while a fail-closed cache is full.
	sweepInterval     = time.Minute
	fullSweepInterval = time.Second
)

var (
	// errReplayed means the id was already redeemed.
	errReplayed = errors.New("already used")
	// errReplayCacheFull means the code cache holds only live entries.
	// Callers must fail closed: accepting the token untracked would allow replay.
	errReplayCacheFull = errors.New("replay cache full")
	// errFamilyRevoked means the refresh token family is revoked, either
	// just now by a reuse or earlier.
	errFamilyRevoked = errors.New("refresh token family revoked")
)

// sweeper decides when a full O(n) prune is due.
type sweeper struct{ last time.Time }

func (w *sweeper) due(now time.Time, full bool) bool {
	interval := sweepInterval
	if full {
		interval = fullSweepInterval
	}
	if now.Sub(w.last) < interval {
		return false
	}
	w.last = now
	return true
}

// replayCache remembers redeemed authorization code ids until the codes
// would have expired anyway (after which the seal envelope rejects them), so
// each code can be exchanged once. It is in-memory and per-process: a restart
// forgets it, which lets a not-yet-expired code be redeemed again within
// oauth.code_ttl (PKCE still binds it to the original client).
type replayCache struct {
	mu    sync.Mutex
	seen  map[string]time.Time // code id -> code expiry
	sweep sweeper
	limit int
}

func newReplayCache(limit int) *replayCache {
	return &replayCache{seen: make(map[string]time.Time), limit: limit}
}

// claim records id as redeemed until exp (the code's own expiry). It returns
// errReplayed if id is already recorded and live, and errReplayCacheFull if
// the cache holds limit live entries. Expired entries are pruned lazily
// here. An entry is dead at now >= exp, the same instant the seal envelope
// starts rejecting the code.
func (c *replayCache) claim(id string, exp, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if until, ok := c.seen[id]; ok && now.Before(until) {
		return errReplayed
	}
	if c.sweep.due(now, len(c.seen) >= c.limit) {
		for k, until := range c.seen {
			if !now.Before(until) {
				delete(c.seen, k)
			}
		}
	}
	if _, exists := c.seen[id]; !exists && len(c.seen) >= c.limit {
		return errReplayCacheFull
	}
	c.seen[id] = exp
	return nil
}

// family is the state of one refresh token chain (one login).
type family struct {
	id      string
	usedGen int64     // highest generation redeemed so far
	exp     time.Time // expiry of the newest token issued in the chain
	revoked bool
	elem    *list.Element // position in the active or revoked LRU list
}

// familyCache enforces single-use refresh tokens with reuse detection, one
// entry per chain rather than per token (so a refresh loop cannot grow it).
// Like replayCache it is per-process and forgets everything on restart.
//
// Unlike replayCache it never fails closed: when full it evicts. Anyone can
// mint logins (the authorize form accepts any credentials), so a full cache
// must not lock legitimate users out for the refresh TTL. Each entry sits in
// one of two intrusive LRU lists (front = most recently used):
//   - active: evicted first, least recently used first. "Used" means created,
//     successfully refreshed, or (for revoked ones) presented again;
//   - revoked: evicting one re-opens its stolen tokens, so they go last. The
//     list is capped at revokedLimit (10% of limit, at least 1) so revoked
//     entries cannot starve the active set; beyond it the least recently
//     used revoked entry is dropped. When the cache holds nothing but revoked
//     entries, the least recently used of those is evicted for a new family.
//
// Every operation is O(1) amortized under the mutex: a hash lookup, a list
// move or pop, plus the rate-limited O(n) expiry sweep (at most once a
// minute) that removes dead entries.
//
// Accepted trade-off: reuse detection is lost for an evicted chain. A rotated
// (old) refresh token of an evicted family is accepted once as a new family,
// exactly as after a restart.
type familyCache struct {
	mu           sync.Mutex
	seen         map[string]*family
	active       *list.List
	revoked      *list.List
	sweep        sweeper
	limit        int
	revokedLimit int

	// Eviction accounting for rate-limited logging, see takeEvictions.
	evicted        int
	evictedRevoked int
	lastReport     time.Time
}

func newFamilyCache(limit int) *familyCache {
	limit = max(1, limit)
	return &familyCache{
		seen: make(map[string]*family), active: list.New(), revoked: list.New(),
		limit: limit, revokedLimit: max(1, limit/10),
	}
}

// evictionReportInterval bounds how often evictions are logged.
const evictionReportInterval = time.Minute

// takeEvictions returns the number of evictions since the last report (and
// how many of them were revoked families) at most once per
// evictionReportInterval, and zero otherwise (the count keeps accumulating).
func (c *familyCache) takeEvictions(now time.Time) (n, revoked int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.evicted == 0 || now.Sub(c.lastReport) < evictionReportInterval {
		return 0, 0
	}
	n, revoked = c.evicted, c.evictedRevoked
	c.evicted, c.evictedRevoked, c.lastReport = 0, 0, now
	return n, revoked
}

// remove drops f from the map and its list.
func (c *familyCache) remove(f *family) {
	if f.revoked {
		c.revoked.Remove(f.elem)
	} else {
		c.active.Remove(f.elem)
	}
	delete(c.seen, f.id)
}

// evict drops the least recently used entry of l, counting it.
func (c *familyCache) evict(l *list.List) {
	c.remove(l.Back().Value.(*family))
	c.evicted++
	if l == c.revoked {
		c.evictedRevoked++
	}
}

// use redeems generation gen of family id and extends the family's lifetime
// to newExp (the expiry of the successor being issued). Atomically:
//   - revoked family: errFamilyRevoked;
//   - gen <= highest used generation: a reuse, so the whole family is revoked
//     (kept until its expiry) and errFamilyRevoked is returned;
//   - otherwise gen is recorded as used.
//
// A family with no live entry is accepted as new, which is why a restart or
// an eviction reopens a window; a full cache evicts to make room, so the only
// error is errFamilyRevoked (nil otherwise). The boolean reports a reuse
// detection (as opposed to an earlier revocation) for logging.
func (c *familyCache) use(id string, gen int64, newExp, now time.Time) (reuse bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	f, ok := c.seen[id]
	if ok && !now.Before(f.exp) {
		c.remove(f) // dead: all its tokens are expired by now
		f, ok = nil, false
	}
	if ok {
		switch {
		case f.revoked:
			c.revoked.MoveToFront(f.elem)
			return false, errFamilyRevoked
		case gen <= f.usedGen:
			f.revoked = true
			c.active.Remove(f.elem)
			f.elem = c.revoked.PushFront(f)
			if c.revoked.Len() > c.revokedLimit {
				c.evict(c.revoked) // never the one just pushed: Len > limit >= 1
			}
			return true, errFamilyRevoked
		}
		f.usedGen = gen
		if newExp.After(f.exp) { // never shorten: older tokens may outlive newExp
			f.exp = newExp
		}
		c.active.MoveToFront(f.elem)
		return false, nil
	}
	if c.sweep.due(now, false) {
		for _, v := range c.seen {
			if !now.Before(v.exp) {
				c.remove(v)
			}
		}
	}
	if len(c.seen) >= c.limit {
		if c.active.Len() > 0 {
			c.evict(c.active)
		} else {
			c.evict(c.revoked)
		}
	}
	f = &family{id: id, usedGen: gen, exp: newExp}
	f.elem = c.active.PushFront(f)
	c.seen[id] = f
	return false, nil
}
