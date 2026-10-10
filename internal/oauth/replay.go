package oauth

import (
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
	// refresh token expires (30 days by default). About 120 bytes each bounds
	// it near 12 MiB; a legitimate deployment has a handful of chains.
	maxFamilyEntries = 100_000

	// Sweep cadence: a full scan is O(n), so it runs at most once a minute
	// normally and at most once a second while the cache is full.
	sweepInterval     = time.Minute
	fullSweepInterval = time.Second
)

var (
	// errReplayed means the id was already redeemed.
	errReplayed = errors.New("already used")
	// errReplayCacheFull means no live entry could be evicted. Callers must
	// fail closed: accepting the token untracked would allow replay.
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
	usedGen int64     // highest generation redeemed so far
	exp     time.Time // expiry of the newest token issued in the chain
	revoked bool
}

// familyCache enforces single-use refresh tokens with reuse detection, one
// entry per chain rather than per token (so a refresh loop cannot grow it).
// Like replayCache it is per-process and forgets everything on restart.
type familyCache struct {
	mu    sync.Mutex
	seen  map[string]*family
	sweep sweeper
	limit int
}

func newFamilyCache(limit int) *familyCache {
	return &familyCache{seen: make(map[string]*family), limit: limit}
}

// use redeems generation gen of family id and extends the family's lifetime
// to newExp (the expiry of the successor being issued). Atomically:
//   - revoked family: errFamilyRevoked;
//   - gen <= highest used generation: a reuse, so the whole family is revoked
//     (kept until its expiry) and errFamilyRevoked is returned;
//   - otherwise gen is recorded as used.
//
// A family with no live entry is accepted as new, which is why a restart
// reopens a window. errReplayCacheFull is returned when a new entry is needed
// and the cache is full of live ones. The boolean reports a reuse detection
// (as opposed to an earlier revocation) for logging.
func (c *familyCache) use(id string, gen int64, newExp, now time.Time) (reuse bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	f, ok := c.seen[id]
	if ok && !now.Before(f.exp) {
		delete(c.seen, id) // dead: all its tokens are expired by now
		f, ok = nil, false
	}
	if ok {
		switch {
		case f.revoked:
			return false, errFamilyRevoked
		case gen <= f.usedGen:
			f.revoked = true
			return true, errFamilyRevoked
		}
		f.usedGen = gen
		if newExp.After(f.exp) { // never shorten: older tokens may outlive newExp
			f.exp = newExp
		}
		return false, nil
	}
	if c.sweep.due(now, len(c.seen) >= c.limit) {
		for k, v := range c.seen {
			if !now.Before(v.exp) {
				delete(c.seen, k)
			}
		}
	}
	if len(c.seen) >= c.limit {
		return false, errReplayCacheFull
	}
	c.seen[id] = &family{usedGen: gen, exp: newExp}
	return false, nil
}
