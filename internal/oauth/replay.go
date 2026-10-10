package oauth

import (
	"container/list"
	"errors"
	"hash/maphash"
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

	// maxRevocationEntries caps the revoked-family set. An entry is an 8-byte
	// hash plus an 8-byte expiry (about 40 bytes with map overhead, so the cap
	// bounds it near 40 MiB). Entries are only ever dropped at their natural
	// expiry, never to make room: see revocationSet.
	maxRevocationEntries = 1_000_000

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
	// errRevocationsFull means the revoked-family set holds only live
	// entries, so an unknown family cannot be told apart from a revoked one
	// whose record is gone. Callers must fail closed.
	errRevocationsFull = errors.New("revocation set full")
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

// fullCounter rate-limits the log line for a cache refusing requests: callers
// count every refusal and log only when take reports a non-zero count.
type fullCounter struct {
	mu   sync.Mutex
	n    int
	last time.Time
}

// take counts one refusal and returns the number accumulated since the last
// report when one is due (at most once per evictionReportInterval), else 0.
func (f *fullCounter) take(now time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if now.Sub(f.last) < evictionReportInterval {
		return 0
	}
	n := f.n
	f.n, f.last = 0, now
	return n
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
	full  fullCounter
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

// revocationSet remembers revoked refresh families by an 8-byte hash of the
// family id until the family's own expiry (after which none of its tokens
// opens anyway). It is separate from familyCache's LRU on purpose: revocations
// are the only state whose loss re-opens stolen tokens, so attacker-created
// families (which only evict LRU entries) must not be able to push one out.
// Entries are dropped only when expired, never to make room; when the set is
// full of live entries, add reports false and familyCache fails closed for
// unknown families instead. Not safe for concurrent use: the caller holds
// familyCache.mu.
//
// The 64-bit hash is keyed per process (maphash), and family ids are 128-bit
// random values sealed inside tokens, so a collision, which would wrongly
// revoke one login, is negligible at this size (about 1e6/2^64 per new family).
type revocationSet struct {
	seed  maphash.Seed
	exp   map[uint64]int64 // hash -> expiry, Unix seconds
	sweep sweeper
	limit int
}

func newRevocationSet(limit int) *revocationSet {
	return &revocationSet{seed: maphash.MakeSeed(), exp: make(map[uint64]int64), limit: max(1, limit)}
}

func (r *revocationSet) hash(id string) uint64 { return maphash.String(r.seed, id) }

// has reports whether h is revoked and not yet expired.
func (r *revocationSet) has(h uint64, now time.Time) bool {
	e, ok := r.exp[h]
	return ok && now.Unix() < e
}

// prune drops expired entries, at most once a minute (once a second while
// the set is at its limit).
func (r *revocationSet) prune(now time.Time) {
	if !r.sweep.due(now, len(r.exp) >= r.limit) {
		return
	}
	for k, e := range r.exp {
		if now.Unix() >= e {
			delete(r.exp, k)
		}
	}
}

// full reports whether no live entry can be added.
func (r *revocationSet) full(now time.Time) bool {
	r.prune(now)
	return len(r.exp) >= r.limit
}

// add records h as revoked until exp (never shortening an existing entry).
// It reports false, recording nothing, when the set is full of live entries.
func (r *revocationSet) add(h uint64, exp, now time.Time) bool {
	r.prune(now)
	if e, ok := r.exp[h]; ok {
		r.exp[h] = max(e, exp.Unix())
		return true
	}
	if len(r.exp) >= r.limit {
		return false
	}
	r.exp[h] = exp.Unix()
	return true
}

// family is the state of one active refresh token chain (one login).
type family struct {
	id      string
	usedGen int64     // highest generation redeemed so far
	exp     time.Time // expiry of the newest token issued in the chain
	// revoked marks a family whose reuse could not be recorded in the
	// revocation set because that was full. It sits in the flagged list, is
	// never evicted for room, and moves to the set once that has room (or
	// is dropped at its expiry).
	revoked bool
	elem    *list.Element // position in the active or flagged list
}

// familyCache enforces single-use refresh tokens with reuse detection, one
// entry per chain rather than per token (so a refresh loop cannot grow it).
// Like replayCache it is per-process and forgets everything on restart.
//
// It tracks active chains in a bounded LRU and never fails closed because of
// them: when full it evicts the least recently used one. Anyone can mint
// logins (the authorize form accepts any credentials), so a full cache must
// not lock legitimate users out for the refresh TTL. "Used" means created or
// successfully refreshed. Accepted trade-off: reuse detection is lost for an
// evicted active chain; a rotated (old) refresh token of it is accepted once
// as a new family, exactly as after a restart.
//
// Revoked families live in revs instead, immune to LRU pressure, so a revoked
// chain stays revoked until its natural expiry. The price is the policy when
// revs is full of live entries (about a million revocations within the
// refresh TTL): an unknown family might be a revoked one with no record, so
// it is refused (errRevocationsFull, a 503 for the caller) until entries
// expire; known active families keep working. That is a deliberate
// availability-for-integrity trade: it takes sustained abuse of the whole
// authorize ceiling for hours to reach, and it never reopens a stolen chain.
// A reuse detected while revs is full is kept as a flagged cache entry that
// is never evicted for room (the flagged list); if only flagged entries are
// left, new families fail closed too, so memory stays bounded.
//
// Every operation is O(1) amortized under the mutex: a hash lookup, a list
// move or pop, plus the rate-limited O(n) expiry sweeps (at most once a
// minute).
type familyCache struct {
	mu     sync.Mutex
	seen   map[string]*family
	active *list.List
	// flagged holds revoked families the full revs could not take; never evicted.
	flagged *list.List
	revs    *revocationSet
	sweep   sweeper
	limit   int

	// Eviction accounting for rate-limited logging, see takeEvictions.
	evicted    int
	lastReport time.Time
	full       fullCounter
}

func newFamilyCache(limit int) *familyCache {
	return &familyCache{
		seen: make(map[string]*family), active: list.New(), flagged: list.New(),
		revs: newRevocationSet(maxRevocationEntries), limit: max(1, limit),
	}
}

// evictionReportInterval bounds how often evictions are logged.
const evictionReportInterval = time.Minute

// takeEvictions returns the number of evictions since the last report at most
// once per evictionReportInterval, and zero otherwise (the count keeps
// accumulating).
func (c *familyCache) takeEvictions(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.evicted == 0 || now.Sub(c.lastReport) < evictionReportInterval {
		return 0
	}
	n := c.evicted
	c.evicted, c.lastReport = 0, now
	return n
}

// remove drops f from the map and the list.
func (c *familyCache) remove(f *family) {
	if f.revoked {
		c.flagged.Remove(f.elem)
	} else {
		c.active.Remove(f.elem)
	}
	delete(c.seen, f.id)
}

// use redeems generation gen of family id and extends the family's lifetime
// to newExp (the expiry of the successor being issued). Atomically:
//   - revoked family: errFamilyRevoked;
//   - gen <= highest used generation: a reuse, so the whole family is revoked
//     (kept in the revocation set until its expiry) and errFamilyRevoked is
//     returned;
//   - otherwise gen is recorded as used.
//
// A family with no live entry is accepted as new, which is why a restart or
// an eviction of an active chain reopens a window, unless the revocation set
// is full or the cache holds only unrecorded revocations: then
// errRevocationsFull. The boolean reports a reuse detection (as opposed to an
// earlier revocation) for logging.
func (c *familyCache) use(id string, gen int64, newExp, now time.Time) (reuse bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	h := c.revs.hash(id)
	if c.revs.has(h, now) {
		return false, errFamilyRevoked
	}
	f, ok := c.seen[id]
	if ok && !now.Before(f.exp) {
		c.remove(f) // dead: all its tokens are expired by now
		f, ok = nil, false
	}
	if ok {
		switch {
		case f.revoked:
			if c.revs.add(h, f.exp, now) {
				c.remove(f) // recorded now that there is room
			}
			return false, errFamilyRevoked
		case gen <= f.usedGen:
			if c.revs.add(h, f.exp, now) {
				c.remove(f)
			} else {
				c.active.Remove(f.elem)
				f.revoked = true
				f.elem = c.flagged.PushFront(f)
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
	if c.revs.full(now) {
		return false, errRevocationsFull
	}
	if c.sweep.due(now, false) {
		for _, v := range c.seen {
			if !now.Before(v.exp) {
				c.remove(v)
			}
		}
	}
	if len(c.seen) >= c.limit {
		if c.active.Len() == 0 { // only flagged revocations left: never evict those
			return false, errRevocationsFull
		}
		c.remove(c.active.Back().Value.(*family))
		c.evicted++
	}
	f = &family{id: id, usedGen: gen, exp: newExp}
	f.elem = c.active.PushFront(f)
	c.seen[id] = f
	return false, nil
}
