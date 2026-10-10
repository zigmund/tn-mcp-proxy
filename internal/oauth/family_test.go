package oauth

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func famID(i int) string { return fmt.Sprintf("f%d", i) }

func mustUse(t *testing.T, c *familyCache, id string, gen int64, exp, now time.Time) {
	t.Helper()
	if reuse, err := c.use(id, gen, exp, now); reuse || err != nil {
		t.Fatalf("use(%s, %d) = %v, %v", id, gen, reuse, err)
	}
}

func (c *familyCache) check(t *testing.T) {
	t.Helper()
	if len(c.seen) != c.active.Len()+c.flagged.Len() || len(c.seen) > c.limit || len(c.revs.exp) > c.revs.limit {
		t.Fatalf("map %d, list %d, limit %d, revocations %d (limit %d)",
			len(c.seen), c.active.Len(), c.limit, len(c.revs.exp), c.revs.limit)
	}
	for e := c.active.Front(); e != nil; e = e.Next() {
		f := e.Value.(*family)
		if c.seen[f.id] != f || f.elem != e || f.revoked {
			t.Fatalf("inconsistent entry %s", f.id)
		}
	}
	for e := c.flagged.Front(); e != nil; e = e.Next() {
		f := e.Value.(*family)
		if c.seen[f.id] != f || f.elem != e || !f.revoked {
			t.Fatalf("inconsistent flagged entry %s", f.id)
		}
	}
}

func TestFamilyFullEvictsLRU(t *testing.T) {
	c := newFamilyCache(3)
	now, exp := fixedNow, fixedNow.Add(time.Hour)
	for i := range 3 {
		mustUse(t, c, famID(i), 0, exp, now)
	}
	mustUse(t, c, "f0", 1, exp, now) // touch f0: f1 is now the LRU
	mustUse(t, c, "new", 0, exp, now)
	if _, ok := c.seen["f1"]; ok {
		t.Error("LRU family f1 not evicted")
	}
	for _, id := range []string{"f0", "f2", "new"} {
		if _, ok := c.seen[id]; !ok {
			t.Errorf("%s evicted", id)
		}
	}
	c.check(t)
}

func TestFamilyHotSurvivesFlood(t *testing.T) {
	c := newFamilyCache(100)
	now, exp := fixedNow, fixedNow.Add(time.Hour)
	mustUse(t, c, "legit", 0, exp, now)
	gen := int64(1)
	for i := range 1000 {
		mustUse(t, c, famID(i), 0, exp, now)
		if i%50 == 0 { // legitimate client refreshes periodically
			mustUse(t, c, "legit", gen, exp, now)
			gen++
		}
	}
	// Reuse detection still works for the hot family.
	if reuse, err := c.use("legit", 0, exp, now); !reuse || err != errFamilyRevoked {
		t.Fatalf("reuse = %v, err = %v", reuse, err)
	}
	c.check(t)
}

func TestFamilyEvictedAcceptedAsNew(t *testing.T) {
	c := newFamilyCache(2)
	now, exp := fixedNow, fixedNow.Add(time.Hour)
	mustUse(t, c, "a", 0, exp, now)
	mustUse(t, c, "a", 1, exp, now)
	mustUse(t, c, "b", 0, exp, now)
	mustUse(t, c, "c", 0, exp, now) // evicts a
	// a's rotated token (gen 0) is accepted as new: the documented trade-off.
	mustUse(t, c, "a", 0, exp, now)
	// Non-evicted families keep reuse detection.
	if reuse, err := c.use("c", 0, exp, now); !reuse || err != errFamilyRevoked {
		t.Fatalf("reuse = %v, err = %v", reuse, err)
	}
}

// revokeFam creates family id and revokes it by presenting generation 0 again.
func revokeFam(t *testing.T, c *familyCache, id string, exp, now time.Time) {
	t.Helper()
	mustUse(t, c, id, 0, exp, now)
	if reuse, err := c.use(id, 0, exp, now); !reuse || err != errFamilyRevoked {
		t.Fatalf("revoke %s: reuse = %v, err = %v", id, reuse, err)
	}
}

// A revoked family stays revoked through a flood of more new active and
// revoked families than either structure holds, until its own expiry.
func TestFamilyRevokedSurvivesFlood(t *testing.T) {
	c := newFamilyCache(20)
	c.revs = newRevocationSet(1000)
	now, exp := fixedNow, fixedNow.Add(time.Hour)
	revokeFam(t, c, "victim", exp, now)
	for i := range 500 { // more than the active capacity
		mustUse(t, c, famID(i), 0, exp, now)
	}
	for i := range 500 { // revoked flood below the set capacity
		revokeFam(t, c, "x"+famID(i), exp.Add(time.Hour), now)
	}
	if _, err := c.use("victim", 5, exp, now); err != errFamilyRevoked {
		t.Fatalf("victim: err = %v (revoked family resurrected)", err)
	}
	c.check(t)
	// Revoked entries leave the active cache: they cost no LRU slots.
	if len(c.seen) > c.limit {
		t.Fatalf("seen = %d", len(c.seen))
	}
	// Natural expiry: after exp the family's tokens are dead and the entry
	// is pruned (accepted as new again, as every expired id).
	later := exp.Add(time.Second)
	if _, err := c.use("victim", 5, later.Add(time.Hour), later); err != nil {
		t.Fatalf("after expiry: err = %v", err)
	}
	if c.revs.has(c.revs.hash("victim"), later) {
		t.Error("expired revocation still reported")
	}
	c.check(t)
}

// When the set is full of live revocations, nothing is evicted to make room:
// unknown families are refused, known active ones and revoked ones keep
// their state, and room appears only as entries expire.
func TestFamilyRevocationsFullFailsClosed(t *testing.T) {
	c := newFamilyCache(100)
	c.revs = newRevocationSet(3)
	now := fixedNow
	exp := now.Add(time.Hour)
	mustUse(t, c, "active", 0, exp, now)
	revokeFam(t, c, "r0", now.Add(time.Minute), now) // expires first
	revokeFam(t, c, "r1", exp, now)
	revokeFam(t, c, "r2", exp, now)
	if _, err := c.use("new", 0, exp, now); err != errRevocationsFull {
		t.Fatalf("unknown family: err = %v, want errRevocationsFull", err)
	}
	if _, ok := c.seen["new"]; ok {
		t.Error("refused family was recorded")
	}
	mustUse(t, c, "active", 1, exp, now) // known family still works
	for _, id := range []string{"r0", "r1", "r2"} {
		if _, err := c.use(id, 9, exp, now); err != errFamilyRevoked {
			t.Fatalf("%s: err = %v", id, err)
		}
	}
	// A reuse while full is still rejected and flagged on the cache entry.
	if reuse, err := c.use("active", 0, exp, now); !reuse || err != errFamilyRevoked {
		t.Fatalf("reuse while full = %v, %v", reuse, err)
	}
	if _, err := c.use("active", 5, exp, now); err != errFamilyRevoked {
		t.Fatalf("flagged family accepted: %v", err)
	}
	c.check(t)
	// r0 expires: room appears, unknown families are accepted again.
	later := now.Add(2 * time.Minute)
	mustUse(t, c, "new", 0, later.Add(time.Hour), later)
	// ... and the flagged family is recorded properly now.
	if _, err := c.use("active", 5, exp, later); err != errFamilyRevoked {
		t.Fatalf("flagged family after room: %v", err)
	}
	c.check(t)
}

func TestRevocationSetBoundAndExpiry(t *testing.T) {
	r := newRevocationSet(100)
	now := fixedNow
	for i := range 1000 {
		r.add(uint64(i), now.Add(time.Hour), now)
	}
	if len(r.exp) != 100 {
		t.Fatalf("len = %d, want the bound 100", len(r.exp))
	}
	if r.add(5000, now.Add(time.Hour), now) {
		t.Error("add succeeded while full")
	}
	if !r.add(3, now.Add(2*time.Hour), now) { // existing entry: extended, not refused
		t.Error("extending an existing entry refused")
	}
	if !r.has(3, now.Add(90*time.Minute)) || r.has(4, now.Add(90*time.Minute)) {
		t.Error("expiry not honoured per entry")
	}
	later := now.Add(3 * time.Hour)
	if !r.add(5000, later.Add(time.Hour), later) || len(r.exp) != 1 {
		t.Errorf("expired entries not pruned: len = %d", len(r.exp))
	}
}

func TestFamilyExpiredPruned(t *testing.T) {
	c := newFamilyCache(100)
	now := fixedNow
	for i := range 10 {
		mustUse(t, c, famID(i), 0, now.Add(time.Minute), now)
	}
	later := now.Add(2 * time.Minute) // past sweepInterval and the expiry
	mustUse(t, c, "x", 0, later.Add(time.Hour), later)
	if len(c.seen) != 1 || c.active.Len() != 1 {
		t.Fatalf("entries = %d, active = %d, want 1", len(c.seen), c.active.Len())
	}
}

func TestFamilyEvictionReportRateLimited(t *testing.T) {
	c := newFamilyCache(1)
	now, exp := fixedNow, fixedNow.Add(24*time.Hour)
	if n := c.takeEvictions(now); n != 0 {
		t.Fatalf("n = %d before any eviction", n)
	}
	mustUse(t, c, "a", 0, exp, now)
	mustUse(t, c, "b", 0, exp, now) // evicts a
	if n := c.takeEvictions(now); n != 1 {
		t.Fatalf("first report = %d", n)
	}
	mustUse(t, c, "c", 0, exp, now)
	mustUse(t, c, "d", 0, exp, now)
	if n := c.takeEvictions(now.Add(30 * time.Second)); n != 0 {
		t.Fatalf("reported within the interval: %d", n)
	}
	if n := c.takeEvictions(now.Add(time.Minute)); n != 2 {
		t.Fatalf("accumulated = %d, want 2", n)
	}
	if n := c.takeEvictions(now.Add(2 * time.Minute)); n != 0 {
		t.Fatalf("repeat = %d", n)
	}
}

// TestFamilyFullIsConstantTime keeps a large cache full and floods it; with
// an O(n) eviction this would take minutes instead of well under a second.
func TestFamilyFullIsConstantTime(t *testing.T) {
	const limit = 200_000
	c := newFamilyCache(limit)
	now, exp := fixedNow, fixedNow.Add(time.Hour)
	for i := range limit {
		mustUse(t, c, famID(i), 0, exp, now)
	}
	start := time.Now()
	for i := range limit {
		mustUse(t, c, famID(limit+i), 0, exp, now)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("%d evicting inserts took %v", limit, d)
	}
	if len(c.seen) != limit {
		t.Fatalf("len = %d", len(c.seen))
	}
	c.check(t)
}

func BenchmarkFamilyEvict(b *testing.B) {
	c := newFamilyCache(100_000)
	now, exp := fixedNow, fixedNow.Add(time.Hour)
	for i := range 100_000 {
		_, _ = c.use(famID(i), 0, exp, now)
	}
	b.ResetTimer()
	for i := range b.N {
		_, _ = c.use(famID(1_000_000+i), 0, exp, now)
	}
}

func TestFamilyConcurrent(t *testing.T) {
	c := newFamilyCache(50)
	now, exp := fixedNow, fixedNow.Add(time.Hour)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 2000 {
				id := famID((g*7 + i) % 200)
				_, _ = c.use(id, int64(i%3), exp, now)
				c.takeEvictions(now.Add(time.Duration(i) * time.Second))
			}
		}()
	}
	wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.check(t)
}

func TestFamilyRevokedExpiredPrunedAndAcceptedAsNew(t *testing.T) {
	c := newFamilyCache(100)
	now := fixedNow
	exp := now.Add(time.Minute)
	revokeFam(t, c, "r", exp, now)
	later := now.Add(2 * time.Minute)
	mustUse(t, c, "x", 0, later.Add(time.Hour), later) // triggers the sweep
	if len(c.revs.exp) != 0 {
		t.Fatalf("revocations = %d after expiry", len(c.revs.exp))
	}
	mustUse(t, c, "r", 0, later.Add(time.Hour), later) // accepted as new
	c.check(t)
}

func TestFamilyConcurrentAdvancingClock(t *testing.T) {
	c := newFamilyCache(50)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 2000 {
				now := fixedNow.Add(time.Duration(i) * 5 * time.Second)
				_, _ = c.use(famID((g*7+i)%200), int64(i%3), now.Add(time.Minute), now)
				c.takeEvictions(now)
			}
		}()
	}
	wg.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.check(t)
}

// Revocations that could not be recorded (set full) are never evicted for
// room; when only they are left, new families fail closed and memory is bounded.
func TestFamilyFlaggedNeverEvicted(t *testing.T) {
	c := newFamilyCache(3)
	c.revs = newRevocationSet(1)
	now, exp := fixedNow, fixedNow.Add(time.Hour)
	for _, id := range []string{"f1", "f2", "f3"} {
		mustUse(t, c, id, 0, exp, now)
	}
	const filler = 999
	c.revs.add(filler, exp, now) // the set is full: reuses can only be flagged
	for _, id := range []string{"f2", "f3"} {
		if reuse, err := c.use(id, 0, exp, now); !reuse || err != errFamilyRevoked {
			t.Fatalf("%s: %v %v", id, reuse, err)
		}
	}
	delete(c.revs.exp, filler)       // room again (as if it expired)
	mustUse(t, c, "n1", 0, exp, now) // evicts the only unflagged entry, f1
	mustUse(t, c, "n2", 0, exp, now) // evicts n1
	for _, id := range []string{"f2", "f3"} {
		if f, ok := c.seen[id]; !ok || !f.revoked {
			t.Fatalf("flagged %s evicted", id)
		}
	}
	if _, ok := c.seen["f1"]; ok {
		t.Error("unflagged f1 survived")
	}
	c.check(t)
	// A third flagged entry leaves nothing evictable: fail closed, no growth.
	c.revs.add(filler, exp, now)
	if reuse, _ := c.use("n2", 0, exp, now); !reuse {
		t.Fatal("no reuse")
	}
	delete(c.revs.exp, filler)
	if _, err := c.use("new", 0, exp, now); err != errRevocationsFull {
		t.Fatalf("only flagged left: err = %v, want errRevocationsFull", err)
	}
	if _, ok := c.seen["new"]; ok || len(c.seen) != 3 {
		t.Fatalf("seen = %d", len(c.seen))
	}
	// Once the set has room a presented flagged family is recorded and freed.
	if _, err := c.use("f2", 9, exp, now); err != errFamilyRevoked {
		t.Fatalf("err = %v", err)
	}
	if len(c.seen) != 2 || !c.revs.has(c.revs.hash("f2"), now) {
		t.Fatalf("flagged f2 not moved to the set: seen = %d", len(c.seen))
	}
	c.check(t)
}
