package oauth

import (
	"container/list"
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
	if len(c.seen) != c.active.Len()+c.revoked.Len() {
		t.Fatalf("map %d != lists %d+%d", len(c.seen), c.active.Len(), c.revoked.Len())
	}
	if len(c.seen) > c.limit || c.revoked.Len() > c.revokedLimit {
		t.Fatalf("over limit: %d (limit %d), revoked %d (limit %d)", len(c.seen), c.limit, c.revoked.Len(), c.revokedLimit)
	}
	for l, wantRevoked := range map[*list.List]bool{c.active: false, c.revoked: true} {
		for e := l.Front(); e != nil; e = e.Next() {
			f := e.Value.(*family)
			if f.revoked != wantRevoked || c.seen[f.id] != f || f.elem != e {
				t.Fatalf("inconsistent entry %s (revoked=%v, list revoked=%v)", f.id, f.revoked, wantRevoked)
			}
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

func TestFamilyRevokedProtectedAndCapped(t *testing.T) {
	c := newFamilyCache(20) // revokedLimit = 2
	now, exp := fixedNow, fixedNow.Add(time.Hour)
	revoke := func(id string) {
		mustUse(t, c, id, 0, exp, now)
		if reuse, _ := c.use(id, 0, exp, now); !reuse {
			t.Fatal("no reuse")
		}
	}
	revoke("r0")
	revoke("r1")
	for i := range 500 { // flood of active families
		mustUse(t, c, famID(i), 0, exp, now)
	}
	for _, id := range []string{"r0", "r1"} {
		if _, err := c.use(id, 5, exp, now); err != errFamilyRevoked {
			t.Fatalf("%s: err = %v (revoked family lost)", id, err)
		}
	}
	c.check(t)
	// Quota: a third revocation drops the least recently used revoked one
	// (r0 was touched before r1 above, so r0 goes).
	revoke("r2")
	if c.revoked.Len() != 2 {
		t.Fatalf("revoked = %d, want 2", c.revoked.Len())
	}
	if _, ok := c.seen["r0"]; ok {
		t.Error("oldest revoked r0 kept")
	}
	if _, ok := c.seen["r1"]; !ok {
		t.Error("r1 lost")
	}
	c.check(t)
}

func TestFamilyOnlyRevokedEvictsLRURevoked(t *testing.T) {
	c := newFamilyCache(1) // revokedLimit = 1
	now, exp := fixedNow, fixedNow.Add(time.Hour)
	mustUse(t, c, "r", 0, exp, now)
	_, _ = c.use("r", 0, exp, now) // revoke: cache holds only a revoked entry
	mustUse(t, c, "n", 0, exp, now)
	if _, ok := c.seen["r"]; ok {
		t.Error("revoked entry kept over a new family")
	}
	if _, ok := c.seen["n"]; !ok {
		t.Error("new family missing")
	}
	c.check(t)
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
	if n, _ := c.takeEvictions(now); n != 0 {
		t.Fatalf("n = %d before any eviction", n)
	}
	mustUse(t, c, "a", 0, exp, now)
	mustUse(t, c, "b", 0, exp, now) // evicts a
	if n, r := c.takeEvictions(now); n != 1 || r != 0 {
		t.Fatalf("first report = %d, %d", n, r)
	}
	mustUse(t, c, "c", 0, exp, now)
	mustUse(t, c, "d", 0, exp, now)
	if n, _ := c.takeEvictions(now.Add(30 * time.Second)); n != 0 {
		t.Fatalf("reported within the interval: %d", n)
	}
	if n, _ := c.takeEvictions(now.Add(time.Minute)); n != 2 {
		t.Fatalf("accumulated = %d, want 2", n)
	}
	if n, _ := c.takeEvictions(now.Add(2 * time.Minute)); n != 0 {
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
	mustUse(t, c, "r", 0, exp, now)
	if reuse, _ := c.use("r", 0, exp, now); !reuse {
		t.Fatal("no reuse")
	}
	later := now.Add(2 * time.Minute)
	mustUse(t, c, "x", 0, later.Add(time.Hour), later) // triggers the sweep
	if c.revoked.Len() != 0 {
		t.Fatalf("revoked = %d after expiry", c.revoked.Len())
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
