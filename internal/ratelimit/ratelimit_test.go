package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func TestBurstThenDeny(t *testing.T) {
	clk := newClock()
	l := New(60, 3, WithClock(clk.now)) // 1 token per second
	for i := range 3 {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("request %d denied within burst", i)
		}
	}
	ok, wait := l.Allow("a")
	if ok {
		t.Fatal("request beyond burst allowed")
	}
	if wait != time.Second {
		t.Fatalf("retryAfter = %v, want 1s", wait)
	}
}

func TestRecoveryAfterRefill(t *testing.T) {
	clk := newClock()
	l := New(60, 2, WithClock(clk.now))
	l.Allow("a")
	l.Allow("a")
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("expected deny")
	}
	clk.advance(500 * time.Millisecond)
	ok, wait := l.Allow("a")
	if ok || wait != 500*time.Millisecond {
		t.Fatalf("after 0.5s: ok=%v wait=%v, want deny with 500ms", ok, wait)
	}
	clk.advance(500 * time.Millisecond)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("token not refilled after 1s")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("only one token should have refilled")
	}
	// Refill is capped at burst.
	clk.advance(time.Hour)
	for i := range 2 {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("request %d denied after long idle", i)
		}
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("burst cap exceeded after long idle")
	}
}

func TestKeyIsolation(t *testing.T) {
	l := New(60, 1, WithClock(newClock().now))
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("a denied")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("a allowed twice")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("b affected by a")
	}
}

func TestKeyGrouping(t *testing.T) {
	tests := []struct{ in, want string }{
		{"203.0.113.7", "203.0.113.7"},
		{"::ffff:203.0.113.7", "203.0.113.7"},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"},
		{"2001:db8:1:3::1", "2001:db8:1:3::/64"},
		{"fe80::1%eth0", "fe80::/64"},
		{"weird", "weird"},
	}
	for _, tt := range tests {
		if got := Key(tt.in); got != tt.want {
			t.Errorf("Key(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	l := New(60, 1, WithClock(newClock().now))
	l.Allow(Key("2001:db8:1:2::1"))
	if ok, _ := l.Allow(Key("2001:db8:1:2::2")); ok {
		t.Fatal("addresses in one /64 must share a bucket")
	}
	if ok, _ := l.Allow(Key("2001:db8:1:3::1")); !ok {
		t.Fatal("different /64 must not share a bucket")
	}
}

func TestBoundedEvictsLeastRecentlySeen(t *testing.T) {
	clk := newClock()
	l := New(1, 1, WithClock(clk.now), WithMaxKeys(3))
	for _, k := range []string{"a", "b", "c"} {
		if ok, _ := l.Allow(k); !ok {
			t.Fatalf("%s denied", k)
		}
		clk.advance(time.Second) // far from refilled at 1/min
	}
	l.Allow("a") // denied, but refreshes a's recency; b is now the oldest
	if ok, _ := l.Allow("d"); !ok {
		t.Fatal("new key denied when full (fail closed)")
	}
	if n := l.Len(); n != 3 {
		t.Fatalf("Len = %d, want 3", n)
	}
	if ok, _ := l.Allow("b"); !ok { // b was evicted: starts over with a full bucket
		t.Fatal("evicted key should get a fresh bucket")
	}
	if ok, _ := l.Allow("a"); ok { // a was kept and is still exhausted
		t.Fatal("recently seen key was evicted")
	}
}

func TestFullMapSweepsRefilledEntries(t *testing.T) {
	clk := newClock()
	l := New(60, 1, WithClock(clk.now), WithMaxKeys(3))
	for _, k := range []string{"a", "b", "c"} {
		l.Allow(k)
	}
	clk.advance(2 * time.Minute) // all three have fully refilled
	l.Allow("d")
	if n := l.Len(); n != 1 {
		t.Fatalf("Len = %d, want 1 after sweeping refilled entries", n)
	}
}

func TestSweepKeepsExhaustedEntries(t *testing.T) {
	clk := newClock()
	l := New(1, 1, WithClock(clk.now), WithMaxKeys(2))
	l.Allow("a")
	l.Allow("b")
	clk.advance(2 * time.Minute) // a and b refilled (1 token per minute)
	l.Allow("a")                 // exhausts a again
	l.Allow("c")                 // full: the sweep drops b only
	if n := l.Len(); n != 2 {
		t.Fatalf("Len = %d, want 2", n)
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("exhausted entry was swept")
	}
}

func TestManyKeysStayBounded(t *testing.T) {
	l := New(60, 5, WithClock(newClock().now), WithMaxKeys(100))
	for i := range 5000 {
		if ok, _ := l.Allow(fmt.Sprintf("k%d", i)); !ok {
			t.Fatalf("new key k%d denied", i)
		}
	}
	if n := l.Len(); n != 100 {
		t.Fatalf("Len = %d, want 100", n)
	}
}

func TestConcurrent(t *testing.T) {
	l := New(600, 50, WithMaxKeys(64))
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 1000 {
				l.Allow(fmt.Sprintf("k%d", (g*31+i)%200))
			}
		}()
	}
	wg.Wait()
	if n := l.Len(); n > 64 {
		t.Fatalf("Len = %d exceeds bound", n)
	}
}

func TestClockStepBackDoesNotMintTokens(t *testing.T) {
	clk := newClock()
	l := New(60, 1, WithClock(clk.now))
	l.Allow("a")
	clk.advance(-time.Hour)
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("backwards clock minted a token")
	}
}
