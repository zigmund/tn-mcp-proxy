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

func TestKeys(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"203.0.113.7", []string{"203.0.113.7"}},
		{"::ffff:203.0.113.7", []string{"203.0.113.7"}},
		{"2001:db8:1:2:3:4:5:6", []string{"2001:db8:1:2::/64", "2001:db8:1::/56", "2001:db8:1::/48"}},
		{"2001:db8:1:ff03::1", []string{"2001:db8:1:ff03::/64", "2001:db8:1:ff00::/56", "2001:db8:1::/48"}},
		{"fe80::1%eth0", []string{"fe80::/64", "fe80::/56", "fe80::/48"}},
		{"weird", []string{"weird"}},
	}
	for _, tt := range tests {
		got := Keys(tt.in)
		if fmt.Sprint(got) != fmt.Sprint(tt.want) {
			t.Errorf("Keys(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// tiers builds the per-tier limiters the way the OAuth server does.
func tiers(clk *fakeClock, perMinute, burst int) []*Limiter {
	mk := func(scale int) *Limiter { return New(perMinute*scale, burst*scale, WithClock(clk.now)) }
	return []*Limiter{mk(1), mk(Scale56), mk(Scale48)}
}

func TestChargeRotating64sExhaustPrefixBudget(t *testing.T) {
	clk := newClock()
	ls := tiers(clk, 60, 2) // /64: 2, /56: 8, /48: 32
	// Every request comes from a fresh /64 of one /48 (all in different /56s
	// so only the /48 tier can stop it): the /48 budget is the ceiling.
	var allowed int
	for i := range 256 {
		ip := fmt.Sprintf("2001:db8:1:%x::1", i<<8) // one /64 per /56
		if ok, _ := Charge(ls, Keys(ip)); ok {
			allowed++
		}
	}
	if allowed != 2*Scale48 {
		t.Fatalf("allowed = %d from rotating /64s, want the /48 burst %d", allowed, 2*Scale48)
	}
	// Rotating /64s inside one /56 stop at the /56 budget.
	ls = tiers(clk, 60, 2)
	allowed = 0
	for i := range 1000 {
		if ok, _ := Charge(ls, Keys(fmt.Sprintf("2001:db8:1:%x::1", 0x100+i%256))); ok {
			allowed++
		}
	}
	if allowed != 2*Scale56 {
		t.Fatalf("allowed = %d within one /56, want %d", allowed, 2*Scale56)
	}
}

func TestChargeIndependentPrefixesAndIPv4(t *testing.T) {
	clk := newClock()
	ls := tiers(clk, 60, 1)
	for i := range Scale48 { // exhaust one /48 (distinct /56s)
		Charge(ls, Keys(fmt.Sprintf("2001:db8:1:%x::1", i<<8)))
	}
	if ok, _ := Charge(ls, Keys("2001:db8:1:ff01::1")); ok {
		t.Fatal("exhausted /48 still allows")
	}
	if ok, _ := Charge(ls, Keys("2001:db8:2::1")); !ok {
		t.Fatal("a different /48 must be independent")
	}
	if ok, _ := Charge(ls, Keys("203.0.113.7")); !ok {
		t.Fatal("IPv4 affected by IPv6 tiers")
	}
	if ok, _ := Charge(ls, Keys("::ffff:203.0.113.7")); ok {
		t.Fatal("IPv4-mapped IPv6 must share the IPv4 bucket")
	}
	if ok, _ := Charge(ls, Keys("203.0.113.8")); !ok {
		t.Fatal("other IPv4 address limited")
	}
}

func TestChargeRefundsOnDenial(t *testing.T) {
	clk := newClock()
	// The /64 tier has room, the /48 tier is exhausted: the denied request
	// must not cost /64 tokens.
	ls := []*Limiter{New(60, 3, WithClock(clk.now)), New(60, 1, WithClock(clk.now))}
	k1 := []string{"a", "p"}
	if ok, _ := Charge(ls, k1); !ok {
		t.Fatal("first denied")
	}
	for range 5 {
		if ok, wait := Charge(ls, k1); ok || wait <= 0 {
			t.Fatalf("ok = %v, wait = %v", ok, wait)
		}
	}
	clk.advance(time.Second) // /48 refilled one token
	for i := range 2 {       // /64 still has its 2 remaining tokens
		if ok, _ := Charge(ls, []string{"a", fmt.Sprint("q", i)}); !ok {
			t.Fatalf("request %d denied: denials leaked /64 tokens", i)
		}
	}
}

func TestTakeDeniedRateLimited(t *testing.T) {
	clk := newClock()
	l := New(1, 1, WithClock(clk.now))
	if n := l.TakeDenied(clk.now(), time.Minute); n != 0 {
		t.Fatalf("n = %d before any denial", n)
	}
	l.Allow("k")
	l.Allow("k")
	l.Allow("k")
	if n := l.TakeDenied(clk.now(), time.Minute); n != 2 {
		t.Fatalf("first report = %d, want 2", n)
	}
	l.Allow("k")
	if n := l.TakeDenied(clk.now().Add(30*time.Second), time.Minute); n != 0 {
		t.Fatalf("reported within the interval: %d", n)
	}
	if n := l.TakeDenied(clk.now().Add(time.Minute), time.Minute); n != 1 {
		t.Fatalf("accumulated = %d, want 1", n)
	}
}

func TestChargeConcurrent(t *testing.T) {
	clk := newClock()
	ls := tiers(clk, 600, 50)
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 2000 {
				Charge(ls, Keys(fmt.Sprintf("2001:db8:%x:%x::1", g, i%50)))
				if i%500 == 0 {
					clk.advance(time.Second)
				}
			}
		}()
	}
	wg.Wait()
}
