package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestConcurrencyLimitAndRelease(t *testing.T) {
	c := NewConcurrency(2)
	r1, ok1 := c.Acquire("a")
	r2, ok2 := c.Acquire("a")
	if !ok1 || !ok2 {
		t.Fatal("slots within the limit refused")
	}
	if r, ok := c.Acquire("a"); ok || r != nil {
		t.Fatal("slot beyond the limit granted")
	}
	if _, ok := c.Acquire("b"); !ok {
		t.Fatal("keys must be independent")
	}
	r1()
	r1() // double release must not free a second slot
	if got := c.Held("a"); got != 1 {
		t.Fatalf("held %d, want 1", got)
	}
	if _, ok := c.Acquire("a"); !ok {
		t.Fatal("freed slot not reusable")
	}
	r2()
}

func TestConcurrencyDropsIdleKeys(t *testing.T) {
	c := NewConcurrency(1)
	for i := range 100 {
		r, _ := c.Acquire(string(rune('a' + i)))
		r()
	}
	if c.Keys() != 0 {
		t.Errorf("%d idle keys retained", c.Keys())
	}
}

func TestConcurrencyRace(t *testing.T) {
	c := NewConcurrency(5)
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if r, ok := c.Acquire("k"); ok {
					if c.Held("k") > 5 {
						t.Error("limit exceeded")
					}
					r()
				}
			}
		}()
	}
	wg.Wait()
	if c.Keys() != 0 {
		t.Error("slots leaked")
	}
}

func TestConcurrencyTakeDenied(t *testing.T) {
	c := NewConcurrency(1)
	now := time.Unix(1_700_000_000, 0)
	c.Acquire("a")
	c.Acquire("a")
	c.Acquire("a")
	if n := c.TakeDenied(now, time.Minute); n != 2 {
		t.Fatalf("got %d, want 2", n)
	}
	c.Acquire("a")
	if n := c.TakeDenied(now.Add(time.Second), time.Minute); n != 0 {
		t.Fatalf("reported again within the interval: %d", n)
	}
	if n := c.TakeDenied(now.Add(time.Minute), time.Minute); n != 1 {
		t.Fatalf("got %d, want 1", n)
	}
}
