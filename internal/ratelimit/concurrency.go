package ratelimit

import (
	"sync"
	"time"
)

// Concurrency caps the number of simultaneously held slots per key. Unlike a
// Limiter it does not refill over time: a slot is held until its release
// function runs, so it suits long-lived requests such as SSE streams. It is
// safe for concurrent use.
//
// A key with no held slots is dropped from the map, so memory is bounded by
// the number of slots currently held (at most max per key).
type Concurrency struct {
	max int

	mu   sync.Mutex
	held map[string]int

	denied     int
	lastReport time.Time
}

// NewConcurrency returns a Concurrency allowing limit slots per key. Values
// below 1 are raised to 1.
func NewConcurrency(limit int) *Concurrency {
	return &Concurrency{max: max(limit, 1), held: make(map[string]int)}
}

// Acquire takes a slot for key without blocking. On success it returns a
// release function that must be called exactly once (extra calls are
// ignored); on failure it returns nil and false and holds nothing.
func (c *Concurrency) Acquire(key string) (release func(), ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.held[key] >= c.max {
		c.denied++
		return nil, false
	}
	c.held[key]++
	var once sync.Once
	return func() { once.Do(func() { c.release(key) }) }, true
}

func (c *Concurrency) release(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := c.held[key]; n <= 1 {
		delete(c.held, key)
	} else {
		c.held[key] = n - 1
	}
}

// Held returns the number of slots currently held for key.
func (c *Concurrency) Held(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.held[key]
}

// Keys returns the number of keys with at least one held slot.
func (c *Concurrency) Keys() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.held)
}

// TakeDenied has the semantics of Limiter.TakeDenied.
func (c *Concurrency) TakeDenied(now time.Time, interval time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.denied == 0 || now.Sub(c.lastReport) < interval {
		return 0
	}
	n := c.denied
	c.denied, c.lastReport = 0, now
	return n
}
