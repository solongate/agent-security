package sdk

import (
	"sync"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/core"
)

// RateLimitResult is one limit decision.
type RateLimitResult struct {
	Allowed   bool
	Remaining int
	// ResetAt is when the oldest call in the window falls out of it, in
	// milliseconds since the epoch.
	ResetAt int64
}

// circularTimestamps is a fixed-size ring of call times.
//
// A slice that is filtered on every check re-allocates on every call and grows
// without bound between checks. The ring is O(1) to push, never allocates
// again, and counts within the window by binary search — the entries are
// pushed in time order, so the ring is sorted in its logical order.
type circularTimestamps struct {
	buf  []int64
	head int // next write position
	size int
}

func newCircularTimestamps(capacity int) *circularTimestamps {
	if capacity <= 0 {
		capacity = 1
	}
	return &circularTimestamps{buf: make([]int64, capacity)}
}

func (c *circularTimestamps) push(ts int64) {
	c.buf[c.head] = ts
	c.head = (c.head + 1) % len(c.buf)
	if c.size < len(c.buf) {
		c.size++
	}
}

// at addresses the ring in logical order, 0 being the oldest entry.
func (c *circularTimestamps) at(logical int) int64 {
	start := 0
	if c.size == len(c.buf) {
		// Full: head is now pointing at the oldest entry, not a free slot.
		start = c.head
	}
	return c.buf[(start+logical)%len(c.buf)]
}

// firstAfter is the logical index of the first entry newer than windowStart.
func (c *circularTimestamps) firstAfter(windowStart int64) int {
	lo, hi := 0, c.size
	for lo < hi {
		mid := (lo + hi) / 2
		if c.at(mid) > windowStart {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo
}

func (c *circularTimestamps) countAfter(windowStart int64) int {
	if c.size == 0 {
		return 0
	}
	if c.at(0) > windowStart {
		return c.size
	}
	return c.size - c.firstAfter(windowStart)
}

func (c *circularTimestamps) oldestInWindow(windowStart int64) (int64, bool) {
	if c.size == 0 {
		return 0, false
	}
	i := c.firstAfter(windowStart)
	if i >= c.size {
		return 0, false
	}
	return c.at(i), true
}

// RateLimiter is a sliding-window limiter, per tool and across all tools.
//
// Safe for concurrent use. That is not decoration: the guard's rate limiter
// once let fourteen calls through a limit of five because two calls read the
// same count before either wrote it back. Everything here happens under one
// lock, and CheckAndRecord exists so a caller cannot leave a gap between
// deciding and recording.
type RateLimiter struct {
	mu         sync.Mutex
	window     time.Duration
	maxEntries int
	buffers    map[string]*circularTimestamps
	global     *circularTimestamps
}

func NewRateLimiter() *RateLimiter {
	return NewRateLimiterWith(core.RateLimitWindowMs*time.Millisecond, core.RateLimitMaxEntries)
}

func NewRateLimiterWith(window time.Duration, maxEntries int) *RateLimiter {
	if window <= 0 {
		window = core.RateLimitWindowMs * time.Millisecond
	}
	if maxEntries <= 0 {
		maxEntries = core.RateLimitMaxEntries
	}
	return &RateLimiter{
		window:     window,
		maxEntries: maxEntries,
		buffers:    map[string]*circularTimestamps{},
		global:     newCircularTimestamps(maxEntries),
	}
}

func nowMillis() int64 { return time.Now().UnixMilli() }

// CheckLimit reports whether one more call to a tool would be within its limit.
// It does NOT record the call.
func (r *RateLimiter) CheckLimit(toolName string, limit int) RateLimitResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checkLocked(r.buffers[toolName], limit)
}

// CheckGlobalLimit is the same question across every tool.
func (r *RateLimiter) CheckGlobalLimit(limit int) RateLimitResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checkLocked(r.global, limit)
}

func (r *RateLimiter) checkLocked(buf *circularTimestamps, limit int) RateLimitResult {
	now := nowMillis()
	windowStart := now - r.window.Milliseconds()
	if buf == nil {
		return RateLimitResult{Allowed: true, Remaining: limit, ResetAt: now + r.window.Milliseconds()}
	}
	count := buf.countAfter(windowStart)
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}
	resetAt := now + r.window.Milliseconds()
	if oldest, ok := buf.oldestInWindow(windowStart); ok {
		resetAt = oldest + r.window.Milliseconds()
	}
	return RateLimitResult{Allowed: count < limit, Remaining: remaining, ResetAt: resetAt}
}

// CheckAndRecord decides and records under one lock.
//
// Checking and recording separately leaves a window in which two concurrent
// calls both see room. Callers that need the limit actually enforced use this;
// CheckLimit exists for reporting.
func (r *RateLimiter) CheckAndRecord(toolName string, limit int, globalLimit int) RateLimitResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := r.checkLocked(r.buffers[toolName], limit)
	if !result.Allowed {
		return result
	}
	if globalLimit > 0 {
		g := r.checkLocked(r.global, globalLimit)
		if !g.Allowed {
			return g
		}
	}
	r.recordLocked(toolName)
	return result
}

// RecordCall marks a call as made.
func (r *RateLimiter) RecordCall(toolName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recordLocked(toolName)
}

func (r *RateLimiter) recordLocked(toolName string) {
	buf, ok := r.buffers[toolName]
	if !ok {
		// Per-tool rings are capped well below the global one: a single tool
		// does not need ten thousand slots, and one map entry per tool name is
		// the memory that actually accumulates.
		capacity := r.maxEntries
		if capacity > 1000 {
			capacity = 1000
		}
		buf = newCircularTimestamps(capacity)
		r.buffers[toolName] = buf
	}
	now := nowMillis()
	buf.push(now)
	r.global.push(now)
}

// Usage is how many calls a tool has made inside the current window.
func (r *RateLimiter) Usage(toolName string) (count int, windowStart int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	windowStart = nowMillis() - r.window.Milliseconds()
	if buf, ok := r.buffers[toolName]; ok {
		count = buf.countAfter(windowStart)
	}
	return count, windowStart
}

func (r *RateLimiter) ResetTool(toolName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.buffers, toolName)
}

func (r *RateLimiter) ResetAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buffers = map[string]*circularTimestamps{}
	r.global = newCircularTimestamps(r.maxEntries)
}
