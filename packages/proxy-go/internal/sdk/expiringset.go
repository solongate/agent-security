package sdk

import (
	"sync"
	"time"
)

// ExpiringSet remembers a value for a while and then forgets it.
//
// It backs replay prevention: a nonce has to be remembered long enough that
// replaying it fails, and forgotten soon after or a long-running gateway grows
// a set that never shrinks. A memory leak in the thing tracking used tokens is
// a denial of service against the gateway itself.
type ExpiringSet struct {
	mu        sync.Mutex
	entries   map[string]time.Time
	ttl       time.Duration
	sweepFreq time.Duration
	lastSweep time.Time
}

func NewExpiringSet(ttl time.Duration) *ExpiringSet {
	// Sweeping every TTL at the earliest, and never more often than once a
	// minute: the sweep is O(n) and a short TTL would otherwise make every add
	// walk the whole set.
	sweep := ttl
	if sweep < time.Minute {
		sweep = time.Minute
	}
	return &ExpiringSet{entries: map[string]time.Time{}, ttl: ttl, sweepFreq: sweep}
}

func (s *ExpiringSet) Add(value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[value] = time.Now()
	s.maybeSweep()
}

// Has drops an expired entry as it finds it, so a value never reads as present
// past its TTL even if no sweep has run.
func (s *ExpiringSet) Has(value string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts, ok := s.entries[value]
	if !ok {
		return false
	}
	if time.Since(ts) > s.ttl {
		delete(s.entries, value)
		return false
	}
	return true
}

func (s *ExpiringSet) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeSweep()
	return len(s.entries)
}

// maybeSweep must be called with the lock held.
func (s *ExpiringSet) maybeSweep() {
	now := time.Now()
	if now.Sub(s.lastSweep) < s.sweepFreq {
		return
	}
	s.lastSweep = now
	cutoff := now.Add(-s.ttl)
	for k, ts := range s.entries {
		if ts.Before(cutoff) {
			delete(s.entries, k)
		}
	}
}
