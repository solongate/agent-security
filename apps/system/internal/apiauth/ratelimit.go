package apiauth

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The port of src/lib/rate-limit.ts.
//
// The live app prefers an Upstash sliding window and falls back to a local
// token bucket when Redis is unconfigured or unreachable — and it falls back on
// EVERY error, deliberately: an Upstash blip once returned a bodyless 500 from
// every rate-limited route, including /auth/session, and the dashboard could
// not log in. The comment in the original says so.
//
// What is here is that fallback, and only that. This process does not talk to
// Upstash. The consequence is real and worth stating plainly: limits are
// per-instance, so N replicas allow N times the configured rate, and a restart
// clears every counter. The limits still EXIST — a looping agent is still
// stopped — but this is not the distributed limiter, and during the cutover the
// Node app and this one keep separate counters for the same key.

// Config is a limit: how many requests in how long.
type Config struct {
	MaxRequests int
	Window      time.Duration
}

// The named limits from src/lib/rate-limit.ts. A route slice picks one of these
// rather than writing numbers, so the limit on an endpoint is the same number
// the live app applies to it.
var (
	LimitStandard   = Config{MaxRequests: 100, Window: time.Minute}
	LimitValidation = Config{MaxRequests: 200, Window: time.Minute}
	LimitSetup      = Config{MaxRequests: 5, Window: time.Minute}
	LimitAuth       = Config{MaxRequests: 10, Window: time.Minute}
	LimitHealth     = Config{MaxRequests: 60, Window: time.Minute}
	LimitAI         = Config{MaxRequests: 20, Window: time.Minute}
	LimitDevicePoll = Config{MaxRequests: 120, Window: time.Minute}
	// LimitScanLive is the live footprint channel, and it is the one limit here
	// set by a REFRESH RATE rather than by what a client ought to need.
	//
	// Both ends of it poll on purpose. The agent posts what a scan is doing
	// about three times a second for as long as one runs, and the screen
	// watching it asks about twice a second - because a scan reads several
	// conversations a second and a counter a second behind is a counter two
	// people compare and stop believing. That is a few hundred requests a
	// minute against a bucket of a hundred, so the standard limit drained in
	// twenty seconds and then refused everything: the agent's reports stopped
	// arriving, the screen's reads 429'd, and the dashboard concluded from the
	// silence that the workspace was gone and the scan had died. Neither was
	// true, and both were this number.
	//
	// It is affordable because of what the endpoint is: one small contentless
	// document, overwritten in place, read back whole. There is no query behind
	// it and nothing to accumulate.
	LimitScanLive = Config{MaxRequests: 600, Window: time.Minute}
)

// Result is one decision. ResetAt is a wall-clock instant, which is what the
// Retry-After header is computed from.
type Result struct {
	Allowed   bool
	Remaining int
	ResetAt   time.Time
}

type bucket struct {
	tokens     float64
	lastRefill time.Time
}

// Limiter is the in-memory token bucket. Safe for concurrent use.
type Limiter struct {
	mu          sync.Mutex
	buckets     map[string]*bucket
	lastCleanup time.Time
	now         func() time.Time // injectable for tests
}

func NewLimiter() *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, lastCleanup: time.Now(), now: time.Now}
}

const cleanupInterval = 5 * time.Minute

// Check spends one token, arithmetic for arithmetic as the original.
//
// The refill is continuous rather than windowed: tokens come back at
// MaxRequests/Window per unit time, so a caller that has run out waits for one
// token rather than for the window to roll. That is why ResetAt on a REFUSAL is
// "when the next token arrives" and ResetAt on an allow is "a full window from
// now" — the two mean different things in the original and both are read, the
// first by Retry-After and the second by nothing.
func (l *Limiter) Check(key string, cfg Config) Result {
	if cfg.MaxRequests <= 0 || cfg.Window <= 0 {
		// A misconfigured limit must not become an accidental block. The live
		// app has no such guard because the configs are literals there; here a
		// zero could arrive from a caller's struct.
		return Result{Allowed: true, Remaining: 0, ResetAt: l.now()}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.cleanupLocked(now, cfg.Window)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(cfg.MaxRequests - 1), lastRefill: now}
		l.buckets[key] = b
		return Result{Allowed: true, Remaining: int(b.tokens), ResetAt: now.Add(cfg.Window)}
	}

	// tokens per nanosecond, so a sub-millisecond gap still refills a little.
	// The original works in milliseconds; the unit does not change the rate.
	rate := float64(cfg.MaxRequests) / float64(cfg.Window)
	elapsed := float64(now.Sub(b.lastRefill))
	b.tokens = math.Min(float64(cfg.MaxRequests), b.tokens+elapsed*rate)
	b.lastRefill = now

	if b.tokens < 1 {
		wait := time.Duration((1 - b.tokens) / rate)
		return Result{Allowed: false, Remaining: 0, ResetAt: now.Add(wait)}
	}

	b.tokens--
	return Result{Allowed: true, Remaining: int(math.Floor(b.tokens)), ResetAt: now.Add(cfg.Window)}
}

// cleanupLocked drops buckets nobody has touched for two windows.
//
// Without it the map is an unbounded, attacker-controlled allocation: the key
// for an unauthenticated route is the caller's IP address, and a spoofed
// X-Forwarded-For gives a new one on every request.
func (l *Limiter) cleanupLocked(now time.Time, window time.Duration) {
	if now.Sub(l.lastCleanup) < cleanupInterval {
		return
	}
	l.lastCleanup = now
	for k, b := range l.buckets {
		if now.Sub(b.lastRefill) > window*2 {
			delete(l.buckets, k)
		}
	}
}

// retryAfterSeconds is `Math.ceil((resetAt - Date.now()) / 1000)`, and never
// below one: a Retry-After of 0 tells a client to try again immediately, which
// is what it was already doing.
func retryAfterSeconds(reset time.Time, now time.Time) string {
	secs := int64(math.Ceil(reset.Sub(now).Seconds()))
	if secs < 1 {
		secs = 1
	}
	return strconv.FormatInt(secs, 10)
}

// ClientIP is the live app's IP extraction, in its order: X-Real-IP wins, then
// the FIRST entry of X-Forwarded-For, then the literal "unknown".
//
// Both headers are caller-controlled and neither is verified. That is not an
// oversight to correct here — the value only ever becomes a rate-limit bucket
// key, never an authorisation input — but it does mean the limit on the
// unauthenticated routes is evadable by anyone who sets a header, which is why
// those routes are also the cheap ones.
//
// RemoteAddr is deliberately NOT used as a fallback. Behind Railway's proxy
// every request carries the same one, so falling back to it would put every
// caller in a single bucket and five setup attempts a minute would be five for
// the whole internet.
func ClientIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		return v
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for _, part := range strings.Split(xff, ",") {
			if p := strings.TrimSpace(part); p != "" {
				return p
			}
		}
	}
	return "unknown"
}

// LimitByIP is the port of withRateLimit: the guard on the routes that have no
// API key to identify a caller by.
//
// It returns false when it has already written the 429, so a handler reads
// `if !LimitByIP(...) { return }`.
func (a *Authenticator) LimitByIP(w http.ResponseWriter, r *http.Request, cfg Config, prefix string) bool {
	key := "ip:" + ClientIP(r)
	if prefix != "" {
		key = prefix + ":" + key
	}
	res := a.limiter.Check(key, cfg)
	if res.Allowed {
		return true
	}
	w.Header().Set("Retry-After", retryAfterSeconds(res.ResetAt, time.Now()))
	Error(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please try again later.")
	return false
}
