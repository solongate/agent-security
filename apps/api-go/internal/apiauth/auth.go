package apiauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/api/internal/store"
	"github.com/codeyevsky/solongate/sgshared"
)

// API-key authentication: the port of src/lib/auth.ts.
//
// A key is `sg_live_` or `sg_test_` followed by 48 hex characters. Its first
// sixteen characters are the PREFIX, which is stored in the clear and indexed;
// the whole key is hashed with SHA-256 and only the hash is stored. So a lookup
// is: take the prefix, fetch the row, compare the hash in constant time.
//
// Three rules hold everywhere in this file and none of them is optional.
//
// A key never reaches a log line, an error body or a response. Not truncated,
// not prefixed, not "just the first eight characters" — the prefix IS eight
// characters of the key and the rest is 48 hex digits, so a leaked prefix
// narrows the search enormously. The only value that is ever printed or
// returned is the key's database id.
//
// The hash comparison is constant-time. It is not the strongest link in the
// chain — the prefix lookup is an indexed equality and leaks timing of its own
// — but a byte-by-byte compare on the hash is a direct oracle for forging one,
// and there is no reason to hand it over.
//
// The project id comes from the KEY, never from the request. Every scoped query
// in internal/store takes a project id, and the only correct source for it is
// KeyInfo.ProjectID. A route that reads `?project_id=` and passes it down is a
// cross-tenant leak with a valid key attached. There are no exceptions left: the
// one route that took a project id from a request body did so for a hosted admin
// console, and both are gone.

// KeyInfo is what a successful authentication yields. It is src/lib/auth.ts's
// ApiKeyInfo, field for field.
//
// TokenSecret is a signing key. It is here because the capability-token routes
// need it without a second query, and it must not travel any further than
// those.
type KeyInfo struct {
	ProjectID   string
	OwnerID     string
	KeyPrefix   string
	KeyID       string
	KeyName     string
	IsLive      bool
	TokenSecret string

	// ActingUserID is whose key this is. OwnerID is whose PROJECT it opens, and
	// those are the same person for everyone except a guest.
	//
	// OwnerID keeps its meaning exactly: nine organisation routes and every
	// project route treat it as the authorization subject, and quietly turning
	// it into "the caller" would hand a guest the host's authority at all of
	// them. This is a new field beside it, empty for a key issued before
	// api_keys.user_id existed.
	ActingUserID string
}

// ActingUser is who to attribute this request to.
//
// A key with no user recorded acts as the project's owner, which is what every
// key issued before api_keys.user_id existed IS: the owner's own key, on the
// owner's own project. Nothing that reads this can tell the two apart, and
// nothing should — the difference only matters to the guest check, which asks a
// different question.
func (k KeyInfo) ActingUser() string {
	if k.ActingUserID != "" {
		return k.ActingUserID
	}
	return k.OwnerID
}

// Authenticator holds what authentication needs: the database, the limiter and
// the buffer of keys whose last-used stamp is owed a write.
type Authenticator struct {
	store   *store.Store
	limiter *Limiter

	pendingMu sync.Mutex
	pending   map[string]struct{}

	seenMu sync.RWMutex
	seen   map[string]seenKey
}

// seenKey is one recently authenticated key. See keyCacheTTL.
type seenKey struct {
	info KeyInfo
	at   time.Time
}

// keyCacheTTL is how long a validated key is trusted without asking the
// database again.
//
// Every authenticated request in this service starts with one AuthLookup, and
// AuthLookup is an HTTP POST to Turso — the driver sends one request per
// statement. A dashboard page that makes seven API calls therefore spends seven
// round trips proving the same key seven times, before any of them has read
// what it came for. This is the whole of that cost, removed.
//
// Ten seconds, and it is a deliberate choice rather than a round number. The
// window is what a revoked key keeps working for, so it is short enough that
// "I revoked it" and "it stopped working" are the same moment to a person
// watching, and revocation purges the entry outright (Forget) so the window
// only ever applies to a key revoked by some OTHER process — a manage-panel
// action, or a second instance of this service.
//
// Nothing else is cached with it. The row's project and owner are what the key
// IS, so they cannot go stale without the key itself being revoked; anything
// that can change under a live key — the policy, the layers, the fleet grant —
// is read per request as before.
const keyCacheTTL = 10 * time.Second

// keyCacheMax bounds the map. It is not a working-set estimate: it is the point
// past which the map is being filled by something other than this service's
// users, and dropping it whole is cheaper than evicting cleverly.
const keyCacheMax = 4096

func New(st *store.Store, lim *Limiter) *Authenticator {
	return &Authenticator{
		store:   st,
		limiter: lim,
		pending: map[string]struct{}{},
		seen:    map[string]seenKey{},
	}
}

// Forget drops a key from the cache by its database id. Called when a key is
// revoked, so the revocation takes effect on the next request rather than at
// the end of the TTL.
func (a *Authenticator) Forget(keyID string) {
	a.seenMu.Lock()
	for hash, entry := range a.seen {
		if entry.info.KeyID == keyID {
			delete(a.seen, hash)
		}
	}
	a.seenMu.Unlock()
}

// cachedKey is the lookup. The map is keyed by the SHA-256 of the WHOLE key,
// not by the prefix: two keys can share a prefix, and a cache hit on a prefix
// would authenticate the wrong one without ever comparing a hash.
func (a *Authenticator) cachedKey(hash string) (KeyInfo, bool) {
	a.seenMu.RLock()
	entry, ok := a.seen[hash]
	a.seenMu.RUnlock()
	if !ok || time.Since(entry.at) > keyCacheTTL {
		return KeyInfo{}, false
	}
	return entry.info, true
}

func (a *Authenticator) rememberKey(hash string, info KeyInfo) {
	a.seenMu.Lock()
	if len(a.seen) >= keyCacheMax {
		a.seen = map[string]seenKey{}
	}
	a.seen[hash] = seenKey{info: info, at: time.Now()}
	a.seenMu.Unlock()
}

// Limiter exposes the shared limiter, for the health route and anything else
// that limits without authenticating.
func (a *Authenticator) Limiter() *Limiter { return a.limiter }

const lastUsedFlushInterval = time.Minute

// StartLastUsedFlusher writes buffered last-used stamps on a timer.
//
// Batched because it is a WRITE on the hot path of every authenticated request,
// and this service is polled by every installed guard on a loop — one UPDATE
// per poll against Turso is a round trip that buys a timestamp nobody reads in
// real time. The live app buffers for a minute and flushes the set; this does
// the same.
//
// It returns when ctx is done, flushing once more on the way out so a graceful
// shutdown does not throw the last minute away.
func (a *Authenticator) StartLastUsedFlusher(ctx context.Context) {
	ticker := time.NewTicker(lastUsedFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			a.flushLastUsed(context.WithoutCancel(ctx))
			return
		case <-ticker.C:
			a.flushLastUsed(ctx)
		}
	}
}

func (a *Authenticator) markKeyUsed(keyID string) {
	a.pendingMu.Lock()
	a.pending[keyID] = struct{}{}
	a.pendingMu.Unlock()
}

func (a *Authenticator) flushLastUsed(ctx context.Context) {
	a.pendingMu.Lock()
	if len(a.pending) == 0 {
		a.pendingMu.Unlock()
		return
	}
	ids := make([]string, 0, len(a.pending))
	for id := range a.pending {
		ids = append(ids, id)
	}
	a.pending = map[string]struct{}{}
	a.pendingMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := a.store.TouchKeysUsed(ctx, ids, store.Now()); err != nil {
		// Put them back and try on the next tick. The ids are database ids, not
		// keys, so this line is safe — and it says how many rather than which,
		// because a list of key ids in a log is a list of what to look for.
		a.pendingMu.Lock()
		for _, id := range ids {
			a.pending[id] = struct{}{}
		}
		a.pendingMu.Unlock()
		log.Printf("api: failed to flush last_used_at for %d keys: %v", len(ids), err)
	}
}

// ExtractKey pulls the presented key out of the request, in the live app's
// order of preference: X-API-Key first, then `Authorization: Bearer <key>`,
// then a bare key in Authorization.
//
// The bare-Authorization form is not a mistake to clean up. Installed hooks
// send it.
func ExtractKey(r *http.Request) string {
	if v := r.Header.Get("X-API-Key"); strings.HasPrefix(v, "sg_") {
		return v
	}
	auth := r.Header.Get("Authorization")
	switch {
	case strings.HasPrefix(auth, "Bearer "):
		return auth[len("Bearer "):]
	case strings.HasPrefix(auth, "sg_"):
		return auth
	}
	return ""
}

// HashAPIKey is SHA-256 over the key's bytes, lowercase hex.
//
// The live app hashes `new TextEncoder().encode(apiKey)`, which is UTF-8 — the
// same bytes Go sees. That agreement is not automatic and the repository has
// already paid for assuming it once: sgshared exists because a hash was
// computed over UTF-16 code units in one implementation and bytes in another.
// A key is ASCII by construction, so the two cannot diverge here, and this
// comment is why nobody has to re-derive that.
func HashAPIKey(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])
}

// GenerateAPIKey mints `sg_live_` or `sg_test_` plus 24 random bytes as hex.
//
// crypto/rand, and its error is fatal rather than swallowed. A key built from a
// degraded random source is a key somebody else can predict, and returning one
// with an error nobody checks is worse than not starting.
func GenerateAPIKey(isLive bool) (string, error) {
	prefix := "sg_test_"
	if isLive {
		prefix = "sg_live_"
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

// GenerateTokenSecret mints a project's capability-token signing secret: 32
// random bytes as hex, as src/lib/auth.ts does.
func GenerateTokenSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ErrNoKey and ErrBadKey separate "nothing was presented" from "what was
// presented is not valid". Both become the same 401 to the caller — see
// Unauthorized — and the distinction exists only so a caller inside this
// process can tell them apart.
var (
	ErrNoKey  = errors.New("apiauth: no api key presented")
	ErrBadKey = errors.New("apiauth: api key rejected")
)

// Validate resolves a presented key to a project.
//
// sgshared.IsRealKey is the format gate rather than a local prefix check, and
// it is stricter than the live app's `startsWith`: it also rejects the sample
// values that ship in the .env templates. That matters more than a format check
// looks — a placeholder key means "no project", and to the guard "no project"
// means ALLOW, so a stray `sg_live_your_key_here` silently disarms it. Rejecting
// the shape here costs a round trip that would have 401'd anyway.
func (a *Authenticator) Validate(ctx context.Context, r *http.Request) (KeyInfo, error) {
	apiKey := ExtractKey(r)
	if apiKey == "" {
		return KeyInfo{}, ErrNoKey
	}
	if !sgshared.IsRealKey(apiKey) {
		return KeyInfo{}, ErrBadKey
	}
	// IsRealKey guarantees at least `sg_live_` plus sixteen hex, so the slice
	// cannot be out of range. The guarantee is stated because a bare k[:16] on
	// caller input is otherwise a panic waiting for a short key.
	prefix := apiKey[:16]
	hash := HashAPIKey(apiKey)

	// The cache is consulted only after the key has been shown to be a key.
	// last_used_at is still stamped on a hit, or a key in constant use would
	// look idle.
	if info, ok := a.cachedKey(hash); ok {
		a.markKeyUsed(info.KeyID)
		return info, nil
	}

	row, err := a.store.AuthLookup(ctx, prefix)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return KeyInfo{}, ErrBadKey
		}
		return KeyInfo{}, err
	}

	if !constantTimeHexEqual(row.KeyHash, hash) {
		return KeyInfo{}, ErrBadKey
	}

	a.markKeyUsed(row.KeyID)

	info := KeyInfo{
		ProjectID:    row.ProjectID,
		OwnerID:      row.OwnerID,
		KeyPrefix:    row.KeyPrefix,
		KeyID:        row.KeyID,
		KeyName:      row.KeyName,
		IsLive:       row.IsLive,
		TokenSecret:  row.TokenSecret,
		ActingUserID: row.UserID,
	}
	// Only a key that passed the hash comparison is remembered. A failed
	// comparison caches nothing, so a wrong key is a database lookup every time
	// and cannot be used to fill the map.
	a.rememberKey(hash, info)
	return info, nil
}

// constantTimeHexEqual compares two hex digests without leaking where they
// diverge.
//
// The values are decoded first and compared as bytes, as the live app's
// Buffer.from(hex) + timingSafeEqual does. Comparing the hex STRINGS with
// subtle.ConstantTimeCompare would be just as constant-time but would also make
// `AB…` and `ab…` unequal, and nothing guarantees the case of a hash written by
// an older client.
//
// A stored value that is not hex, or is the wrong length, is false rather than
// an error: it is a row that cannot match any key, and treating it as a server
// error would turn one corrupt row into a 500 on a login attempt.
func constantTimeHexEqual(storedHex, computedHex string) bool {
	stored, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(storedHex)))
	if err != nil {
		return false
	}
	computed, err := hex.DecodeString(computedHex)
	if err != nil {
		return false
	}
	if len(stored) != len(computed) {
		return false
	}
	return subtle.ConstantTimeCompare(stored, computed) == 1
}

// ── the wrapper the route slices use ────────────────────────────────────────

// Handler is a route body that has already been authenticated. The KeyInfo is
// passed rather than stashed in the context so a handler cannot forget to fetch
// it and silently operate unscoped.
type Handler func(w http.ResponseWriter, r *http.Request, key KeyInfo)

// WithAuth is the port of src/lib/auth.ts's withAuth, at the standard limit.
func (a *Authenticator) WithAuth(next Handler) http.Handler {
	return a.WithAuthLimit(LimitStandard, next)
}

// WithAuthLimit authenticates, then rate-limits per KEY, then runs the handler.
//
// The order matters and is the original's: an unauthenticated request is
// refused before it can consume anyone's budget, so an attacker cannot exhaust
// a victim's limit by presenting their key prefix.
//
// X-RateLimit-Remaining is set BEFORE the handler runs, which is the only place
// it can be set in Go — headers are frozen once anything is written. The live
// app sets it on the returned response object, which amounts to the same thing.
func (a *Authenticator) WithAuthLimit(cfg Config, next Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, err := a.Validate(r.Context(), r)
		if err != nil {
			if !errors.Is(err, ErrNoKey) && !errors.Is(err, ErrBadKey) {
				// A database failure is not an authentication failure. Saying
				// 401 here would send a working client off to re-authenticate
				// over an outage it cannot fix.
				Internal(w, "auth", err)
				return
			}
			Unauthorized(w)
			return
		}

		// The bucket is the key PREFIX and the PATH, not the key alone. Not the
		// key: a rate-limit map keyed by secrets is a map that leaks them to
		// anything that ever dumps it. And not one bucket for the whole key: the
		// Shadow agent's own heartbeat and policy poll shared a single per-key
		// bucket with the operator's TUI, and the TUI's live panels (forty to
		// sixty reads a minute) drained it, so the agent's beats 429'd and a new
		// version took the two-minute heartbeat tick to reach the roster instead
		// of the next five-second poll. Per-path, the agent's low-rate routes
		// keep their own budget whatever the TUI is doing, and a runaway on one
		// endpoint no longer starves the rest. The limit numbers are unchanged;
		// only the bucket they are counted in is finer.
		res := a.limiter.Check("key:"+key.KeyPrefix+"|"+r.URL.Path, cfg)
		if !res.Allowed {
			w.Header().Set("Retry-After", retryAfterSeconds(res.ResetAt, time.Now()))
			w.Header().Set("X-RateLimit-Remaining", "0")
			Error(w, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests. Please slow down.")
			return
		}
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))

		next(w, r, key)
	})
}
