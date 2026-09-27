package apiauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Tests for the three things in this package that are contracts rather than
// code: what a key looks like, what a failure body looks like, and how the
// limiter counts.

func TestExtractKeyPrefersXAPIKeyThenBearerThenBare(t *testing.T) {
	const live = "sg_live_" + "0123456789abcdef0123456789abcdef0123456789abcdef"
	const test = "sg_test_" + "fedcba9876543210fedcba9876543210fedcba9876543210"

	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"x-api-key wins", map[string]string{"X-API-Key": live, "Authorization": "Bearer " + test}, live},
		{"bearer", map[string]string{"Authorization": "Bearer " + live}, live},
		// Installed hooks send the key bare in Authorization. Dropping this
		// branch would 401 every one of them.
		{"bare authorization", map[string]string{"Authorization": live}, live},
		{"x-api-key that is not a key is ignored", map[string]string{"X-API-Key": "nope", "Authorization": "Bearer " + test}, test},
		{"nothing", map[string]string{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := ExtractKey(r); got != tc.want {
				t.Errorf("ExtractKey = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGeneratedKeysHaveTheExpectedShape(t *testing.T) {
	for _, live := range []bool{true, false} {
		k, err := GenerateAPIKey(live)
		if err != nil {
			t.Fatalf("GenerateAPIKey: %v", err)
		}
		prefix := "sg_test_"
		if live {
			prefix = "sg_live_"
		}
		if !strings.HasPrefix(k, prefix) {
			t.Errorf("%q does not start with %q", k, prefix)
		}
		// 8 characters of prefix plus 24 bytes as hex. The lookup slices the
		// first sixteen characters, so anything shorter would panic there.
		if len(k) != len(prefix)+48 {
			t.Errorf("len(%q) = %d, want %d", k, len(k), len(prefix)+48)
		}
	}
}

func TestConstantTimeHexEqual(t *testing.T) {
	const a = "0123456789abcdef"
	cases := []struct {
		name             string
		stored, computed string
		want             bool
	}{
		{"equal", a, a, true},
		// A hash written by an older client may be upper-case. Comparing the
		// strings rather than the decoded bytes would call these unequal.
		{"case-insensitive", strings.ToUpper(a), a, true},
		{"different", a, "fedcba9876543210", false},
		{"different length", a, a + "00", false},
		{"stored is not hex", "zzzz", a, false},
		{"stored is empty", "", a, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := constantTimeHexEqual(tc.stored, tc.computed); got != tc.want {
				t.Errorf("constantTimeHexEqual(%q, %q) = %v, want %v", tc.stored, tc.computed, got, tc.want)
			}
		})
	}
}

func TestHashAPIKeyIsSHA256Hex(t *testing.T) {
	// The value the live app's crypto.subtle.digest('SHA-256', utf8) produces
	// for this input. If these ever disagree, every key in the database stops
	// authenticating at once.
	const in = "sg_live_0123456789abcdef"
	const want = "078672a9dc55b9267e1398a69531bce7ba35998b4e34608cb7f02d1b62d01f23"
	if got := HashAPIKey(in); got != want {
		t.Errorf("HashAPIKey(%q) = %q, want %q", in, got, want)
	}
}

func TestErrorBodyIsTheDeployedShape(t *testing.T) {
	rec := httptest.NewRecorder()
	Unauthorized(rec)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var body map[string]map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if body["error"]["code"] != "AUTHENTICATION_ERROR" || body["error"]["message"] != "Invalid API key" {
		t.Errorf("body = %v, want the live app's envelope", body)
	}
}

func TestJSONDoesNotEscapeHTML(t *testing.T) {
	// A policy's command constraint. Go's default encoder would rewrite the
	// ampersands and angle brackets into \u0026, \u003c and \u003e, and the
	// guard hashes the bytes it receives.
	rec := httptest.NewRecorder()
	JSON(rec, 200, map[string]string{"command": "sh -c 'a && b' <input >output"})

	got := rec.Body.String()
	for _, escaped := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if strings.Contains(got, escaped) {
			t.Errorf("body = %s, contains %s; JSON.stringify leaves the character alone", got, escaped)
		}
	}
	if !strings.Contains(got, "a && b") {
		t.Errorf("body = %s, want the command verbatim", got)
	}
	if strings.HasSuffix(got, "\n") {
		t.Error("body has a trailing newline; JSON.stringify does not add one")
	}
}

func TestLimiterRefusesPastTheLimitAndRefills(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewLimiter()
	l.now = func() time.Time { return now }

	cfg := Config{MaxRequests: 3, Window: time.Minute}
	for i := 0; i < 3; i++ {
		if res := l.Check("k", cfg); !res.Allowed {
			t.Fatalf("request %d refused, the first %d must pass", i+1, cfg.MaxRequests)
		}
	}
	res := l.Check("k", cfg)
	if res.Allowed {
		t.Fatal("the fourth request must be refused")
	}
	if !res.ResetAt.After(now) {
		t.Error("ResetAt on a refusal must be in the future; Retry-After is computed from it")
	}

	// One token comes back after a third of the window, since the bucket
	// refills continuously rather than at a window boundary.
	now = now.Add(21 * time.Second)
	if res := l.Check("k", cfg); !res.Allowed {
		t.Error("a token should have refilled")
	}
}

func TestLimiterBucketsAreIndependent(t *testing.T) {
	l := NewLimiter()
	cfg := Config{MaxRequests: 1, Window: time.Minute}
	if !l.Check("key:sg_live_aaaa", cfg).Allowed {
		t.Fatal("first key refused")
	}
	if !l.Check("key:sg_live_bbbb", cfg).Allowed {
		t.Error("one key's budget must not be spent by another's")
	}
}

func TestClientIPPrefersRealIPThenFirstForwarded(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"x-real-ip", map[string]string{"X-Real-IP": " 203.0.113.7 "}, "203.0.113.7"},
		{"first forwarded", map[string]string{"X-Forwarded-For": "203.0.113.7, 10.0.0.1"}, "203.0.113.7"},
		{"real-ip wins", map[string]string{"X-Real-IP": "198.51.100.1", "X-Forwarded-For": "203.0.113.7"}, "198.51.100.1"},
		// Never RemoteAddr: behind the platform proxy every request carries the
		// same one, and one bucket for the whole internet is not a limit.
		{"neither", map[string]string{}, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := ClientIP(r); got != tc.want {
				t.Errorf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRateLimitedResponseCarriesRetryAfter(t *testing.T) {
	a := New(nil, NewLimiter())
	cfg := Config{MaxRequests: 1, Window: time.Minute}

	r := httptest.NewRequest("POST", "/api/v1/setup", nil)
	r.Header.Set("X-Real-IP", "203.0.113.9")

	if !a.LimitByIP(httptest.NewRecorder(), r, cfg, "setup") {
		t.Fatal("the first request must pass")
	}
	rec := httptest.NewRecorder()
	if a.LimitByIP(rec, r, cfg, "setup") {
		t.Fatal("the second request must be refused")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Retry-After is missing; the CLI backs off on it")
	}
	var body map[string]map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"]["code"] != "RATE_LIMITED" {
		t.Errorf("code = %q, want RATE_LIMITED", body["error"]["code"])
	}
}

// ── the validated-key cache ─────────────────────────────────────────────────
//
// These tests are about the two ways a cache on an authentication path can be
// wrong: handing a hit to a key that did not earn it, and outliving a
// revocation. Neither reaches the database, because the cache is in front of
// it — which is exactly why it has to be checked without one.

func cacheTestAuth() *Authenticator {
	return &Authenticator{pending: map[string]struct{}{}, seen: map[string]seenKey{}}
}

func TestCacheHitRequiresTheWholeKey(t *testing.T) {
	a := cacheTestAuth()
	// Two keys sharing a prefix. That is not hypothetical: the prefix is the
	// first sixteen characters and it is what the database lookup is keyed by,
	// so a cache keyed the same way would authenticate the wrong row.
	live := "sg_live_" + strings.Repeat("a", 48)
	other := "sg_live_" + strings.Repeat("a", 8) + strings.Repeat("b", 40)
	if live[:16] != other[:16] {
		t.Fatal("the fixtures do not share a prefix, so this proves nothing")
	}

	a.rememberKey(HashAPIKey(live), KeyInfo{ProjectID: "proj-live", KeyID: "key-1"})

	if info, ok := a.cachedKey(HashAPIKey(live)); !ok || info.ProjectID != "proj-live" {
		t.Fatalf("the key that was cached did not hit: %+v ok=%v", info, ok)
	}
	if _, ok := a.cachedKey(HashAPIKey(other)); ok {
		t.Error("a different key with the same prefix hit the cache")
	}
}

func TestCacheEntryExpires(t *testing.T) {
	a := cacheTestAuth()
	hash := HashAPIKey("sg_live_" + strings.Repeat("c", 48))
	a.seen[hash] = seenKey{info: KeyInfo{KeyID: "key-1"}, at: time.Now().Add(-keyCacheTTL - time.Second)}
	if _, ok := a.cachedKey(hash); ok {
		t.Error("an entry older than the TTL was served")
	}
}

func TestRevocationDropsTheCachedKey(t *testing.T) {
	a := cacheTestAuth()
	mine := HashAPIKey("sg_live_" + strings.Repeat("d", 48))
	theirs := HashAPIKey("sg_live_" + strings.Repeat("e", 48))
	a.rememberKey(mine, KeyInfo{KeyID: "key-1", ProjectID: "p"})
	a.rememberKey(theirs, KeyInfo{KeyID: "key-2", ProjectID: "p"})

	a.Forget("key-1")

	if _, ok := a.cachedKey(mine); ok {
		t.Error("a revoked key is still authenticating from the cache")
	}
	if _, ok := a.cachedKey(theirs); !ok {
		t.Error("revoking one key dropped another")
	}
}

func TestCacheDoesNotGrowWithoutBound(t *testing.T) {
	a := cacheTestAuth()
	for i := 0; i < keyCacheMax+10; i++ {
		a.rememberKey(HashAPIKey("sg_live_"+strconv.Itoa(i)+strings.Repeat("f", 40)), KeyInfo{KeyID: "k"})
	}
	if len(a.seen) > keyCacheMax {
		t.Errorf("cache holds %d entries, past its own cap of %d", len(a.seen), keyCacheMax)
	}
}
