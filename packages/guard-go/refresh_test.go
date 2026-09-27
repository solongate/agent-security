package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/codeyevsky/solongate/sgshared"
)

// A cache with no timestamp, or none at all, is stale: there is nothing to
// trust, and treating it as current is how a machine goes on enforcing a policy
// nobody can see any more.
func TestCacheStalenessTreatsTheUnknownAsStale(t *testing.T) {
	now := time.Now().UnixMilli()

	for _, tc := range []struct {
		name  string
		cache *sgshared.PolicyCache
		want  bool
	}{
		{"absent", nil, true},
		{"no timestamp", &sgshared.PolicyCache{}, true},
		{"written just now", &sgshared.PolicyCache{TS: now}, false},
		{"one second old", &sgshared.PolicyCache{TS: now - 1_000}, false},
		{"exactly at the TTL", &sgshared.PolicyCache{TS: now - int64(policyCacheTTL/time.Millisecond)}, true},
		{"a minute old", &sgshared.PolicyCache{TS: now - 60_000}, true},
		// A clock that moved backwards leaves a timestamp in the future. Reading
		// that as fresh would pin the cache until the clock caught up.
		{"written in the future", &sgshared.PolicyCache{TS: now + 60_000}, false},
	} {
		if got := cacheIsStale(tc.cache); got != tc.want {
			t.Errorf("%s: cacheIsStale = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The wait is a bound, not a requirement. A refresh that does not land in time
// leaves the call to be answered from the cache, exactly as it was before the
// wait existed — the child keeps running and its write lands for the next call.
func TestWaitForRefreshIsBounded(t *testing.T) {
	never := make(chan struct{})
	start := time.Now()
	if waitForRefresh(never, 50*time.Millisecond) {
		t.Error("a refresh that never lands must not report success")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("waited %v for a 50ms bound", elapsed)
	}

	landed := make(chan struct{})
	close(landed)
	if !waitForRefresh(landed, 50*time.Millisecond) {
		t.Error("a refresh that already landed must report success")
	}
}

// Returning nil rather than a channel is how the caller learns there is nothing
// to wait for. An unpaired machine has no key and no refresh to make.
func TestRefreshIsNotAttemptedWithoutAKey(t *testing.T) {
	if done := refreshPolicyDetached(sgshared.Credential{APIURL: "https://example.invalid"}, "claude-code"); done != nil {
		t.Error("a machine with no key must not spawn a refresh")
	}
}

// A refresh with nothing to talk to fails fast and reports it, so the caller
// falls through to the cache rather than treating a failure as a fresh policy.
func TestFetchReportsFailureRatherThanClaimingSuccess(t *testing.T) {
	if fetchAndWriteCache("", "key", "claude-code", 50*time.Millisecond) {
		t.Error("no URL is not a successful refresh")
	}
	if fetchAndWriteCache("https://example.invalid", "", "claude-code", 50*time.Millisecond) {
		t.Error("no key is not a successful refresh")
	}
	if fetchAndWriteCache("http://127.0.0.1:9", "key", "claude-code", 50*time.Millisecond) {
		t.Error("an unreachable API is not a successful refresh")
	}
}

// Two refreshes overlap whenever two tool calls do. A slow one that started
// before a rule was added and lands after a fast one would otherwise overwrite
// the new policy with the old, under a fresh timestamp — an intermittent stale
// ALLOW that leaves nothing behind to find.
func TestACacheIsNeverReplacedByAnOlderVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	write := func(v int64) {
		body := `{"_ts":1,"policy":{"id":"p"},"policyVersion":` + strconv.FormatInt(v, 10) + `}`
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write(12)
	if got := readCachedVersion(path); got != 12 {
		t.Fatalf("readCachedVersion = %d, want 12", got)
	}

	// A cache with no version is one written by an older build or by the Node
	// hook. Refusing to replace it would freeze the machine on what it holds.
	if err := os.WriteFile(path, []byte(`{"_ts":1,"policy":{"id":"p"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readCachedVersion(path); got != 0 {
		t.Errorf("a cache with no version must read as 0, got %d", got)
	}

	// Absent and unreadable are the same answer, for the same reason.
	if got := readCachedVersion(filepath.Join(dir, "nothing.json")); got != 0 {
		t.Errorf("an absent cache must read as 0, got %d", got)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readCachedVersion(path); got != 0 {
		t.Errorf("a torn cache must read as 0, got %d", got)
	}
}

// The managed flag has to survive the decode, and this is the test that says so
// against the WRITER rather than against a file somebody wrote by hand.
//
// The bug it pins: fetchAndWriteCache unmarshals the response into
// map[string]json.RawMessage so an unknown field survives the round trip, which
// makes every value in that map a []byte. jsonTrue used to take interface{} and
// type-assert to bool, an assertion []byte can never satisfy, so `managed` read
// false for every response the API ever sent. And because sgshared.SaveFleet
// writes only on a CHANGE, false matched the zero value and the file was never
// created at all — on any machine, ever.
//
// Nothing caught it because the only managed test in the tree writes
// ~/.solongate/.fleet.json with os.WriteFile and then reads it back. That tests
// the reader against a file the writer could not produce. This one goes through
// the HTTP response, the decode and SaveFleet, which is where it broke.
func TestManagedSurvivesTheDecode(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"managed", `{"policy":{"id":"p"},"self_protection_enabled":true,"managed":true}`, true},
		{"not managed", `{"policy":{"id":"p"},"managed":false}`, false},
		// The API sends managed with omitempty, so an unmanaged machine gets no
		// key at all. That has to read as false rather than as a failure.
		{"absent", `{"policy":{"id":"p"}}`, false},
		// A value this code does not recognise must not be read as an
		// instruction, which is the same rule self_protection_enabled follows.
		{"null", `{"policy":{"id":"p"},"managed":null}`, false},
		{"string", `{"policy":{"id":"p"},"managed":"true"}`, false},
		{"number", `{"policy":{"id":"p"},"managed":1}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			if !fetchAndWriteCache(srv.URL, "key", "claude-code", 5*time.Second) {
				t.Fatal("the refresh did not report success")
			}
			if got := sgshared.LoadFleet().Managed; got != tc.want {
				t.Errorf("Managed = %v, want %v", got, tc.want)
			}
			// The file only has to exist when the answer is true. SaveFleet
			// writes on a change and false IS the zero value it starts from, so
			// an unmanaged machine correctly keeps no file.
			_, err := os.Stat(sgshared.FleetStatePath())
			if tc.want && err != nil {
				t.Errorf("a managed machine has no fleet state on disk: %v", err)
			}
			if !tc.want && err == nil {
				t.Error("an unmanaged machine wrote a fleet state file it did not need")
			}
		})
	}
}

// Revocation has to reach the machine too. A host who takes a developer back
// out of the fleet stops sending managed, and the guard has to notice: the file
// is the only thing standing between a released machine and the escapes that
// managed closes.
func TestManagedClearsWhenTheGrantGoesAway(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	managed := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if managed {
			_, _ = w.Write([]byte(`{"policy":{"id":"p"},"managed":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"policy":{"id":"p"}}`))
	}))
	defer srv.Close()

	if !fetchAndWriteCache(srv.URL, "key", "claude-code", 5*time.Second) {
		t.Fatal("the first refresh did not report success")
	}
	if !sgshared.LoadFleet().Managed {
		t.Fatal("the machine did not come under management")
	}

	managed = false
	if !fetchAndWriteCache(srv.URL, "key", "claude-code", 5*time.Second) {
		t.Fatal("the second refresh did not report success")
	}
	if sgshared.LoadFleet().Managed {
		t.Error("the machine is still managed after the grant was withdrawn")
	}
}
