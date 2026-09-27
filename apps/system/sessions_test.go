package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/codeyevsky/solongate/system/internal/store"
)

// The counters are recounted from audit rows on every read, and the rules for
// which counter a call lands in are the whole reason: a call is either a DLP
// event or a rate-limit event, never both, and dlp wins.
func TestTallySessionCallsAttributesOneSignalPerCall(t *testing.T) {
	scanner := newDLPScanner(store.DefaultSecurityLayers())

	// Assembled rather than written out, so this file is not itself something a
	// secret scanner has to ignore.
	secret := `{"command":"export K=` + "AKIA" + strings.Repeat("X", 16) + `"}`
	rows := []store.SessionCall{
		// Minute 10: three calls, which a limit of three does not exceed.
		{Decision: "ALLOW", CreatedAt: 600},
		{Decision: "DENY", Reason: "Denied by rule bash-guard", CreatedAt: 600},
		// A denial that names rate limiting is a burst whatever the counting
		// says: the calls that would have proved it were never made.
		{Decision: "DENY", Reason: "Security layer (rate limit): blocked", CreatedAt: 600},
		// Minute 20: four calls, which it does. The first carries a secret AND
		// lands in that burst, and counts once — as DLP.
		{Decision: "ALLOW", ArgumentsSummary: secret, CreatedAt: 1200},
		{Decision: "ALLOW", CreatedAt: 1200},
		{Decision: "ALLOW", CreatedAt: 1200},
		// An empty decision reads as ALLOW, as `String(d || 'ALLOW')` does.
		{Decision: "", CreatedAt: 1200},
	}

	got := tallySessionCalls(rows, scanner, 3)
	want := sessionTally{total: 7, allowed: 5, denied: 2, dlp: 1, rateLimit: 4}
	if got != want {
		t.Errorf("tally = %+v, want %+v", got, want)
	}

	// With no limit in force nothing can be a burst, and the rate-limit DENIAL
	// still is — it is evidence rather than a count.
	got = tallySessionCalls(rows, scanner, 0)
	want = sessionTally{total: 7, allowed: 5, denied: 2, dlp: 1, rateLimit: 1}
	if got != want {
		t.Errorf("tally with no limit = %+v, want %+v", got, want)
	}
}

func TestDeniedSpellingsBothCountAsDenied(t *testing.T) {
	scanner := newDLPScanner(store.DefaultSecurityLayers())
	got := tallySessionCalls([]store.SessionCall{
		{Decision: "denied"}, {Decision: "deny"}, {Decision: "allow"},
	}, scanner, 0)
	if got.denied != 2 || got.allowed != 1 {
		t.Errorf("tally = %+v, want two denied and one allowed", got)
	}
}

func TestEffectivePerMinute(t *testing.T) {
	layers := store.DefaultSecurityLayers()
	if got := effectivePerMinute(layers, nil); got != 120 {
		t.Errorf("detect mode = %d, want the configured limit", got)
	}

	layers.RateLimit.Mode = store.LayerOff
	if got := effectivePerMinute(layers, nil); got != 0 {
		t.Errorf("off with no history = %d, want 0 — nothing can be a burst", got)
	}
	// A project that turned rate limiting off keeps the bursts it recorded while
	// it was on, which is what the history clause is for.
	if got := effectivePerMinute(layers, []store.RateLimitChange{{TS: 1, Minute: 60}}); got != 120 {
		t.Errorf("off with history = %d, want the configured limit", got)
	}
}

func TestPhaseOf(t *testing.T) {
	cases := map[string]string{
		"READ": "Exploration", "read": "Exploration",
		"WRITE": "Modification", "EXECUTE": "Execution", "NETWORK": "Network",
		"": "Other", "SOMETHING": "Other",
	}
	for in, want := range cases {
		if got := phaseOf(in); got != want {
			t.Errorf("phaseOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCallPreviewPicksTheFirstTrackedKey(t *testing.T) {
	// The key ORDER is the point: a Bash call's command says more than its
	// timeout, so the list is walked rather than the object.
	if got := callPreview(`{"timeout":5,"path":"/etc/hosts","command":"ls -la"}`, "Bash"); got != "ls -la" {
		t.Errorf("preview = %q, want the command", got)
	}
	// Only the first line, trimmed.
	if got := callPreview(`{"command":"  git commit\n\nbody here"}`, "Bash"); got != "git commit" {
		t.Errorf("preview = %q, want the first line", got)
	}
	// No tracked key, a non-object, and a truncated column all fall back to the
	// tool name. arguments_summary is cut on write, so the last is expected.
	for _, summary := range []string{`{"other":"x"}`, `"a string"`, `{truncated`, ""} {
		if got := callPreview(summary, "WebFetch"); got != "WebFetch" {
			t.Errorf("preview(%q) = %q, want the tool name", summary, got)
		}
	}
	// An empty string in a tracked key is skipped rather than shown.
	if got := callPreview(`{"command":"   ","path":"/tmp/x"}`, "Bash"); got != "/tmp/x" {
		t.Errorf("preview = %q, want the next key with content", got)
	}

	long := strings.Repeat("a", 200)
	got := callPreview(`{"command":"`+long+`"}`, "Bash")
	if len([]rune(got)) != 121 || !strings.HasSuffix(got, "…") {
		t.Errorf("preview length = %d, want 120 runes and an ellipsis", len([]rune(got)))
	}
}

func TestJSONStringListDropsNonStrings(t *testing.T) {
	cases := []struct {
		json string
		want []string
	}{
		{`["a","b"]`, []string{"a", "b"}},
		// A number that reads as an id is not an id: dropping it deletes nothing
		// rather than deleting the row whose id happens to be "1".
		{`[1,"b",null]`, []string{"b"}},
		{`[]`, []string{}},
		{`"a"`, nil},
		{`{"a":1}`, nil},
	}
	for _, c := range cases {
		got := jsonStringList(json.RawMessage(c.json))
		if len(got) != len(c.want) {
			t.Errorf("jsonStringList(%s) = %v, want %v", c.json, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("jsonStringList(%s) = %v, want %v", c.json, got, c.want)
				break
			}
		}
	}
	if got := jsonStringList(nil); got != nil {
		t.Errorf("absent ids = %v, want nil so the scope branch runs", got)
	}
}

// A session's duration is milliseconds on the wire and seconds in the column,
// and it is floored at zero: a client with a skewed clock can report a session
// last seen before it started.
func TestSessionCardDuration(t *testing.T) {
	if got := max64(0, (100-160)*1000); got != 0 {
		t.Errorf("duration = %d, want 0 for a backwards session", got)
	}
	if got := max64(0, (760-160)*1000); got != 600_000 {
		t.Errorf("duration = %d, want 600000 ms", got)
	}
}
