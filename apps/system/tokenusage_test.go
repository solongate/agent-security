package main

import (
	"strings"
	"testing"
	"time"
)

// What a turn cost, and the three ways a number here could be wrong.
//
// This is the first thing SolonGate records that a customer is billed for, so a
// figure that is quietly double, quietly stale or quietly invented is worse
// than no figure at all.

// The same turn reported twice is one row.
//
// A hook retries — a network blip, a re-run, a client that fires Stop twice —
// and a spend figure that grows on every retry is a bill that grows with the
// weather. The key is the client's own turn identifier, hashed with the project
// so two projects cannot collide on a session id neither of them chose.
func TestTheSameTurnKeyedTheSameWay(t *testing.T) {
	a := tokenTurnKey("proj-1", "claude-code", "req_abc")
	b := tokenTurnKey("proj-1", "claude-code", "req_abc")
	if a != b {
		t.Fatal("the same turn hashed two different ways, so a retry would double it")
	}

	// Every part of the key separates.
	for _, other := range [][3]string{
		{"proj-2", "claude-code", "req_abc"},
		{"proj-1", "codex", "req_abc"},
		{"proj-1", "claude-code", "req_xyz"},
	} {
		if got := tokenTurnKey(other[0], other[1], other[2]); got == a {
			t.Errorf("%v collides with the original turn", other)
		}
	}
	if !strings.HasPrefix(a, "tk_") {
		t.Errorf("the key is %q, which is not recognisable as one", a)
	}
}

// The SESSION is not part of the key, and that is the fix for a real double
// count rather than a simplification.
//
// Resuming or forking a conversation copies prior records into a file under a
// new session id, so the same API request appears in two transcripts — 1,460 of
// them on one developer's machine, carrying nearly two million output tokens.
// Keyed by session, every one of those is a second row and a bill that grows
// because somebody resumed.
func TestResumingASessionDoesNotDoubleTheBill(t *testing.T) {
	// The same provider-issued request id, seen in two different session files.
	first := tokenTurnKey("proj-1", "claude-code", "req_abc")
	afterResume := tokenTurnKey("proj-1", "claude-code", "req_abc")
	if first != afterResume {
		t.Fatal("the same request in a resumed session is a second row")
	}
}

// One implausible number must not own a chart.
//
// Ten million is above every model's context window, so a number past it is a
// unit error, a cumulative counter sent as a delta, or a corrupted read. It is
// clamped rather than refused: the rest of the turn is still worth having.
func TestAnImplausibleCountIsClamped(t *testing.T) {
	if got := clampTokens(50_000_000); got != tokenMaxPerTurn {
		t.Errorf("a huge count survived as %d", got)
	}
	// Negative is zero. A count cannot be negative and a client sending one has
	// a bug this service should not store.
	if got := clampTokens(-5); got != 0 {
		t.Errorf("a negative count survived as %d", got)
	}
	if got := clampTokens(1234); got != 1234 {
		t.Errorf("an ordinary count was changed to %d", got)
	}
}

// A stamp from a skewed clock is replaced with now.
//
// Otherwise one machine whose clock is a year fast puts a bar at the end of
// every chart forever, and one that is a year slow puts one before anything
// else on it.
func TestAnImpossibleStampBecomesNow(t *testing.T) {
	now := time.Now()

	future := now.Add(48 * time.Hour).UnixMilli()
	if got := tokenStamp(future); got > now.Add(time.Hour).Unix() {
		t.Error("a stamp from the future was stored as-is")
	}
	ancient := now.AddDate(-5, 0, 0).UnixMilli()
	if got := tokenStamp(ancient); got < now.AddDate(-2, 0, 0).Unix() {
		t.Error("a stamp from before this product existed was stored as-is")
	}
	// Absent is now.
	if got := tokenStamp(0); got < now.Unix()-5 {
		t.Error("an absent stamp did not become now")
	}
	// An ordinary one is kept, in SECONDS.
	ok := now.Add(-time.Hour).UnixMilli()
	if got := tokenStamp(ok); got != ok/1000 {
		t.Errorf("an ordinary stamp became %d, want %d", got, ok/1000)
	}
}
