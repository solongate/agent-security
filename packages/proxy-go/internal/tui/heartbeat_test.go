package tui

import (
	"strings"
	"testing"
)

// THE PANE TITLED "system heartbeat" HAS TO BEAT.
//
// It is written to by API errors — there is no API in this build — by alerts, and by a
// local poll that found a handful of new calls. So the healthy case, a quiet machine with
// nothing wrong, produced an empty pane under a title promising a sign of life, and the
// one question a live console exists to answer was the one it could not: is this running?
//
// An idle console and a hung console looked identical.
func TestTheHeartbeatBeatsOnAQuietMachine(t *testing.T) {
	p := &Live{}

	// Nothing has happened at all: no recording, no calls, no events.
	p.setBeat(1_000)
	if p.beat.ts == 0 {
		t.Fatal("no heartbeat on an idle console, which is exactly when one is needed")
	}
	if strings.TrimSpace(p.beat.msg) == "" {
		t.Error("the heartbeat has no text, so the row is blank")
	}

	// THE CLOCK HAS TO MOVE. A row whose every field is identical from one second to the
	// next cannot distinguish a live console from a frozen one, which is the failure this
	// whole thing is for.
	first := p.beat
	p.setBeat(2_000)
	if p.beat.ts == first.ts {
		t.Error("the heartbeat timestamp did not advance between polls")
	}
}

// What it says changes with what it saw, or it is a decoration rather than a reading.
func TestTheHeartbeatReportsWhatThePollSaw(t *testing.T) {
	on := true
	off := false

	p := &Live{localOn: &off}
	p.setBeat(1_000)
	if !strings.Contains(p.beat.msg, "no local recording") {
		t.Errorf("with recording off the heartbeat says %q", p.beat.msg)
	}

	p = &Live{localOn: &on}
	p.setBeat(1_000)
	if !strings.Contains(p.beat.msg, "no calls") {
		t.Errorf("with nothing recorded the heartbeat says %q", p.beat.msg)
	}

	// Calls arrive: the beat reports how many are new, which is the number that tells
	// somebody the guard is being exercised right now rather than merely loaded.
	p.local = make([]streamItem, 7)
	p.setBeat(2_000)
	if !strings.Contains(p.beat.msg, "7") {
		t.Errorf("after 7 calls arrived the heartbeat says %q, with no count in it", p.beat.msg)
	}

	// And nothing new since: quiet, which is a reading and not an absence. Without this
	// the busy readings mean nothing, because there would be nothing to contrast them
	// with.
	p.setBeat(3_000)
	if !strings.Contains(p.beat.msg, "quiet") {
		t.Errorf("with no new calls the heartbeat says %q, want it to report quiet", p.beat.msg)
	}
}
