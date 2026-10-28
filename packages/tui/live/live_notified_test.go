// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package live

import (
	"testing"
)

func mkLiveWithEvents(ids ...string) *Live {
	p := &Live{openedAt: 0, notified: map[string]bool{}, local: make([]streamItem, 0), merged: make([]streamItem, 0)}
	for i, id := range ids {
		p.local = append(p.local, streamItem{
			ID:       id,
			At:       int64(i + 1),
			Tool:     "Bash",
			Decision: "DENY",
			Detail:   "x",
		})
	}
	return p
}

// Issue #205: p.notified grew one entry per event ID forever. The eviction in
// notifySecurityEvents drops IDs that are no longer in the merged window.
func TestNotifiedSetIsBoundedAfterRebuild(t *testing.T) {
	p := mkLiveWithEvents()
	for i := 0; i < 500; i++ {
		p.local = append(p.local, streamItem{
			ID: "old-" + string(rune('a'+i%26)) + string(rune(i)),
			At: int64(i + 10), Tool: "Bash", Decision: "DENY", Detail: "x",
		})
	}

	p.rebuildMerged(0)
	p.notifySecurityEvents(baseCtx(10_000, false))
	// The set is bounded by the merged window: 500 unique DENY events in
	// local means 500 notified entries here — but after the window is
	// replaced with fresh events, the stale IDs must be evicted.
	stale := len(p.notified)

	p.local = nil
	for i := 0; i < 400; i++ {
		p.local = append(p.local, streamItem{
			ID: "new-" + string(rune('a'+i%26)) + string(rune(i)),
			At: int64(1000 + i), Tool: "Bash", Decision: "DENY", Detail: "fresh",
		})
	}
	p.rebuildMerged(0)
	p.notifySecurityEvents(baseCtx(10_000, false))
	if len(p.notified) > len(p.merged) {
		t.Fatalf("notified (%d) exceeds the merged window (%d)", len(p.notified), len(p.merged))
	}
	for _, e := range p.merged {
		if !p.notified[e.ID] {
			t.Fatalf("fresh event %s was not marked notified", e.ID)
		}
	}
	if stale == 0 {
		t.Fatal("precondition failed: no stale entries to evict")
	}
}

func TestNotifiedStillDeduplicatesWithinWindow(t *testing.T) {
	p := mkLiveWithEvents("e1", "e2")
	p.rebuildMerged(0)
	if cmds := p.notifySecurityEvents(baseCtx(10_000, false)); len(cmds) == 0 {
		t.Log("no alerts fired (depends on panel context)")
	}
	first := len(p.notified)
	p.notifySecurityEvents(baseCtx(10_000, false))
	if len(p.notified) != first {
		t.Fatalf("second pass added entries: %d -> %d", first, len(p.notified))
	}
}
