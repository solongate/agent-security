// SPDX-License-Identifier: Apache-2.0

package panels

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/codeyevsky/solongate/proxy/internal/api"
)

// A grid cursor, built by hand so the test does not need a loaded panel: these
// are the only fields the navigation and the all-on/all-off keys read.
func gridPanel(n int, custom ...string) *DLP {
	p := &DLP{cols: 120, rows: 24, focused: true, hasDraft: true, editIdx: -1}
	for i := 0; i < n; i++ {
		p.available = append(p.available, string(rune('a'+i%26))+"-pattern")
	}
	for _, c := range custom {
		p.dlp.DLP.Custom = append(p.dlp.DLP.Custom, api.CustomPattern{Name: c, Re: c + "-*"})
	}
	return p
}

func press(p *DLP, s string) {
	switch s {
	case "up", "down", "left", "right":
		p.key(tea.KeyMsg{Type: map[string]tea.KeyType{"up": tea.KeyUp, "down": tea.KeyDown, "left": tea.KeyLeft, "right": tea.KeyRight}[s]})
	default:
		p.key(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)})
	}
}

// ↑↓ STEPS A ROW, NOT AN ENTRY.
//
// The built-ins tile four across. A ↓ that moved one entry would walk the cursor
// along a row instead of down the column under it, which is not what the shape on
// screen says the key does.
func TestDownStepsAWholeRowOfBuiltIns(t *testing.T) {
	p := gridPanel(70)

	press(p, "down")
	if p.sel != dlpCols {
		t.Fatalf("↓ from the first cell landed on %d, want %d — one row down", p.sel, dlpCols)
	}
	press(p, "right")
	if p.sel != dlpCols+1 {
		t.Fatalf("→ landed on %d, want %d — one cell right", p.sel, dlpCols+1)
	}
	press(p, "up")
	if p.sel != 1 {
		t.Fatalf("↑ landed on %d, want 1 — the same column, one row up", p.sel)
	}
}

// THE EDGES HOLD. A cursor that ran off the grid would select an entry that is
// not drawn, and the panel would look stuck.
func TestTheGridCursorStaysInsideTheBuiltIns(t *testing.T) {
	p := gridPanel(70)

	press(p, "up")
	press(p, "left")
	if p.sel != 0 {
		t.Fatalf("↑ and ← at the first cell moved to %d, want to stay at 0", p.sel)
	}

	p.sel = len(p.available) - 1
	press(p, "right")
	if p.sel != len(p.available)-1 {
		t.Fatalf("→ past the last built-in moved to %d, want to stay at %d", p.sel, len(p.available)-1)
	}
	press(p, "down")
	if p.sel != len(p.available)-1 {
		t.Fatalf("↓ off the last row with no custom patterns moved to %d, want to stay put", p.sel)
	}
}

// CROSSING INTO THE CUSTOM LIST. The last grid row is not a full row of four, so
// a ↓ of dlpCols from anywhere in it would overshoot the custom section entirely.
func TestDownFromTheLastGridRowReachesTheCustomPatterns(t *testing.T) {
	p := gridPanel(70, "internal-id")
	p.sel = 68 // 70 built-ins: the last row holds 68 and 69

	press(p, "down")
	if p.sel != 70 {
		t.Fatalf("↓ from the last grid row landed on %d, want 70 — the first custom pattern", p.sel)
	}
	press(p, "up")
	if p.sel != 69 {
		t.Fatalf("↑ out of the custom list landed on %d, want 69 — the last built-in", p.sel)
	}
}

// ←→ BELONG TO THE GRID, AND ← AT THE LEFT EDGE BELONGS TO THE OWNER.
//
// The Policies panel asks WantsLeft before it treats ← as "back". Answering yes
// everywhere would trap somebody in the panel; answering no everywhere would make
// ← unable to move a cell.
func TestLeftLeavesOnlyFromTheLeftmostColumn(t *testing.T) {
	p := gridPanel(70, "internal-id")

	if p.WantsLeft() {
		t.Error("← at column 0 was claimed by the grid, so there is no key that goes back")
	}
	p.sel = 2
	if !p.WantsLeft() {
		t.Error("← mid-row was given away as back, so it cannot move a cell")
	}
	p.sel = len(p.available) // the one custom pattern
	if p.WantsLeft() {
		t.Error("← in the custom list was claimed by the grid, which has no cursor there")
	}
}

// ALL ON / ALL OFF, over seventy patterns, without pressing space seventy times.
// Neither key may touch the custom patterns: they are a different list.
func TestSelectAllAndUnselectAllCoverOnlyTheBuiltIns(t *testing.T) {
	p := gridPanel(70, "internal-id")
	p.dlp.DLP.Patterns = []string{p.available[3]}

	press(p, "A")
	if len(p.dlp.DLP.Patterns) != 70 {
		t.Fatalf("A enabled %d patterns, want all 70", len(p.dlp.DLP.Patterns))
	}
	if !p.dirty {
		t.Error("A did not mark the draft unsaved, so s would have nothing to write")
	}
	if len(p.dlp.DLP.Custom) != 1 {
		t.Error("A rewrote the custom patterns, which are not built-ins")
	}

	press(p, "U")
	if len(p.dlp.DLP.Patterns) != 0 {
		t.Fatalf("U left %d patterns enabled, want none", len(p.dlp.DLP.Patterns))
	}
	if len(p.dlp.DLP.Custom) != 1 {
		t.Error("U removed a custom pattern, which is not a built-in")
	}
}

// A grid row holds four entries, so the scroll window has to find the row that
// CONTAINS the cursor. Matching on equality kept the view pinned to the top for
// three cells out of every four.
func TestEveryCellInTheGridIsReachableAndRendered(t *testing.T) {
	p := gridPanel(70)
	for i := 0; i < 70; i++ {
		p.sel = i
		out := p.View(ctxOf(120, 24))
		if out == "" {
			t.Fatalf("cell %d rendered nothing", i)
		}
	}
}
