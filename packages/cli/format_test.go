// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

// The line that made this necessary: a repair note, three sentences and a path,
// printed where every other line in the run is nine columns in.
const credentialNote = "Removed /home/codeyevsky/.solongate/clo" + "ud-guard.json, " +
	"left over from when this product had accounts. It held an API key: revoke " +
	"that key at whatever issued it, because deleting the file does not."

func TestWrapIndentedKeepsEveryLineInTheColumn(t *testing.T) {
	t.Setenv("COLUMNS", "80")

	lines := wrapIndented(credentialNote)
	if len(lines) < 2 {
		t.Fatalf("a 200-character note at 80 columns produced %d line(s)", len(lines))
	}
	for i, l := range lines {
		if !strings.HasPrefix(l, markIndent) {
			t.Errorf("line %d does not start in the indented column: %q", i, l)
		}
		if len(l) > 80 {
			t.Errorf("line %d is %d columns wide, past the 80 it was given: %q", i, len(l), l)
		}
	}
	// Nothing lost and nothing invented.
	joined := strings.Join(nil, "")
	for _, l := range lines {
		joined += " " + strings.TrimPrefix(l, markIndent)
	}
	if strings.Join(strings.Fields(joined), " ") != strings.Join(strings.Fields(credentialNote), " ") {
		t.Error("wrapping changed the words")
	}
}

func TestWrapIndentedWithNoTerminalDoesNotGuess(t *testing.T) {
	// A log file has no width. Folding it at an assumed column makes every
	// line a guess, so the text goes out whole.
	t.Setenv("COLUMNS", "")
	lines := wrapIndented(credentialNote)
	if len(lines) != 1 {
		t.Errorf("an unmeasurable terminal produced %d lines; it must produce one", len(lines))
	}
}

func TestWrapIndentedRefusesToBreakAPath(t *testing.T) {
	t.Setenv("COLUMNS", "40")
	long := "/home/codeyevsky/some/very/deeply/nested/directory/that/goes/on/forever/file.txt"
	lines := wrapIndented("Removed " + long + " because it was stale.")

	found := false
	for _, l := range lines {
		if strings.Contains(l, long) {
			found = true
		}
	}
	if !found {
		// A path cut in half is a path nobody can copy. One overflowing line
		// is a worse line; a broken one is a wrong line.
		t.Errorf("the path was broken across lines: %q", lines)
	}
}

func TestWrapIndentedAtANarrowWidthDoesNotFold(t *testing.T) {
	// Below the point where an indent plus a word is most of the line, folding
	// produces one word per line, which is less readable than overflowing.
	t.Setenv("COLUMNS", "24")
	if lines := wrapIndented(credentialNote); len(lines) != 1 {
		t.Errorf("a 24-column terminal produced %d lines; too narrow to fold usefully", len(lines))
	}
}

func TestWrapIndentedShortTextIsOneLine(t *testing.T) {
	t.Setenv("COLUMNS", "80")
	lines := wrapIndented("open a new AI session for it to take effect")
	if len(lines) != 1 {
		t.Fatalf("a short note produced %d lines", len(lines))
	}
	if !strings.HasPrefix(lines[0], markIndent) {
		t.Errorf("a short note lost its indent: %q", lines[0])
	}
}

// The indent has to be exactly the width of the mark, or the unmarked lines sit
// in a column of their own and the whole run looks like two programs taking
// turns.
func TestMarkIndentMatchesTheMarkWidth(t *testing.T) {
	if len(markIndent) != len("[  OK  ] ") {
		t.Errorf("markIndent is %d wide, the mark is %d", len(markIndent), len("[  OK  ] "))
	}
}