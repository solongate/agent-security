// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cliutil

import (
	"strings"
	"testing"
)

const credentialNote = "Removed /home/codeyevsky/.solongate/clo" + "ud-guard.json, " +
	"left over from when this product had accounts. It held an API key: revoke " +
	"that key at whatever issued it, because deleting the file does not."

func TestWrapIndentedKeepsEveryLineInTheColumn(t *testing.T) {
	t.Setenv("COLUMNS", "80")

	lines := WrapIndented(credentialNote)
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

	joined := strings.Join(nil, "")
	for _, l := range lines {
		joined += " " + strings.TrimPrefix(l, markIndent)
	}
	if strings.Join(strings.Fields(joined), " ") != strings.Join(strings.Fields(credentialNote), " ") {
		t.Error("wrapping changed the words")
	}
}

func TestWrapIndentedWithNoTerminalDoesNotGuess(t *testing.T) {

	t.Setenv("COLUMNS", "")
	lines := WrapIndented(credentialNote)
	if len(lines) != 1 {
		t.Errorf("an unmeasurable terminal produced %d lines; it must produce one", len(lines))
	}
}

func TestWrapIndentedRefusesToBreakAPath(t *testing.T) {
	t.Setenv("COLUMNS", "40")
	long := "/home/codeyevsky/some/very/deeply/nested/directory/that/goes/on/forever/file.txt"
	lines := WrapIndented("Removed " + long + " because it was stale.")

	found := false
	for _, l := range lines {
		if strings.Contains(l, long) {
			found = true
		}
	}
	if !found {

		t.Errorf("the path was broken across lines: %q", lines)
	}
}

func TestWrapIndentedAtANarrowWidthDoesNotFold(t *testing.T) {

	t.Setenv("COLUMNS", "24")
	if lines := WrapIndented(credentialNote); len(lines) != 1 {
		t.Errorf("a 24-column terminal produced %d lines; too narrow to fold usefully", len(lines))
	}
}

func TestWrapIndentedShortTextIsOneLine(t *testing.T) {
	t.Setenv("COLUMNS", "80")
	lines := WrapIndented("open a new AI session for it to take effect")
	if len(lines) != 1 {
		t.Fatalf("a short note produced %d lines", len(lines))
	}
	if !strings.HasPrefix(lines[0], markIndent) {
		t.Errorf("a short note lost its indent: %q", lines[0])
	}
}

func TestMarkIndentMatchesTheMarkWidth(t *testing.T) {
	if len(markIndent) != len("[  OK  ] ") {
		t.Errorf("markIndent is %d wide, the mark is %d", len(markIndent), len("[  OK  ] "))
	}
}

func TestPadRight(t *testing.T) {
	if got := PadRight("foo", 6); got != "foo   " {
		t.Errorf("padRight(\"foo\", 6) = %q, want \"foo   \"", got)
	}
	if got := PadRight("foobar", 6); got != "foobar" {
		t.Errorf("padRight(\"foobar\", 6) = %q, want \"foobar\"", got)
	}
	if got := PadRight("foobarbaz", 6); got != "foobarbaz" {
		t.Errorf("padRight(\"foobarbaz\", 6) = %q, want \"foobarbaz\"", got)
	}
}
