// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Issue #206: a window that opens exactly after a newline holds complete
// lines; the old code dropped the first one anyway.
func TestTailLinesKeepsCompleteLineAtExactBoundary(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "log")
	content := strings.Repeat("A", 9) + "\n" + strings.Repeat("B", 9) + "\n" + strings.Repeat("C", 9) + "\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got := TailLines(file, 20) // start lands right after line 1's newline
	want := "B" + strings.Repeat("", 0)
	_ = want
	if len(got) != 2 {
		t.Fatalf("TailLines = %q, want 2 lines [B..., C...]", got)
	}
	if got[0] != strings.Repeat("B", 9) || got[1] != strings.Repeat("C", 9) {
		t.Errorf("TailLines = %q, want [BBBBBBBBB, CCCCCCCCC]", got)
	}
}

func TestTailLinesDropsRealFragmentAtMidLineBoundary(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "log")
	content := strings.Repeat("A", 9) + "XX\n" + strings.Repeat("B", 9) + "\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// start lands inside line 1 ("A………X|X"), so the first chunk is a fragment
	got := TailLines(file, 20)
	if len(got) != 1 || got[0] != strings.Repeat("B", 9) {
		t.Errorf("TailLines = %q, want only the complete line B", got)
	}
}

func TestTailLinesWholeFileWhenWindowCoversIt(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "log")
	content := "one\ntwo\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got := TailLines(file, 1<<20)
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Errorf("TailLines = %q", got)
	}
}
