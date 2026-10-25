//go:build !windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cliutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTerminalColumnsOnRegularFileReturnsZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "regular.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if got := TerminalColumns(f); got != 0 {
		t.Errorf("TerminalColumns on a regular (non-tty) file = %d, want 0 (TIOCGWINSZ fails)", got)
	}
}