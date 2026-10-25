//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cliutil

import (
	"os"
	"testing"
)

func TestTerminalColumnsOnWindowsIsAlwaysZero(t *testing.T) {
	if got := TerminalColumns(os.Stdout); got != 0 {
		t.Errorf("TerminalColumns (windows stub) = %d, want 0", got)
	}
}