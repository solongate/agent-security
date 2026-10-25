// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cliutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsTerminalRegularFileIsFalse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "regular.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if IsTerminal(f) {
		t.Error("IsTerminal on a regular file = true, want false")
	}
}