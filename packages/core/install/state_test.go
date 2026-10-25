// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"os"
	"path/filepath"
	"testing"
)

func writeVersionScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestGuardVersionAtMissingPath(t *testing.T) {
	if got := guardVersionAt(filepath.Join(t.TempDir(), "does-not-exist")); got != nil {
		t.Errorf("guardVersionAt() = %v, want nil for a missing path", got)
	}
}

func TestGuardVersionAtValidScript(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard")
	writeVersionScript(t, path, `echo 42`)

	got := guardVersionAt(path)
	if got == nil || *got != 42 {
		t.Errorf("guardVersionAt() = %v, want pointer to 42", got)
	}
}

func TestGuardVersionAtNonZeroExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard")
	writeVersionScript(t, path, `exit 1`)

	if got := guardVersionAt(path); got != nil {
		t.Errorf("guardVersionAt() = %v, want nil when the binary exits non-zero", got)
	}
}

func TestGuardVersionAtNonNumericOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard")
	writeVersionScript(t, path, `echo not-a-number`)

	if got := guardVersionAt(path); got != nil {
		t.Errorf("guardVersionAt() = %v, want nil for non-numeric output", got)
	}
}

func TestGuardVersionAtTrimsWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard")
	writeVersionScript(t, path, `printf '  7\n'`)

	got := guardVersionAt(path)
	if got == nil || *got != 7 {
		t.Errorf("guardVersionAt() = %v, want pointer to 7", got)
	}
}

func TestInstalledGuardVersion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	writeVersionScript(t, filepath.Join(BinDir(), guardBinaryName()), `echo 9`)

	got := InstalledGuardVersion()
	if got == nil || *got != 9 {
		t.Errorf("InstalledGuardVersion() = %v, want pointer to 9", got)
	}
}

func TestInstalledGuardVersionMissing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if got := InstalledGuardVersion(); got != nil {
		t.Errorf("InstalledGuardVersion() = %v, want nil with no binary installed", got)
	}
}

func TestShippedGuardVersion(t *testing.T) {
	dir, ok := selfBinDir()
	if !ok {
		t.Skip("selfBinDir() could not resolve the test binary's own directory")
	}
	path := filepath.Join(dir, guardBinaryName())
	writeVersionScript(t, path, `echo 5`)
	t.Cleanup(func() { _ = os.Remove(path) })

	got := ShippedGuardVersion()
	if got == nil || *got != 5 {
		t.Errorf("ShippedGuardVersion() = %v, want pointer to 5", got)
	}
}