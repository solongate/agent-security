// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLockFileThenUnlockFileRoundTrip(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command("chattr", "-i", file).Run() })

	lockFile(file)
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o500 {
		t.Errorf("after lockFile, perm = %v, want 0500", info.Mode().Perm())
	}

	unlockFile(file)
	info, err = os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("after unlockFile, perm = %v, want 0600", info.Mode().Perm())
	}
}

func TestLockFileOnMissingPathIsANoop(t *testing.T) {
	lockFile(filepath.Join(t.TempDir(), "does-not-exist"))
}

func TestUnlockFileOnMissingPathIsANoop(t *testing.T) {
	unlockFile(filepath.Join(t.TempDir(), "does-not-exist"))
}

func TestRunIgnoresFailuresAndMissingBinaries(t *testing.T) {
	run("definitely-not-a-real-binary-xyz", "arg")
	run("false")
}

func TestWriteProtectedFileFreshFileWritesDirectly(t *testing.T) {
	file := filepath.Join(t.TempDir(), "new.json")
	if ok := WriteProtectedFile(file, []byte("hello")); !ok {
		t.Fatal("WriteProtectedFile() = false, want true")
	}
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("file contents = %q, want %q", got, "hello")
	}
}

func TestWriteProtectedFileOverLockedFileUnlocksRewritesAndRelocks(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod-based protection cannot block a write made as root")
	}
	file := filepath.Join(t.TempDir(), "locked.json")
	if err := os.WriteFile(file, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command("chattr", "-i", file).Run() })
	lockFile(file)

	if ok := WriteProtectedFile(file, []byte("new")); !ok {
		t.Fatal("WriteProtectedFile() = false, want true")
	}

	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("file contents = %q, want %q", got, "new")
	}

	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o500 {
		t.Errorf("perm after relock = %v, want 0500", info.Mode().Perm())
	}
}

func TestWriteProtectedFileSkipsRelockWhenEnvOptsOut(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod-based protection cannot block a write made as root")
	}
	t.Setenv("SOLONGATE_NO_OS_LOCK", "1")
	file := filepath.Join(t.TempDir(), "locked.json")
	if err := os.WriteFile(file, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command("chattr", "-i", file).Run() })
	lockFile(file)

	if ok := WriteProtectedFile(file, []byte("new")); !ok {
		t.Fatal("WriteProtectedFile() = false, want true")
	}

	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perm with SOLONGATE_NO_OS_LOCK=1 = %v, want 0600 (not relocked)", info.Mode().Perm())
	}
}