// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Install() has no guard binary to find in a test binary's directory, so it
// always fails at the "no guard binary for this platform" check. That still
// exercises every step before it: plugin staging, hook registration planning,
// directory creation and the launcher script write.
func TestInstallFailsWithoutAGuardBinaryButWritesTheLauncher(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("SOLONGATE_NO_OS_LOCK", "1")

	res := Install()
	if res.OK {
		t.Fatalf("Install() = %+v, want OK=false with no guard binary present", res)
	}
	if !strings.Contains(res.Message, "no guard binary") {
		t.Errorf("Install().Message = %q, want it to mention the missing guard binary", res.Message)
	}

	p := GlobalPaths()
	launcher := filepath.Join(p.HooksDir, LauncherName)
	if !Exists(launcher) {
		t.Error("Install() did not write the hook launcher before failing")
	}
	if !Exists(p.ClaudeDir) {
		t.Error("Install() did not create the Claude config directory")
	}
	beatDir := filepath.Join(p.SGDir, BeatDirName)
	if !Exists(beatDir) {
		t.Error("Install() did not create the beat directory")
	}
}

func TestUninstallWithNothingInstalled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("SOLONGATE_NO_OS_LOCK", "1")

	res := Uninstall()
	if !res.OK {
		t.Errorf("Uninstall() with nothing installed = %+v, want OK=true", res)
	}
}

func TestUninstallRemovesClaudeRegistration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("SOLONGATE_NO_OS_LOCK", "1")

	p := GlobalPaths()
	reg, err := planClaude(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.commit(); err != nil {
		t.Fatal(err)
	}
	if !ClaudeGuardInstalled() {
		t.Fatal("setup: ClaudeGuardInstalled() = false after committing planClaude")
	}

	res := Uninstall()
	if !res.OK {
		t.Fatalf("Uninstall() = %+v, want OK=true", res)
	}
	if ClaudeGuardInstalled() {
		t.Error("ClaudeGuardInstalled() = true after Uninstall()")
	}
}

func TestWriteFileAtomicWritesContentAndCleansUpTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := writeFileAtomic(path, []byte("hello world")); err != nil {
		t.Fatalf("writeFileAtomic() error: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Errorf("content = %q, want %q", got, "hello world")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".solongate-") {
			t.Errorf("leftover temp file %q was not cleaned up", e.Name())
		}
	}
}

func TestWriteFileAtomicOverwritesExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("new")); err != nil {
		t.Fatalf("writeFileAtomic() error: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("content = %q, want %q", got, "new")
	}
}

func TestClearUpdateCheckStamp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if !ClearUpdateCheckStamp() {
		t.Error("ClearUpdateCheckStamp() = false when the stamp does not exist, want true")
	}

	p := GlobalPaths()
	if err := os.MkdirAll(p.SGDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.UpdateCheckPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !ClearUpdateCheckStamp() {
		t.Error("ClearUpdateCheckStamp() = false removing an existing stamp, want true")
	}
	if Exists(p.UpdateCheckPath) {
		t.Error("the update-check stamp still exists after ClearUpdateCheckStamp()")
	}
}