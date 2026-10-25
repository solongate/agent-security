// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirUsesHomeDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	want := filepath.Join(home, ".solongate")
	if got := Dir(); got != want {
		t.Errorf("Dir() = %q, want %q", got, want)
	}
}

func TestDirFallsBackToHomeEnvWhenUserHomeDirFails(t *testing.T) {
	t.Setenv("HOME", "")
	// os.UserHomeDir on unix reads $HOME directly, so clearing it also
	// exercises the fallback branch; this just asserts Dir() still
	// produces a .solongate suffix without panicking.
	if got := Dir(); filepath.Base(got) != ".solongate" {
		t.Errorf("Dir() = %q, want a path ending in .solongate", got)
	}
}

func TestPolicyFilePath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	want := filepath.Join(Dir(), "policy.json")
	if got := PolicyFilePath(); got != want {
		t.Errorf("PolicyFilePath() = %q, want %q", got, want)
	}
}

func TestTUIConfigPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	want := filepath.Join(Dir(), "tui-config.json")
	if got := TUIConfigPath(); got != want {
		t.Errorf("TUIConfigPath() = %q, want %q", got, want)
	}
}

func TestHooksDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	want := filepath.Join(Dir(), "hooks")
	if got := HooksDir(); got != want {
		t.Errorf("HooksDir() = %q, want %q", got, want)
	}
}

func TestLocalLogsDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	want := filepath.Join(Dir(), "local-logs")
	if got := LocalLogsDir(); got != want {
		t.Errorf("LocalLogsDir() = %q, want %q", got, want)
	}
}

func TestDefaultLocalLogFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	want := filepath.Join(LocalLogsDir(), "solongate-audit.jsonl")
	if got := DefaultLocalLogFile(); got != want {
		t.Errorf("DefaultLocalLogFile() = %q, want %q", got, want)
	}
}

func TestProjectFlagDirIsUnderDirProjectsAndKeyedByCwd(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	got := ProjectFlagDir()
	wantParent := filepath.Join(Dir(), "projects")
	if filepath.Dir(got) != wantParent {
		t.Errorf("ProjectFlagDir() = %q, want parent %q", got, wantParent)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(Dir(), "projects", ProjectKey(abs))
	if got != want {
		t.Errorf("ProjectFlagDir() = %q, want %q", got, want)
	}
}