// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package shared

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGuessPermission(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		{"apply_patch", "WRITE"},
		{"ApplyPatch", "WRITE"},
		{"Bash", "EXECUTE"},
		{"ShellExec", "EXECUTE"},
		{"RunCommand", "EXECUTE"},
		{"Monitor", "EXECUTE"},
		{"EnterWorktree", "EXECUTE"},
		{"ExitWorktree", "EXECUTE"},
		{"WebFetch", "NETWORK"},
		{"curl", "NETWORK"},
		{"WebSearch", "NETWORK"},
		{"Write", "WRITE"},
		{"CreateFile", "WRITE"},
		{"DeleteFile", "WRITE"},
		{"Mkdir", "WRITE"},
		{"Read", "READ"},
		{"Grep", "READ"},
		{"", "READ"},
	}
	for _, tc := range cases {
		if got := GuessPermission(tc.tool); got != tc.want {
			t.Errorf("GuessPermission(%q) = %q, want %q", tc.tool, got, tc.want)
		}
	}
}

func TestAgentKeySanitizesInput(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"claude-code", "claude-code"},
		{"my agent!", "my_agent_"},
		{"", "default"},
		{"ÜnıcödE", "_n_c_dE"},
	}
	for _, tc := range cases {
		if got := AgentKey(tc.in); got != tc.want {
			t.Errorf("AgentKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestProjectKeyIsStableAndDistinct(t *testing.T) {
	a := ProjectKey("/home/user/project-a")
	b := ProjectKey("/home/user/project-b")
	if a != ProjectKey("/home/user/project-a") {
		t.Error("ProjectKey should be stable for the same input")
	}
	if a == b {
		t.Error("ProjectKey should differ for different inputs")
	}
	if ProjectKey("") == "" {
		t.Error("ProjectKey should never return an empty string")
	}
}

func TestSGDirUsesHomeDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got := SGDir()
	if filepath.Base(got) != ".solongate" {
		t.Errorf("SGDir() = %q, want a path ending in .solongate", got)
	}
}

func TestEnsureSGDirCreatesDirWithMode(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := EnsureSGDir(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(SGDir())
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("expected SGDir to be created as a directory")
	}
	if info.Mode().Perm() != DirMode {
		t.Errorf("dir mode = %v, want %v", info.Mode().Perm(), os.FileMode(DirMode))
	}
}

func TestProjectFlagDirIsUnderSGDirProjects(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got := ProjectFlagDir()
	want := filepath.Join(SGDir(), "projects")
	if filepath.Dir(got) != want {
		t.Errorf("ProjectFlagDir() = %q, want parent %q", got, want)
	}
}
