// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// volumeRoot is "/" on Unix and "C:\\" on Windows, so the root case is the real
// root of the filesystem under test rather than a hardcoded slash.
func volumeRoot() string {
	return filepath.VolumeName(string(filepath.Separator)) + string(filepath.Separator)
}

func TestWorkspaceRootRejectsFilesystemRoot(t *testing.T) {
	err := checkWorkspaceRoot(volumeRoot())
	if err == nil {
		t.Fatalf("workspace root %q was accepted", volumeRoot())
	}
	if !strings.Contains(err.Error(), "confines nothing") {
		t.Fatalf("unexpected error for root workspace: %v", err)
	}
}

func TestWorkspaceRootRejectsSymlinkToFilesystemRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink needs a privilege the Windows CI runner does not have")
	}
	link := filepath.Join(t.TempDir(), "root-alias")
	if err := os.Symlink(volumeRoot(), link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	err := checkWorkspaceRoot(link)
	if err == nil {
		t.Fatalf("symlink %q -> %q was accepted as a workspace root", link, volumeRoot())
	}
	if !strings.Contains(err.Error(), "confines nothing") {
		t.Fatalf("unexpected error for symlinked root workspace: %v", err)
	}
}

func TestWorkspaceRootRejectsHomeDirectory(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory in this environment: %v", err)
	}
	err = checkWorkspaceRoot(home)
	if err == nil {
		t.Fatalf("home directory %q was accepted as a workspace root", home)
	}
	if !strings.Contains(err.Error(), "home directory") {
		t.Fatalf("unexpected error for home workspace: %v", err)
	}
}

func TestWorkspaceRootRejectsSymlinkToHomeDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating a symlink needs a privilege the Windows CI runner does not have")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory in this environment: %v", err)
	}
	link := filepath.Join(t.TempDir(), "home-alias")
	if err := os.Symlink(home, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	err = checkWorkspaceRoot(link)
	if err == nil {
		t.Fatalf("symlink %q -> home directory was accepted as a workspace root", link)
	}
	if !strings.Contains(err.Error(), "home directory") {
		t.Fatalf("unexpected error for symlinked home workspace: %v", err)
	}
}

func TestWorkspaceRootAcceptsProjectDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := checkWorkspaceRoot(dir); err != nil {
		t.Fatalf("project directory %q was rejected: %v", dir, err)
	}
}

func TestWorkspaceRootRejectsRelativePath(t *testing.T) {
	err := checkWorkspaceRoot("project")
	if err == nil {
		t.Fatal("relative workspace path was accepted")
	}
	if !strings.Contains(err.Error(), "absolute path") {
		t.Fatalf("unexpected error for relative workspace: %v", err)
	}
}
