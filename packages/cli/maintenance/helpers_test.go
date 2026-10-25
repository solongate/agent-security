// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !windows

package maintenance

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// newHome points HOME at a fresh, empty temp directory so tests that reach
// into packages/core/client, packages/core/install, or packages/core/config
// never read or write the real developer machine.
func newHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

// captureStderrFD redirects the real OS-level stderr file descriptor (fd 2)
// to a pipe for the duration of fn and returns everything written to it.
//
// A plain `os.Stderr = w` swap is not enough for code going through
// cliutil.Errln: cliutil captures os.Stderr once into its own unexported
// package-level io.Writer at init time, so it keeps writing to the original
// *os.File no matter what a test later assigns to the os.Stderr variable.
// Redirecting the fd itself with dup2 affects every writer using fd 2,
// regardless of which *os.File value it holds, so it also works for code
// that writes straight to os.Stderr.
func captureStderrFD(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	fd := int(os.Stderr.Fd())
	saved, err := syscall.Dup(fd)
	if err != nil {
		t.Fatalf("syscall.Dup: %v", err)
	}
	if err := unix.Dup2(int(w.Fd()), fd); err != nil {
		t.Fatalf("unix.Dup2: %v", err)
	}
	w.Close()

	fn()

	if err := unix.Dup2(saved, fd); err != nil {
		t.Fatalf("unix.Dup2 restore: %v", err)
	}
	syscall.Close(saved)

	out, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	return string(out)
}

// requireGit skips the calling test when there is no usable git binary on
// PATH, matching the tool-presence guard style used elsewhere in this repo
// (e.g. packages/sandbox's linux_test.go).
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// newGitRepoOnBranch creates a real, local git repository on the given
// branch with one commit, so the repo is never on an unpredictable
// init.defaultBranch name picked by the host's git config.
func newGitRepoOnBranch(t *testing.T, branch string) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "symbolic-ref", "HEAD", "refs/heads/"+branch)
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "f.txt")
	runGit(t, dir, "commit", "-q", "-m", "initial")
	return dir
}

func newGitRepo(t *testing.T) string {
	t.Helper()
	return newGitRepoOnBranch(t, "main")
}

// newBareRepoOnBranch creates a bare repository whose own HEAD points at
// branch, so a later `git clone` of it checks out that branch's content
// instead of leaving the clone's working tree empty on a nonexistent
// default branch.
func newBareRepoOnBranch(t *testing.T, branch string) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "--bare", "-q")
	runGit(t, dir, "symbolic-ref", "HEAD", "refs/heads/"+branch)
	return dir
}