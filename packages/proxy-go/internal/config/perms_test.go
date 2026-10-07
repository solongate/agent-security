// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestTheAccountsFileIsOwnerOnly stood here. accounts.json held live API keys in
// cleartext and was written 0644 — world-readable — which on the machines this tool
// runs on (shared build boxes, CI runners, containers) handed every other user a
// working credential. Nothing writes accounts.json any more; see credentials.go.
//
// What the test knew is still true of the files that ARE written, and is the reason
// the policy writer goes through a temporary file: os.WriteFile applies a mode only
// when it CREATES a file, so passing 0600 leaves every existing install exactly as
// exposed as it was — which is most of them. A rename puts a NEW inode in place, and
// the new inode carries the mode that was asked for.
//
// This test holds the directory those files live in. The policy file's own mode is
// held by internal/api (it is written there), by test/local-cli.mjs against the
// built artifact, and by test/post-tool-hook.mjs for the audit trail.
func TestTheConfigDirectoryIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	// The state of a machine that was set up by an older version: the directory is
	// there already, and it is group- and world-readable.
	dir := filepath.Join(home, ".solongate")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := EnsureDir(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	// MkdirAll applies a mode only when it CREATES the directory, so an existing one
	// keeps whatever it had — the same trap as WriteFile. A directory holding the
	// policy and the audit trail must not be readable by every user on the machine.
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Errorf("~/.solongate mode = %04o, want 0700 — an existing directory was left as it was", mode)
	}
}

// A directory this code CREATES gets the same mode, which is the half that was never
// in doubt and is worth keeping so a change to EnsureDir cannot pass by fixing only
// the case above.
func TestAFreshConfigDirectoryIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	if err := EnsureDir(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(home, ".solongate"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Errorf("~/.solongate mode = %04o, want 0700", mode)
	}
}
