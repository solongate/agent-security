package install

import (
	"os"
	"path/filepath"
	"testing"
)

// AN INSTALL HAS TO REMEMBER WHERE IT CAME FROM, or `update` has nothing to update from.
//
// Once the binaries are in the store, nothing about their location says anything about
// the checkout they were built in: ~/.solongate/bin has no repository above it. So the
// install writes the path down, and this checks the two halves of that — that it is
// written, and that reading it back is verified rather than trusted.
func TestAnInstallRemembersItsCheckout(t *testing.T) {
	home := sandbox(t)
	haveHookSources(t)

	// Before any install there is nothing recorded, and asking is not an error.
	if root, ok := InstalledFrom(); ok {
		t.Errorf("with nothing installed, InstalledFrom() = %q, want no source", root)
	}

	if r := Install(); !r.OK {
		t.Fatalf("install failed: %+v", r)
	}

	root, ok := InstalledFrom()
	if !ok {
		t.Fatal("after installing from a checkout, no source was recorded — `update` would " +
			"have nothing to pull and would tell the user to install again")
	}

	// It has to be the repository, not some directory inside it: `update` runs git and
	// install.sh there, and both only exist at the root.
	for _, name := range []string{"install.sh", ".git"} {
		if !Exists(filepath.Join(root, name)) {
			t.Errorf("the recorded source %q has no %s, so it is not a checkout root", root, name)
		}
	}
	_ = home
}

// A RECORDED PATH IS VERIFIED, NOT TRUSTED.
//
// A checkout can be deleted, moved, or replaced by an unrelated directory after the
// install that recorded it. Reporting a stale path as a source sends `update` to run git
// and a build script somewhere that has neither, and the error it dies with would name
// git rather than the real problem.
func TestAStaleOrMovedCheckoutIsNotASource(t *testing.T) {
	home := sandbox(t)
	if err := os.MkdirAll(GlobalPaths().SGDir, 0o755); err != nil {
		t.Fatal(err)
	}

	write := func(path string) {
		t.Helper()
		if err := os.WriteFile(SourceRecordPath(), []byte(path+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Gone entirely.
	write(filepath.Join(home, "deleted-checkout"))
	if root, ok := InstalledFrom(); ok {
		t.Errorf("a deleted path reported as a source: %q", root)
	}

	// There, but not a checkout — somebody reused the directory.
	other := filepath.Join(home, "someone-elses-dir")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	write(other)
	if root, ok := InstalledFrom(); ok {
		t.Errorf("an unrelated directory reported as a source: %q", root)
	}

	// A git repository with no install script is still not one: `update` runs that script.
	half := filepath.Join(home, "half")
	if err := os.MkdirAll(filepath.Join(half, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(half)
	if root, ok := InstalledFrom(); ok {
		t.Errorf("a repository with no install script reported as a source: %q", root)
	}

	// And with both, it is.
	if err := os.WriteFile(filepath.Join(half, "install.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := InstalledFrom(); !ok {
		t.Error("a directory with .git and install.sh was not accepted as a source")
	}
}
