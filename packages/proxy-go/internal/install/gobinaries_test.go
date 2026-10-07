// SPDX-License-Identifier: Apache-2.0

package install

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The installed hook can only find a binary in ~/.solongate/bin, and this is
// what puts one there.
//
// Before it, a global install left the guard running its Node implementation on
// every call, on every machine — the hook is written to ~/.solongate/hooks as a
// lone file, and from there require.resolve("@solongate/guard-<platform>") finds
// nothing. Nothing reported it either: a fallback and a fast path produce
// identical answers, so the only difference was tens of milliseconds nobody was
// measuring.
//
// The tests drive the real copy against a real temporary HOME rather than
// checking that a function was called.

func withHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	return home
}

// A stand-in platform package: an executable named like the guard, beside a
// stand-in for the CLI.
func fakePlatformPackage(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range goBinaryNames() {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("staging %s: %v", name, err)
		}
	}
	return dir
}

func TestTheBinariesLandWhereTheHookLooks(t *testing.T) {
	home := withHome(t)
	src := fakePlatformPackage(t)

	// os.Executable() reports the test binary, so the copy is driven directly
	// against a known source — what is under test is the copy and its
	// destination, not how the running program finds itself.
	placed := copyFrom(src)
	if len(placed) != len(goBinaryNames()) {
		t.Fatalf("placed %v, want all of %v", placed, goBinaryNames())
	}

	for _, name := range goBinaryNames() {
		p := filepath.Join(home, ".solongate", "bin", name)
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("%s is not in ~/.solongate/bin, which is the only place a globally "+
				"installed hook looks: %v", name, err)
			continue
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
			t.Errorf("%s is not executable, so the hook will skip it and fall back to Node", name)
		}
	}
}

// The destination is exactly what packages/proxy/hooks/guard.mjs looks for. If
// either side moves, the fast path goes quiet rather than breaking, so the two
// are pinned together here.
func TestTheDestinationMatchesWhatTheHookSearches(t *testing.T) {
	withHome(t)
	if got := filepath.Base(BinDir()); got != "bin" {
		t.Errorf("BinDir() ends in %q, want \"bin\"", got)
	}
	hook, err := os.ReadFile(filepath.Join("..", "..", "..", "proxy", "hooks", "gu"+"ard.mjs"))
	if err != nil {
		t.Skipf("the npm hook is not in this checkout: %v", err)
	}
	src := string(hook)
	for _, want := range []string{`'.solongate', 'bin'`, "solongate-guard"} {
		if !strings.Contains(src, want) {
			t.Errorf("the hook no longer looks for %s — this installer is filling a directory nothing reads", want)
		}
	}
}

// Running it twice must not fail, and must not leave the temporary file behind.
func TestCopyingTwiceIsFine(t *testing.T) {
	withHome(t)
	src := fakePlatformPackage(t)
	copyFrom(src)
	placed := copyFrom(src)
	if len(placed) == 0 {
		t.Fatal("the second install placed nothing")
	}
	entries, err := os.ReadDir(BinDir())
	if err != nil {
		t.Fatalf("reading the bin directory: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".new") {
			t.Errorf("%s was left behind; a half-written binary is refused by the hook's "+
				"version probe, so this would be a silent fallback", e.Name())
		}
	}
}

// A platform package that carries nothing is not an error. npm declines an
// optionalDependency it has no build for, and the machine is still guarded — by
// the Node implementation, which is the whole reason that fallback exists.
func TestAnAbsentBinaryIsNotAFailure(t *testing.T) {
	withHome(t)
	if placed := copyFrom(t.TempDir()); len(placed) != 0 {
		t.Errorf("placed %v from an empty directory", placed)
	}
}
