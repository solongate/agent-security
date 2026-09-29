package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// THE SHIELD IS WIRED UP BY AN INSTALL, and for a while nothing wired it.
//
// shield.mjs landed on disk with the other hooks and no installer ever called
// InstallClaudeShim, so the one surface that masks the PROMPT did nothing at all. The
// hooks see tool calls and tool results; a secret somebody types, or one a client
// sweeps into the context it assembles, reaches the model without passing any of them.
//
// The shim is a shell function that runs `claude` through the shield. It can only be
// installed when Claude Code is on PATH, so this test puts a fake one there — the
// question is whether Install() wires what it found, not whether this machine has
// Claude Code on it.
func TestInstallWiresTheShieldShim(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the POSIX shim; the PowerShell profile path is its own case")
	}
	home := sandbox(t)
	haveHookSources(t)

	// A `claude` on PATH for the shim to wrap. It is never run.
	bin := t.TempDir()
	fake := filepath.Join(bin, "claude")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	// A shell profile to write into. shimTargets only writes files that exist, so
	// without this there is nothing to wire and the test would pass vacuously.
	profile := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(profile, []byte("# my own settings\nexport EDITOR=vi\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := Install()
	if !r.OK {
		t.Fatalf("install failed: %+v", r)
	}

	b, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if !strings.Contains(got, shimBegin) {
		t.Fatalf("no shim in the shell profile — the shield is on disk and nothing routes to it:\n%s", got)
	}
	if !strings.Contains(got, shieldHookName) {
		t.Errorf("the shim does not name the shield:\n%s", got)
	}
	if !strings.Contains(got, fake) {
		t.Errorf("the shim does not wrap the claude it found:\n%s", got)
	}
	// The user's own lines survive. A shell profile is theirs, and an installer that
	// rewrites it is worse than one that does nothing.
	if !strings.Contains(got, "export EDITOR=vi") {
		t.Errorf("the install ate the user's shell configuration:\n%s", got)
	}

	// TWICE MUST LEAVE ONE. `repair` is this same function, so a machine repaired
	// weekly would otherwise accumulate a definition of `claude` per run — and the last
	// one wins, which makes the damage invisible until one of them is wrong.
	if r2 := Install(); !r2.OK {
		t.Fatalf("second install failed: %+v", r2)
	}
	b2, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b2), shimBegin); n != 1 {
		t.Errorf("shim blocks after two installs = %d, want 1", n)
	}

	// And an uninstall takes it out, leaving the rest of the profile alone.
	Uninstall()
	b3, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b3), shimBegin) {
		t.Errorf("the shim survived an uninstall:\n%s", b3)
	}
	if !strings.Contains(string(b3), "export EDITOR=vi") {
		t.Errorf("the uninstall ate the user's shell configuration:\n%s", b3)
	}
}

// With no Claude Code on PATH there is nothing to wrap, and that is not a failure —
// but it must be SAID, because tool calls are guarded either way and the missing
// prompt-path masking is invisible from the outside.
func TestNoClaudeOnPathSaysTheShieldIsNotWired(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the POSIX shim")
	}
	sandbox(t)
	haveHookSources(t)

	// A PATH with node on it and no `claude`. Emptying PATH outright would fail the
	// install for a different reason — the hooks run under node — and prove nothing
	// about the shim.
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on PATH")
	}
	bin := t.TempDir()
	if err := os.Symlink(node, filepath.Join(bin, "node")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	r := Install()
	if !r.OK {
		t.Fatalf("an install with no Claude Code on PATH must still succeed: %+v", r)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "NOT in the prompt") {
			found = true
		}
	}
	if !found {
		t.Errorf("nothing said the prompt path is unmasked: %+v", r.Notes)
	}
}
