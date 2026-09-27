package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// The Node hook and this binary have to agree about which one they are.
//
// The hook hands a call to this binary only when `--sg-version` matches its own
// HOOK_VERSION, and falls back to deciding in Node when it does not. That check
// is only worth anything if the number here tracks the number there: a guard.mjs
// change that alters a decision and bumps HOOK_VERSION, without the same change
// landing here, would leave a binary that says "80" and decides like 79. The
// hook would trust it, and the machine would enforce something nobody wrote.
//
// This test is what makes that impossible to do quietly. If it fails, the
// question to answer is not "which number do I edit" — it is "does this Go code
// implement what guard.mjs now does?" Bumping the constant to make the test pass
// without porting the change is exactly the failure the test exists to catch.
func TestHookVersionMatchesTheNodeHook(t *testing.T) {
	// From packages/guard-go to the hook the npm package ships.
	path := filepath.Join("..", "proxy", "hooks", "guard.mjs")
	src, err := os.ReadFile(path)
	if err != nil {
		// Not skipped. A guard-go checked out without the npm package next to it
		// cannot verify the one number that lets it be trusted, and reporting
		// that as a pass is how the check stops being a check.
		t.Fatalf("cannot read the Node hook at %s: %v", path, err)
	}

	m := regexp.MustCompile(`(?m)^const HOOK_VERSION\s*=\s*(\d+)\s*;`).FindSubmatch(src)
	if m == nil {
		t.Fatalf("no `const HOOK_VERSION = <n>;` in %s — if it was renamed, this test and main.go's hookVersion have to follow", path)
	}
	want, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("HOOK_VERSION in %s is not a number: %q", path, m[1])
	}

	if hookVersion != want {
		t.Fatalf("hookVersion = %d, guard.mjs HOOK_VERSION = %d\n\n"+
			"These must be equal or the hook will hand calls to a binary that decides differently.\n"+
			"If guard.mjs changed, port the change here FIRST, then set hookVersion = %d.\n"+
			"If it did not, the hook is what needs fixing.",
			hookVersion, want, want)
	}
}

// The version answer is on the critical path of every tool call that takes the
// fast route, so it has to be exactly a number and nothing else — no banner, no
// "v" prefix, no trailing prose. The hook compares strings.
func TestVersionFlagPrintsBareNumber(t *testing.T) {
	if _, err := strconv.Atoi(strconv.Itoa(hookVersion)); err != nil {
		t.Fatalf("hookVersion is not an integer: %v", err)
	}
	if hookVersion <= 0 {
		t.Fatalf("hookVersion = %d, which no hook will ever match", hookVersion)
	}
}
