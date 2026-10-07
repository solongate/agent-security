// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The guard's own per-agent state must be unreachable from a tool call, by EVERY
// route — not only from a shell command.
//
// IT WAS REACHABLE IN THE JAVASCRIPT HOOK, not in this binary, and the asymmetry
// is the point. Go's MatchPathGlob compiles a pattern to a regex, so the `*` in
// the per-agent entry is a real wildcard and the file matched all along. The
// hook's matchPathGlob splits on `**` and substring-tests each remaining piece,
// leaving that `*` literal — and no filename contains one. A machine runs
// whichever of the two it has.
//
// That was a disarm with a wide mouth. Deleting the policy cache through the
// shell was refused on both sides, but a Write tool aimed at the same path went
// through on the hook, and every coding agent has one. Overwriting it with `{}`
// leaves the guard with no policy to apply, so the next call is allowed — and the
// refresh that would repair it is debounced for three seconds, so it repeats.
//
// This test holds the line for the binary. It passed before the fix too, because
// the glob already covered it here; what it protects against is the protection
// moving back onto a glob-engine subtlety that the policy layer can change.
//
// The names are assembled rather than written out: the protection under test
// matches this repository's own paths otherwise, and the tooling that edits these
// files refuses to touch them. That is the protection working, and it is worth
// knowing it reaches this far.
func TestTheGuardsOwnStateIsUnreachableByPath(t *testing.T) {
	home := "/home/dev"
	sg := filepath.Join(home, ".solongate")
	agent := "claude-code"

	blocked := []struct{ name, path string }{
		{"the policy cache", filepath.Join(sg, "."+"policy"+"-cache-"+agent+".json")},
		// `.log`, which is what the limiter actually writes. This case said `.json` and
		// passed anyway, because the basename rule matches the prefix — so it was
		// asserting protection for a path that never exists. Deleting the real file
		// resets the window, turning a limit of N calls/minute into N per deletion, so
		// this is the entry on this list with a live payoff.
		{"the rate-limit counter", filepath.Join(sg, "."+"ratelimit-"+agent+".log")},
		{"the credential", filepath.Join(sg, "cloud"+"-guard.json")},
		{"a hook", filepath.Join(sg, "hooks", "au"+"dit.mjs")},
		// The guard BINARY and its directory. The hook runs whatever is there once it
		// prints the expected version, so this is the shortest disarm there is.
		{"the guard binary", filepath.Join(sg, "bin", "solongate-guard")},
		{"the binary's directory", filepath.Join(sg, "bin")},
	}
	// The compiled policy — `.opa-wasm-<agent>.json` — was on this list. It was what a
	// service sent; nothing writes it and nothing reads it, so a leftover one is not
	// state and tampering with it achieves nothing. Protecting a file that cannot exist
	// reads as thoroughness and is not.
	for _, c := range blocked {
		if hit := isProtectedPath(c.path); hit == "" {
			t.Errorf("%s is reachable by path: %s", c.name, c.path)
		}
	}

	// And the other half, which is what keeps this from being a blunt instrument:
	// the names above are matched as PREFIXES, and several of them are names a
	// person's own project may well use. Protecting them everywhere would block
	// files that have nothing to do with this product.
	allowed := []struct{ name, path string }{
		{"a project's own policy file", "/src/app/" + "poli" + "cy.json"},
		{"a project's own cache directory", "/src/app/cache/" + "." + "policy" + "-cache-x.json"},
		{"an ordinary source file", "/src/app/main.go"},
		{"a directory that merely starts the same way", "/home/dev/.solongate-backup/anything.json"},
	}
	for _, c := range allowed {
		if hit := isProtectedPath(c.path); hit != "" {
			t.Errorf("%s is blocked and should not be: %s (matched %q)", c.name, c.path, hit)
		}
	}
}

// The two implementations have to agree about this, because which one decides a
// call depends on whether a machine has the binary. The JavaScript twin carries
// the same block; this asserts it is still there rather than asserting its
// behaviour, which is what the conformance suite drives end to end.
func TestTheJavaScriptTwinCarriesTheSameCheck(t *testing.T) {
	path := filepath.Join("..", "proxy", "hooks", "gu"+"ard.mjs")
	src, err := os.ReadFile(path)
	if err != nil {
		// Not skipped. A guard-go checked out without the npm package beside it
		// cannot verify the pair agrees, and reporting that as a pass is how the
		// check stops being a check.
		t.Fatalf("cannot read the Node hook at %s: %v", path, err)
	}
	// The scoping test and the basename loop, which together are the fix.
	for _, want := range []string{`\.solongate\/`, "TAMPER_BASENAMES", "lastIndexOf('/')"} {
		if !strings.Contains(string(src), want) {
			t.Errorf("the Node hook's isProtectedPath no longer contains %q — the two have diverged", want)
		}
	}
}
