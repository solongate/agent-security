// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// Two capabilities, and neither is an identity. A layer asks what the client can
// do, never which client is running.
//
// ReportsAfter is the one that decides whether an OBSERVED signal is written
// from here. Antigravity has no post-tool stage, so a detect-mode DLP hit this
// binary does not record is not recorded anywhere — the mode looked like it was
// working, because reads were still being redacted, while an argument carrying a
// secret went out with no row behind it.
func TestClientCapabilitiesAreDeclaredForEveryClient(t *testing.T) {
	for name, want := range map[string]struct{ reportsAfter, redactsOutput bool }{
		"claude-code": {true, true},
		"codex":       {true, false},
		"opencode":    {true, false},
		"antigravity": {false, false},
		// An unknown client claims neither: masking that cannot be applied
		// becomes a block, and a signal nothing else would file is filed here.
		"generic": {false, false},
	} {
		c, ok := clients[name]
		if !ok {
			t.Errorf("%s has no adapter", name)
			continue
		}
		if c.ReportsAfter != want.reportsAfter {
			t.Errorf("%s: ReportsAfter = %v, want %v", name, c.ReportsAfter, want.reportsAfter)
		}
		if c.RedactsOutput != want.redactsOutput {
			t.Errorf("%s: RedactsOutput = %v, want %v", name, c.RedactsOutput, want.redactsOutput)
		}
	}
}

// An unknown client must claim the weaker capability on both, or a client nobody
// has adapted yet is silently the least guarded one.
func TestAnUnknownClientClaimsNothing(t *testing.T) {
	c := clientFor("something-nobody-has-adapted")
	if c != clients["generic"] {
		t.Fatal("an unknown client must fall back to the generic adapter")
	}
	if c.ReportsAfter || c.RedactsOutput {
		t.Error("the generic adapter must not claim a capability it cannot prove")
	}
}
