// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

import "testing"

func TestAvailablePatternsReturnsEveryName(t *testing.T) {
	got := AvailablePatterns()
	if len(got) != len(dlpPatternNames) {
		t.Fatalf("got %d patterns, want %d", len(got), len(dlpPatternNames))
	}
	for i, name := range dlpPatternNames {
		if got[i] != name {
			t.Errorf("pattern %d = %q, want %q", i, got[i], name)
		}
	}
}

func TestAvailablePatternsReturnsACopy(t *testing.T) {
	got := AvailablePatterns()
	if len(got) == 0 {
		t.Fatal("no patterns to mutate")
	}
	original := dlpPatternNames[0]
	got[0] = "mutated"
	if dlpPatternNames[0] != original {
		t.Error("mutating the returned slice changed the package's own pattern list")
	}
}

func TestAvailablePatternsHasNoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range AvailablePatterns() {
		if seen[name] {
			t.Errorf("pattern %q appears more than once", name)
		}
		seen[name] = true
	}
}