// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

import (
	"testing"

	"github.com/solongate/agent-security/packages/shared"
)

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

// Issue #200: dlpPatternNames is a hand-maintained copy of
// shared.DLPPatternNames(), so a reorder of the real scan patterns (to fix
// match precedence, e.g. OpenRouter before OpenAI) silently left this list,
// and therefore the TUI DLP panel and the dlp CLI commands, showing the
// stale order. Pin the two lists together so they can't drift again.
func TestDLPPatternNamesMatchesSharedScanOrder(t *testing.T) {
	want := shared.DLPPatternNames()
	if len(dlpPatternNames) != len(want) {
		t.Fatalf("got %d pattern names, want %d (shared.DLPPatternNames)", len(dlpPatternNames), len(want))
	}
	for i, name := range want {
		if dlpPatternNames[i] != name {
			t.Errorf("pattern %d = %q, want %q (shared.DLPPatternNames order)", i, dlpPatternNames[i], name)
		}
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