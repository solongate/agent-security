// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"sort"
	"testing"
)

func TestNamesStayInSyncWithHandlers(t *testing.T) {
	h := handlers()
	got := append([]string(nil), Names...)
	sort.Strings(got)

	want := make([]string, 0, len(h))
	for name := range h {
		want = append(want, name)
	}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("Names contains %d commands, handlers() contains %d: got %v, want %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Names[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	for _, name := range LocalNames {
		if _, ok := h[name]; !ok {
			t.Errorf("LocalNames contains %q, which has no handler", name)
		}
	}
}
