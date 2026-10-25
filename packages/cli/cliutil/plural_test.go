// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cliutil

import "testing"

func TestPlural(t *testing.T) {
	cases := []struct {
		name string
		n    int
		one  string
		many string
		want string
	}{
		{"one", 1, "item", "items", "1 item"},
		{"zero", 0, "item", "items", "0 items"},
		{"two", 2, "item", "items", "2 items"},
		{"negative", -1, "item", "items", "-1 items"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Plural(tc.n, tc.one, tc.many); got != tc.want {
				t.Errorf("Plural(%d, %q, %q) = %q, want %q", tc.n, tc.one, tc.many, got, tc.want)
			}
		})
	}
}