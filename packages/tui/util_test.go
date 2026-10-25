// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import "testing"

func TestTruncate4(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"shorter than 4 is unchanged", "ab", "ab"},
		{"exactly 4 is unchanged", "abcd", "abcd"},
		{"longer than 4 is cut to 4 runes", "abcdef", "abcd"},
		{"empty stays empty", "", ""},
		{"multi-byte runes are counted, not bytes", "日本語です", "日本語で"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Truncate4(tc.in); got != tc.want {
				t.Errorf("Truncate4(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCollapseSpace(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"single spaces unchanged", "a b c", "a b c"},
		{"runs of whitespace collapse to one space", "a   b\tc\nd", "a b c d"},
		{"leading and trailing whitespace trimmed", "  a b  ", "a b"},
		{"empty stays empty", "", ""},
		{"all whitespace becomes empty", "   \t\n ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CollapseSpace(tc.in); got != tc.want {
				t.Errorf("CollapseSpace(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestJoinColumnsPadsAndJoinsWithTwoSpaces(t *testing.T) {
	cols := [][]string{{"a", "bb"}, {"ccc"}}
	widths := []int{3, 3}
	out := JoinColumns(cols, widths, 2)
	want := []string{"a    ccc", "bb      "}
	if len(out) != len(want) {
		t.Fatalf("JoinColumns() returned %d lines, want %d", len(out), len(want))
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("JoinColumns() line %d = %q, want %q", i, out[i], want[i])
		}
	}
}

func TestJoinColumnsMissingRowBecomesBlankPadding(t *testing.T) {
	cols := [][]string{{"only-row-0"}}
	widths := []int{4}
	out := JoinColumns(cols, widths, 2)
	if len(out) != 2 {
		t.Fatalf("JoinColumns() returned %d lines, want 2", len(out))
	}
	if out[1] != "    " {
		t.Errorf("JoinColumns() row beyond a column's data = %q, want fully padded blank", out[1])
	}
}

func TestJoinColumnsLineWiderThanWidthIsNotTruncated(t *testing.T) {
	cols := [][]string{{"toolong"}}
	widths := []int{3}
	out := JoinColumns(cols, widths, 1)
	if out[0] != "toolong" {
		t.Errorf("JoinColumns() with a line wider than its column width = %q, want it left unpadded/untruncated", out[0])
	}
}

func TestMaxInt(t *testing.T) {
	cases := []struct {
		a, b, want int
	}{
		{1, 2, 2},
		{2, 1, 2},
		{-1, -2, -1},
		{3, 3, 3},
	}
	for _, tc := range cases {
		if got := MaxInt(tc.a, tc.b); got != tc.want {
			t.Errorf("MaxInt(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestMinInt(t *testing.T) {
	cases := []struct {
		a, b, want int
	}{
		{1, 2, 1},
		{2, 1, 1},
		{-1, -2, -2},
		{3, 3, 3},
	}
	for _, tc := range cases {
		if got := MinInt(tc.a, tc.b); got != tc.want {
			t.Errorf("MinInt(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}