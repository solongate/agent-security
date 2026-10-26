// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cliutil

import "testing"

func TestParsePositionals(t *testing.T) {
	p := Parse([]string{"foo", "bar", "baz"})
	if got := p.Positional(0); got != "foo" {
		t.Errorf("Positional(0) = %q, want foo", got)
	}
	if got := p.Positional(2); got != "baz" {
		t.Errorf("Positional(2) = %q, want baz", got)
	}
}

func TestParseFlagWithValue(t *testing.T) {
	p := Parse([]string{"--name", "value"})
	if got, ok := p.FlagStrOK("name"); !ok || got != "value" {
		t.Errorf("FlagStrOK(name) = %q, %v, want value, true", got, ok)
	}
}

func TestParseFlagWithEquals(t *testing.T) {
	p := Parse([]string{"--name=value"})
	if got, ok := p.FlagStrOK("name"); !ok || got != "value" {
		t.Errorf("FlagStrOK(name) = %q, %v, want value, true", got, ok)
	}
}

func TestParseBooleanFlagAtEndOfArgv(t *testing.T) {
	p := Parse([]string{"--verbose"})
	if !p.FlagBool("verbose") {
		t.Error("FlagBool(verbose) = false, want true for a trailing bare flag")
	}
}

func TestParseBooleanFlagFollowedByAnotherFlag(t *testing.T) {
	p := Parse([]string{"--verbose", "--quiet"})
	if !p.FlagBool("verbose") {
		t.Error("FlagBool(verbose) = false, want true when followed by another flag")
	}
	if !p.FlagBool("quiet") {
		t.Error("FlagBool(quiet) = false, want true as a trailing bare flag")
	}
}

func TestParseFlagValueStartingWithDashDashBecomesBool(t *testing.T) {
	p := Parse([]string{"--foo", "--bar", "baz"})
	if !p.FlagBool("foo") {
		t.Error("FlagBool(foo) = false, want true: its next token starts with -- so foo is a bare bool")
	}
	if got, ok := p.FlagStrOK("bar"); !ok || got != "baz" {
		t.Errorf("FlagStrOK(bar) = %q, %v, want baz, true: bar takes baz as its value", got, ok)
	}
}

func TestParseMixedOrder(t *testing.T) {
	p := Parse([]string{"pos1", "--flag1", "v1", "pos2", "--flag2=v2", "pos3"})
	if got := p.Rest(0); got != "pos1 pos2 pos3" {
		t.Errorf("Rest(0) = %q, want %q", got, "pos1 pos2 pos3")
	}
	if got := p.FlagStr("flag1"); got != "v1" {
		t.Errorf("FlagStr(flag1) = %q, want v1", got)
	}
	if got := p.FlagStr("flag2"); got != "v2" {
		t.Errorf("FlagStr(flag2) = %q, want v2", got)
	}
}

func TestFlagStrAbsent(t *testing.T) {
	p := Parse(nil)
	if got, ok := p.FlagStrOK("missing"); ok || got != "" {
		t.Errorf("FlagStrOK(missing) = %q, %v, want \"\", false", got, ok)
	}
	if got := p.FlagStr("missing"); got != "" {
		t.Errorf("FlagStr(missing) = %q, want \"\"", got)
	}
}

func TestFlagStrOnBoolFlagIsEmpty(t *testing.T) {
	p := Parse([]string{"--verbose"})
	if got, ok := p.FlagStrOK("verbose"); ok || got != "" {
		t.Errorf("FlagStrOK(verbose) on a bool flag = %q, %v, want \"\", false", got, ok)
	}
}

func TestFlagNum(t *testing.T) {
	cases := []struct {
		name   string
		argv   []string
		flag   string
		wantN  int
		wantOK bool
	}{
		{"valid int", []string{"--n", "42"}, "n", 42, true},
		{"valid float", []string{"--n", "3.9"}, "n", 3, true},
		{"empty string", []string{"--n="}, "n", 0, false},
		{"non numeric", []string{"--n", "abc"}, "n", 0, false},
		{"inf rejected", []string{"--n", "Inf"}, "n", 0, false},
		{"neg inf rejected", []string{"--n", "-Inf"}, "n", 0, false},
		{"nan rejected", []string{"--n", "NaN"}, "n", 0, false},
		{"absent", nil, "n", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Parse(tc.argv)
			n, ok := p.FlagNumOK(tc.flag)
			if n != tc.wantN || ok != tc.wantOK {
				t.Errorf("FlagNumOK(%s) = %d, %v, want %d, %v", tc.flag, n, ok, tc.wantN, tc.wantOK)
			}
			if got := p.FlagNum(tc.flag); got != tc.wantN {
				t.Errorf("FlagNum(%s) = %d, want %d", tc.flag, got, tc.wantN)
			}
		})
	}
}

func TestFlagBool(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		flag string
		want bool
	}{
		{"bare bool true", []string{"--v"}, "v", true},
		{"string true", []string{"--v=true"}, "v", true},
		{"string false", []string{"--v=false"}, "v", false},
		{"other string", []string{"--v=yes"}, "v", false},
		{"absent", nil, "v", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Parse(tc.argv)
			if got := p.FlagBool(tc.flag); got != tc.want {
				t.Errorf("FlagBool(%s) = %v, want %v", tc.flag, got, tc.want)
			}
		})
	}
}

func TestPositionalOutOfRange(t *testing.T) {
	p := Parse([]string{"a", "b"})
	if got := p.Positional(5); got != "" {
		t.Errorf("Positional(5) = %q, want \"\"", got)
	}
}

func TestRestOutOfRange(t *testing.T) {
	p := Parse([]string{"a", "b"})
	if got := p.Rest(5); got != "" {
		t.Errorf("Rest(5) = %q, want \"\"", got)
	}
}

func TestTailInRange(t *testing.T) {
	p := Parse([]string{"--flag", "v", "a", "b", "c"})
	tail := p.Tail(1)
	if got := tail.Rest(0); got != "b c" {
		t.Errorf("Tail(1).Rest(0) = %q, want %q", got, "b c")
	}
	if got := tail.FlagStr("flag"); got != "v" {
		t.Errorf("Tail(1).FlagStr(flag) = %q, want v (flags must survive Tail)", got)
	}
}

func TestTailBeyondLengthKeepsFlags(t *testing.T) {
	p := Parse([]string{"--flag", "v", "a"})
	tail := p.Tail(10)
	if got := tail.Rest(0); got != "" {
		t.Errorf("Tail(10).Rest(0) = %q, want \"\"", got)
	}
	if got := tail.Positional(0); got != "" {
		t.Errorf("Tail(10).Positional(0) = %q, want \"\"", got)
	}
	if got := tail.FlagStr("flag"); got != "v" {
		t.Errorf("Tail(10).FlagStr(flag) = %q, want v (flags must survive Tail)", got)
	}
}