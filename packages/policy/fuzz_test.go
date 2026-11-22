// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package policy

import (
	"regexp"
	"testing"
)

func FuzzMatchGlob(f *testing.F) {
	for _, seed := range []struct{ str, pattern string }{
		{"a.txt", "*"},
		{"/etc/shadow", "/etc/*"},
		{"a***b", "a***b"},
		{"", ""},
		{"ABC", "abc"},
	} {
		f.Add(seed.str, seed.pattern)
	}
	f.Fuzz(func(t *testing.T, str, pattern string) {
		MatchGlob(str, pattern)
	})
}

func FuzzMatchPathGlob(f *testing.F) {
	for _, seed := range []struct{ path, pattern string }{
		{"a.txt", "*"},
		{"/etc/shadow", "/etc/*"},
		{"a***b", "a***b"},
		{"", ""},
		{"ABC", "abc"},
	} {
		f.Add(seed.path, seed.pattern)
	}
	f.Fuzz(func(t *testing.T, path, pattern string) {
		MatchPathGlob(path, pattern)
	})
}

func FuzzListGlobToRegex(f *testing.F) {
	for _, seed := range []struct{ first, second string }{
		{"a.txt", "*"},
		{"/etc/shadow", "/etc/*"},
		{"a***b", "a***b"},
		{"", ""},
		{"ABC", "abc"},
	} {
		f.Add(seed.first, seed.second)
	}
	f.Fuzz(func(t *testing.T, first, second string) {
		re := ListGlobToRegex([]string{first, second})
		if _, err := regexp.Compile(re); err != nil {
			t.Fatalf("ListGlobToRegex(%q, %q) produced a regex that does not compile %q: %v", first, second, re, err)
		}
	})
}

func FuzzNormalizeShellCommand(f *testing.F) {
	for _, seed := range []string{
		"",
		"cat .env",
		`a=.en; cat ${a}v`,
		`cat .e""nv`,
		"a=1; b=${a}; echo $b",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		NormalizeShellCommand(cmd)
	})
}
