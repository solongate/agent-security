// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package policy

import "testing"

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
