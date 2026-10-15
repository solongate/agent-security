// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package policy

import "testing"

// TWO FUNCTIONS THAT BUILD A REGEX OR RUN ONE FROM UNTRUSTED INPUT, which is
// exactly where a policy file (or a model's obfuscated command) gets to pick
// the input these seeds explore the edges of.
//
// MatchGlob's own comment already names the risk: `a***b` is the kind of
// pattern a backtracking engine turns into a stall before every tool call.
// NormalizeShellCommand runs a chain of regexes over attacker-shaped text to
// undo quoting and variable substitution. Neither should panic or hang on any
// input; that is the only property a fuzz target here is asked to hold.

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