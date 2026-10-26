// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package policy

import (
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/config"
)

func TestProtectUsage(t *testing.T) {
	u := protectUsage()
	for _, want := range []string{"solongate policy protect", "require-sandbox", "remove <path>"} {
		if !strings.Contains(u, want) {
			t.Errorf("protectUsage() missing %q:\n%s", want, u)
		}
	}
}

func TestLockColour(t *testing.T) {
	tests := []struct {
		name string
		lock config.Lock
		want string
	}{
		{"immutable", config.Lock{How: "chattr +i", Immutable: true}, cliutil.Green(config.Lock{How: "chattr +i", Immutable: true}.Summary())},
		{"held but not immutable", config.Lock{How: "chmod 0400"}, cliutil.Yellow(config.Lock{How: "chmod 0400"}.Summary())},
		{"neither", config.Lock{}, cliutil.Red(config.Lock{}.Summary())},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lockColour(tc.lock); got != tc.want {
				t.Errorf("lockColour() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSandboxLine(t *testing.T) {
	if got := sandboxLine(true); !strings.Contains(got, "required") {
		t.Errorf("sandboxLine(true) = %q, want it to mention \"required\"", got)
	}
	if got := sandboxLine(false); !strings.Contains(got, "applied when started with") {
		t.Errorf("sandboxLine(false) = %q, want it to mention the non-required phrasing", got)
	}
}

func TestAskYes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"y", "y\n", true},
		{"yes", "yes\n", true},
		{"no", "no\n", false},
		{"empty input (EOF)", "", false},
		{"garbage", "maybe\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withStdin(t, tc.input)
			got := askYes("prompt: ")
			if got != tc.want {
				t.Errorf("askYes(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
