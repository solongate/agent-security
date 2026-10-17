// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/solongate/agent-security/packages/shared"
)

func TestNormalizeSandboxID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"1", "001"},
		{"01", "001"},
		{"001", "001"},
		{"  2  ", "002"},
		{"42", "042"},
		{"999", "999"},

		{"1000", "1000"},

		{"claude", "claude"},
		{"1a", "1a"},
		{"", ""},
	}
	for _, c := range cases {
		if got := NormalizeSandboxID(c.in); got != c.want {
			t.Errorf("NormalizeSandboxID(%q)=%q, want %q", c.in, got, c.want)
		}
	}
}

func TestNextSandboxIDFillsTheGap(t *testing.T) {
	boxes := func(ids ...string) []shared.Sandbox {
		out := make([]shared.Sandbox, 0, len(ids))
		for _, id := range ids {
			out = append(out, shared.Sandbox{ID: id})
		}
		return out
	}

	cases := []struct {
		name     string
		existing []shared.Sandbox
		want     string
	}{
		{"nothing yet", nil, "001"},
		{"one box", boxes("001"), "002"},
		{"a run with no gaps", boxes("001", "002", "003"), "004"},
		{"002 was deleted", boxes("001", "003"), "002"},
		{"001 was deleted", boxes("002", "003"), "001"},
		{"out of order on disk", boxes("003", "001"), "002"},
		{"a gap further along", boxes("001", "002", "004", "005"), "003"},
	}
	for _, c := range cases {
		if got := nextSandboxID(c.existing); got != c.want {
			t.Errorf("%s: nextSandboxID=%q, want %q", c.name, got, c.want)
		}
	}
}

func TestValidateSandboxDirRefusesWhatIsNotAConfinement(t *testing.T) {
	real := t.TempDir()
	file := filepath.Join(real, "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()

	bad := []struct{ name, dir string }{
		{"empty", ""},
		{"a tilde, which is a shell convention", "~/projects/x"},
		{"a tilde alone", "~"},
		{"relative", "projects/x"},
		{"relative with a dot", "./projects/x"},
		{"root", "/"},
		{"a file rather than a directory", file},
		{"a directory that does not exist", filepath.Join(real, "nope")},
	}
	for _, c := range bad {
		if _, err := validateSandboxDir(c.dir); err == nil {
			t.Errorf("%s: validateSandboxDir(%q) was accepted", c.name, c.dir)
		}
	}

	if home != "" {
		if _, err := validateSandboxDir(home); err == nil {
			t.Error("the home directory was accepted as a sandbox")
		}
	}

	got, err := validateSandboxDir(real)
	if err != nil {
		t.Fatalf("a real absolute directory was refused: %v", err)
	}
	if got != filepath.Clean(real) {
		t.Errorf("validateSandboxDir returned %q, want the cleaned path %q", got, filepath.Clean(real))
	}

	messy := filepath.Join(real, "..", filepath.Base(real))
	if got, err := validateSandboxDir(messy); err != nil {
		t.Errorf("a path needing cleaning was refused: %v", err)
	} else if got != filepath.Clean(real) {
		t.Errorf("validateSandboxDir(%q)=%q, want %q", messy, got, filepath.Clean(real))
	}
}

func TestPolicyAppliesTo(t *testing.T) {
	cases := []struct {
		name   string
		agents []string
		client string
		want   bool
	}{
		{"no list means every client", nil, "claude-code", true},
		{"an empty list means every client", []string{}, "claude-code", true},
		{"a client in the list", []string{"claude-code", "codex"}, "codex", true},
		{"a client not in the list", []string{"claude-code"}, "codex", false},
		{"an unknown client against a list", []string{"claude-code"}, "something-else", false},
		{"an empty client against a list", []string{"claude-code"}, "", false},
		{"an empty client with no list", nil, "", true},
	}
	for _, c := range cases {
		p := shared.Policy{Agents: c.agents}
		if got := p.AppliesTo(c.client); got != c.want {
			t.Errorf("%s: AppliesTo(%q)=%v, want %v", c.name, c.client, got, c.want)
		}
	}
}