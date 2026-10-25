// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestHookCommandNonWindows(t *testing.T) {
	p := Paths{HooksDir: filepath.Join("home", ".solongate", "hooks")}

	cases := []struct {
		name string
		kind string
		want string
	}{
		{"guard", guardKind, `/bin/sh "home/.solongate/hooks/sg-run.sh" guard client-x "Client X"`},
		{"audit", auditKind, `/bin/sh "home/.solongate/hooks/sg-run.sh" audit client-x "Client X"`},
		{"tokens", tokensKind, `/bin/sh "home/.solongate/hooks/sg-run.sh" tokens client-x "Client X"`},
	}
	for _, tc := range cases {
		got := hookCommand(p, tc.kind, "client-x", "Client X")
		if got != tc.want {
			t.Errorf("hookCommand(%s) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestHookCommandUsesSlashSeparators(t *testing.T) {
	p := Paths{HooksDir: filepath.Join("home", ".solongate", "hooks")}
	got := hookCommand(p, guardKind, "c", "C")
	if strings.Contains(got, `\`) {
		t.Errorf("hookCommand() = %q, want forward slashes only", got)
	}
}

func TestClaudeHookCommandUsesClaudeCodeLabel(t *testing.T) {
	p := Paths{HooksDir: "hooks"}
	got := claudeHookCommand(p, auditKind)
	if !strings.Contains(got, "claude-code") || !strings.Contains(got, `"Claude Code"`) {
		t.Errorf("claudeHookCommand() = %q, want it to reference claude-code / \"Claude Code\"", got)
	}
	if !strings.Contains(got, auditKind) {
		t.Errorf("claudeHookCommand() = %q, want it to reference the audit kind", got)
	}
}

func TestLauncherAndBeatConstants(t *testing.T) {
	if LauncherName != "sg-run.sh" {
		t.Errorf("LauncherName = %q, want sg-run.sh", LauncherName)
	}
	if BeatDirName != ".beat" {
		t.Errorf("BeatDirName = %q, want .beat", BeatDirName)
	}
	kinds := map[string]bool{guardKind: true, auditKind: true, tokensKind: true}
	if len(kinds) != 3 {
		t.Errorf("guard/audit/tokens kinds collide: %v", kinds)
	}
}