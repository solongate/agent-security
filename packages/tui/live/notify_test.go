// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package live

import "testing"

func TestWindowsPowerShellFallsBackWhenNotFound(t *testing.T) {
	// On a non-Windows test runner (or any machine without that exact
	// install layout) the computed path never exists, so windowsPowerShell
	// must fall back to the bare "powershell" command name regardless of
	// SystemRoot. This exercises that not-found branch; the found/Stat-ok
	// branch is not reachable here without writing outside the sandbox.
	t.Setenv("SystemRoot", "")
	if got := windowsPowerShell(); got != "powershell" {
		t.Errorf("windowsPowerShell() = %q, want %q with no SystemRoot set", got, "powershell")
	}

	t.Setenv("SystemRoot", `C:\DoesNotExist`)
	if got := windowsPowerShell(); got != "powershell" {
		t.Errorf("windowsPowerShell() = %q, want %q with an unresolvable SystemRoot", got, "powershell")
	}
}

func TestUnixBinaryFallsBackWhenNotFound(t *testing.T) {
	const name = "sg-definitely-not-a-real-binary-xyz"
	if got := unixBinary(name); got != name {
		t.Errorf("unixBinary(%q) = %q, want the bare name when /usr/bin/%s does not exist", name, got, name)
	}
}