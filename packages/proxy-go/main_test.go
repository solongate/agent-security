// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/codeyevsky/solongate/proxy/internal/commands"
)

// TestAgentMarkerCatchesEveryClientFamily and TestAgentMarkerIgnoresAnOrdinaryShell
// stood here, and between them they pinned a list of environment-variable prefixes —
// CLAUDECODE, CURSOR, CODEX_, ANTIGRAVITY and a dozen more — any one of which made this
// CLI refuse to run.
//
// The second of the two was named "a plain human shell must not be refused, or the gate is
// a wall", and it checked exactly that: a shell with none of those variables. What it
// could not check is the case that mattered — a human in an INTEGRATED terminal, which
// inherits the agent's environment and therefore carries every one of those markers. Those
// people were refused by their own tool, in VS Code, in Cursor, in any editor whose
// terminal is a child of an agent process.
//
// The gate is the TERMINAL now: an agent tool call pipes stdin and stdout, a person has a
// tty on both. What the marker list was protecting moved to the guard, which refuses a
// tool call whose command invokes this CLI — a fact about the caller rather than a guess
// about its environment, and one that holds even if the agent allocated a pseudo-terminal.
// See reTamperCmdCLI in packages/guard-go/tamper.go, and the cases in
// test/tamper-path.mjs which drive both implementations.

// Every subcommand the CLI routes on has to exist in the table, or it falls
// through to the proxy runtime and gets spawned as an upstream program.
func TestEverySubcommandIsInTheTable(t *testing.T) {
	have := map[string]bool{}
	for _, c := range table() {
		if have[c.name] {
			t.Errorf("duplicate table entry %q", c.name)
		}
		have[c.name] = true
	}
	for name := range cliSubcommands {
		if !have[name] {
			t.Errorf("%q is routed as a human subcommand but has no table entry", name)
		}
	}
}

// A stub must not look like a success. Exit 0 would tell a script the command
// ran; this build has not run it.
//
// Only the commands that are STILL stubs are exercised. The ported ones would
// reach the network from here, and `watch` runs until it is interrupted, so
// calling them in a test would hang rather than fail.
func TestStubsDoNotReportSuccess(t *testing.T) {
	ported := map[string]bool{
		// One-line pointer at the dataroom rather than a stub.
		// Owned by the TUI slice; running it would start a Bubble Tea program.
		"dataroom": true,
		// COMMANDS THIS TEST MUST NOT INVOKE, as opposed to commands it has nothing
		// to say about. `repair` rewrites this machine's guard hooks and client
		// settings; `update` pulls the checkout it was installed from and runs its
		// install script, which rebuilds and reinstalls. Both were called by this
		// test for one run after they were ported, and both did exactly what they
		// say on whatever machine was running the suite.
		//
		// `update`'s entry went missing in a later edit while this comment stayed,
		// so the test called it. It got as far as "this install did not come from a
		// checkout" and returned 1, which read as an unported stub — the failure
		// that found this.
		"repair": true,
		"update": true,
	}
	for _, n := range commands.Names {
		ported[n] = true
	}
	// The local commands too. They are implemented in the same package and are
	// listed separately only because they take no API client; a stub test that
	// read that difference as "not written yet" would fail on a working
	// command.
	for _, n := range commands.LocalNames {
		ported[n] = true
	}

	stubs := 0
	for _, c := range table() {
		if ported[c.name] {
			continue
		}
		stubs++
		if code := c.run(nil); code != exitNotPorted {
			t.Errorf("%s returned %d, want %d so a caller can tell it was not run", c.name, code, exitNotPorted)
		}
	}
	if stubs == 0 {
		t.Log("no stubs left in the table; this test can go with the last one")
	}
}

// The management commands are wired to the real implementation, not to the
// stub. Getting this wrong is silent: the CLI would still run and would still
// exit non-zero, and it would look like the command failed rather than like it
// was never connected.
func TestManagementCommandsAreWired(t *testing.T) {
	for _, n := range commands.Names {
		c, ok := lookup(n)
		if !ok {
			t.Errorf("%q has no table entry", n)
			continue
		}
		if c.name != n {
			t.Errorf("lookup(%q) returned %q", n, c.name)
		}
	}
}

func TestLookupUnknownCommand(t *testing.T) {
	if _, ok := lookup("nope"); ok {
		t.Error("lookup accepted a command that does not exist")
	}
	if c, ok := lookup("policy"); !ok || c.name != "policy" {
		t.Error("lookup did not find a registered command")
	}
}
