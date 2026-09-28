package main

import (
	"testing"

	"github.com/codeyevsky/solongate/proxy/internal/commands"
)

// The gate is the reason an agent cannot turn the guard off, so its matching is
// tested rather than read. Every entry here is a variable one of the guarded
// clients actually leaks into a tool subprocess.
func TestAgentMarkerCatchesEveryClientFamily(t *testing.T) {
	cases := []struct{ env, want string }{
		{"CLAUDECODE=1", "CLAUDECODE"},
		{"CLAUDE_CODE_CHILD_SESSION=x", "CLAUDE_CODE_CHILD_SESSION"},
		{"CLAUDE_AGENT_ID=x", "CLAUDE_AGENT_ID"},
		{"ANTIGRAVITY_SESSION=x", "ANTIGRAVITY_SESSION"},
		{"CORTEX_HOME=/x", "CORTEX_HOME"},
		{"CASCADE_ID=x", "CASCADE_ID"},
		{"WINDSURF=1", "WINDSURF"},
		{"JETSKI_X=1", "JETSKI_X"},
		{"EXA_KEY=1", "EXA_KEY"},
		{"GEMINI_CLI=1", "GEMINI_CLI"},
		{"GEMINI_CWD=/x", "GEMINI_CWD"},
		{"CURSOR_TRACE_ID=x", "CURSOR_TRACE_ID"},
		{"AIDER_MODEL=x", "AIDER_MODEL"},
		{"OPENAI_CODEX_X=1", "OPENAI_CODEX_X"},
		{"CODEX_HOME=/x", "CODEX_HOME"},
		{"OPENCLAW=1", "OPENCLAW"},
		{"REPLIT_DB_URL=x", "REPLIT_DB_URL"},
		{"DEVIN=1", "DEVIN"},
	}
	for _, tc := range cases {
		if got := agentMarkerIn([]string{"PATH=/usr/bin", tc.env, "HOME=/home/me"}); got != tc.want {
			t.Errorf("agentMarkerIn(%q) = %q, want %q", tc.env, got, tc.want)
		}
	}
}

// A plain human shell must not be refused, or the gate is a wall.
func TestAgentMarkerIgnoresAnOrdinaryShell(t *testing.T) {
	env := []string{
		"PATH=/usr/bin", "HOME=/home/me", "SHELL=/bin/bash", "TERM=xterm-256color",
		"LANG=en_GB.UTF-8", "PWD=/home/me/proj", "EDITOR=vim",
		// Names that merely mention an agent word without being one of the
		// prefixes: a human who set them must still be able to run the CLI.
		"MY_CLAUDE_NOTES=/home/me/notes", "GEMINI=x", "CODEX=x",
	}
	if got := agentMarkerIn(env); got != "" {
		t.Errorf("agentMarkerIn refused an ordinary shell via %q", got)
	}
}

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
		// `update` reaches the npm registry and can run `npm install -g`, and
		// `repair` rewrites this machine's guard hooks and client settings.
		// Both were called by this test for one run after they were ported, and
		// `update` did install the package globally: the test binary carries no
		// version stamp, so it compared itself as 0.0.0 and concluded it was out
		// of date. The updater refuses an unstamped build now (see
		// selfupdate.VersionKnown), and neither belongs in a list of commands
		// this test INVOKES.
		"repair": true,
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
