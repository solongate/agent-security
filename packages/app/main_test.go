// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	f()
	os.Stdout = old
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// printHelp's run and sandbox lines must match the real CLI contracts:
// run takes <command> [args...] (a leading "--" is optional, never required);
// sandbox takes an id before the agent, not a "-- <agent>" form.
func TestPrintHelpDocumentsRealSandboxSyntax(t *testing.T) {
	out := captureStdout(t, printHelp)
	if strings.Contains(out, "sandbox -- <agent>") {
		t.Error("help text still documents \"sandbox -- <agent>\", which sandbox does not accept")
	}
	if !strings.Contains(out, "sandbox <id> <agent>") {
		t.Error("help text should document \"sandbox <id> <agent>\"")
	}
	if strings.Contains(out, "run -- <agent>") {
		t.Error("help text still documents \"run -- <agent>\", which run does not require")
	}
	if !strings.Contains(out, "run <command> [args...]") {
		t.Error("help text should document \"run <command> [args...]\"")
	}
}

// The human-only gate has no exemption. SOLONGATE_INTERNAL=1 once skipped it
// for a daemon that no longer exists; with that gone, the variable was only a
// way for an agent to walk past the gate by exporting it (issue #173).
func TestAssertHumanTerminalIgnoresInternalEnv(t *testing.T) {
	if os.Getenv("SG_TEST_GATE_CHILD") == "1" {
		assertHumanTerminal(false)
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestAssertHumanTerminalIgnoresInternalEnv$")
	cmd.Env = append(os.Environ(), "SG_TEST_GATE_CHILD=1", "SOLONGATE_INTERNAL=1")
	// Pipes on every stream, so the child has no terminal, like an agent's subprocess.
	var stdout, stderr bytes.Buffer
	cmd.Stdin = strings.NewReader("")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("a non-interactive caller with SOLONGATE_INTERNAL=1 got past the gate (err=%v)", err)
	}
	if !strings.Contains(stderr.String(), "SolonGate is human-only") {
		t.Errorf("refused without saying why; stderr:\n%s", stderr.String())
	}
}

// update rebuilds and reinstalls the binaries, and the explain forms of run and
// sandbox map out what confinement leaves open. None of them may answer a
// caller with no terminal (issues #226, #252, #174, #253). update gets an
// argument it refuses with exit 2, so a missing gate fails this test instead
// of pulling and reinstalling anything.
func TestHumanOnlyGateRefusesNonInteractiveCallers(t *testing.T) {
	if raw, ok := os.LookupEnv("SG_TEST_GATE_ARGS"); ok {
		os.Exit(run(strings.Fields(raw)))
	}

	for _, args := range []string{
		"update --not-an-argument",
		"run --explain",
		"run explain",
		"sandbox --explain",
		"sandbox explain",
		"sandbox --explain 001",
		"sandbox -- --explain",
	} {
		t.Run(args, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestHumanOnlyGateRefusesNonInteractiveCallers$")
			cmd.Env = append(os.Environ(), "SG_TEST_GATE_ARGS="+args, "HOME="+t.TempDir())
			var stderr bytes.Buffer
			cmd.Stdin = strings.NewReader("")
			cmd.Stdout = io.Discard
			cmd.Stderr = &stderr

			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("`solongate %s` ran without a terminal (err=%v); stderr:\n%s", args, err, stderr.String())
			}
			if !strings.Contains(stderr.String(), "SolonGate is human-only") {
				t.Errorf("refused without saying why; stderr:\n%s", stderr.String())
			}
		})
	}
}

// Only the explain forms are gated: launching an agent has to keep working
// from a script, and run hands a "--" straight to the agent's argv.
func TestExplainRequested(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"run"}, false},
		{[]string{"run", "--explain"}, true},
		{[]string{"run", "explain"}, true},
		{[]string{"run", "--", "claude"}, false},
		{[]string{"run", "--", "--explain"}, false},
		{[]string{"run", "claude", "--explain"}, false},
		{[]string{"sandbox"}, false},
		{[]string{"sandbox", "--"}, false},
		{[]string{"sandbox", "--explain"}, true},
		{[]string{"sandbox", "explain", "001"}, true},
		{[]string{"sandbox", "--", "--explain"}, true},
		{[]string{"sandbox", "001", "claude"}, false},
		{[]string{"sandbox", "list"}, false},
		{[]string{"doctor", "--explain"}, false},
	} {
		if got := explainRequested(tc.args); got != tc.want {
			t.Errorf("explainRequested(%q) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

// errRefreshed stops run() right after the guard refresh, before any command starts.
var errRefreshed = errors.New("guard refresh requested")

// run and sandbox launch agents against the installed guard, so they must refresh
// it like the human commands do, and do it without asking for a terminal (#283).
func TestAgentLaunchersRefreshGuardBinaries(t *testing.T) {
	orig := installGoBinaries
	t.Cleanup(func() { installGoBinaries = orig })
	installGoBinaries = func() []string { panic(errRefreshed) }

	refreshed := func(args ...string) (hit bool) {
		defer func() {
			if r := recover(); r != nil {
				if r != errRefreshed {
					panic(r)
				}
				hit = true
			}
		}()
		captureStdout(t, func() { run(args) })
		return false
	}

	for _, args := range [][]string{
		{"run", "--", "claude"},
		{"run", "claude"},
		{"sandbox", "001", "claude"},
	} {
		if !refreshed(args...) {
			t.Errorf("`solongate %s` launched without refreshing the guard binaries", strings.Join(args, " "))
		}
	}

	if refreshed("not-a-command") {
		t.Error("an unknown command refreshed the guard binaries")
	}
}

func TestPrintWelcome(t *testing.T) {
	output := captureStdout(t, printWelcome)

	if !strings.Contains(output, "solongate doctor") {
		t.Errorf("expected output to mention 'solongate doctor', got: %s", output)
	}

	if !strings.Contains(output, "~/.solongate/") {
		t.Errorf("expected output to mention '~/.solongate/', got: %s", output)
	}
}

// version and help answer before any gate or guard refresh, so they work from
// scripts and agents alike.
func TestRunVersionAndHelpShortCircuit(t *testing.T) {
	orig := installGoBinaries
	t.Cleanup(func() { installGoBinaries = orig })
	installGoBinaries = func() []string { t.Fatal("version/help must not refresh the guard binaries"); return nil }

	origVersion := buildVersion
	t.Cleanup(func() { buildVersion = origVersion })
	buildVersion = "v9.9.9-test"

	for _, arg := range []string{"--version", "-v", "version"} {
		var code int
		out := captureStdout(t, func() { code = run([]string{arg}) })
		if code != 0 {
			t.Errorf("run(%q) = %d, want 0", arg, code)
		}
		if strings.TrimSpace(out) != "v9.9.9-test" {
			t.Errorf("run(%q) printed %q, want the build version", arg, out)
		}
	}

	for _, arg := range []string{"--help", "-h", "help"} {
		var code int
		out := captureStdout(t, func() { code = run([]string{arg}) })
		if code != 0 {
			t.Errorf("run(%q) = %d, want 0", arg, code)
		}
		if !strings.Contains(out, "sandbox <id> <agent>") {
			t.Errorf("run(%q) did not print the help text; got:\n%s", arg, out)
		}
	}
}

// An unknown command is reported with exit 1, without asking for a terminal and
// without touching the installed guard binaries.
func TestRunUnknownCommand(t *testing.T) {
	orig := installGoBinaries
	t.Cleanup(func() { installGoBinaries = orig })
	installGoBinaries = func() []string { t.Fatal("an unknown command must not refresh the guard binaries"); return nil }

	var code int
	out := captureStdout(t, func() { code = run([]string{"not-a-command"}) })
	if code != 1 {
		t.Errorf("run(unknown) = %d, want 1", code)
	}
	if !strings.Contains(out, "Unknown command: not-a-command") {
		t.Errorf("expected the unknown command to be named, got:\n%s", out)
	}
	if !strings.Contains(out, "solongate --help") {
		t.Errorf("expected a pointer to --help, got:\n%s", out)
	}
}

// Every human-only subcommand must refuse a caller with no terminal, including
// when --json is passed, which only relaxes the stdout check. The refusal comes
// before the command starts, so nothing is changed on the machine.
func TestCLISubcommandsAreHumanOnly(t *testing.T) {
	if raw, ok := os.LookupEnv("SG_TEST_SUBCOMMAND_ARGS"); ok {
		os.Exit(run(strings.Fields(raw)))
	}

	for sub := range cliSubcommands {
		for _, args := range []string{sub, sub + " --json"} {
			t.Run(args, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestCLISubcommandsAreHumanOnly$")
				cmd.Env = append(os.Environ(), "SG_TEST_SUBCOMMAND_ARGS="+args, "HOME="+t.TempDir())
				var stderr bytes.Buffer
				cmd.Stdin = strings.NewReader("")
				cmd.Stdout = io.Discard
				cmd.Stderr = &stderr

				err := cmd.Run()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 {
					t.Fatalf("`solongate %s` ran without a terminal (err=%v); stderr:\n%s", args, err, stderr.String())
				}
				if !strings.Contains(stderr.String(), "SolonGate is human-only") {
					t.Errorf("refused without saying why; stderr:\n%s", stderr.String())
				}
			})
		}
	}
}

// The gated set and the command table must agree: a gated name with no command
// would be refused and then reported unknown, and run/sandbox must stay open to
// scripts, so they must not be in the human-only set.
func TestSubcommandTablesAreConsistent(t *testing.T) {
	for sub := range cliSubcommands {
		if _, ok := lookup(sub); !ok {
			t.Errorf("%q is human-only but has no entry in the command table", sub)
		}
	}
	for sub := range guardRunnerSubcommands {
		if cliSubcommands[sub] {
			t.Errorf("%q is a guard runner and must stay callable without a terminal", sub)
		}
		if _, ok := lookup(sub); !ok {
			t.Errorf("%q is a guard runner but has no entry in the command table", sub)
		}
	}
}
