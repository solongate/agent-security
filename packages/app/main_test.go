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

// printHelp's sandbox line must match confine.parseSandboxArgs's real
// contract (an id before the agent), not the "run"-style "-- <agent>" form.
func TestPrintHelpDocumentsRealSandboxSyntax(t *testing.T) {
	out := captureStdout(t, printHelp)
	if strings.Contains(out, "sandbox -- <agent>") {
		t.Error("help text still documents \"sandbox -- <agent>\", which sandbox does not accept")
	}
	if !strings.Contains(out, "sandbox <id> <agent>") {
		t.Error("help text should document \"sandbox <id> <agent>\"")
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
