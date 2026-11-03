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
