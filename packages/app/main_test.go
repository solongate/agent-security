// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"io"
	"os"
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