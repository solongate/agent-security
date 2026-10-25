// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build windows

package sandbox

import (
	"os"
	"strings"
	"testing"
)

func TestWindowsLaunchRefusesWorkspaceConfinement(t *testing.T) {
	_, err := Launch(Plan{Workspace: `C:\work`}, []string{"cmd"}, nil)
	if err == nil {
		t.Fatal("expected workspace confinement to be refused on Windows")
	}
}

func TestWindowsLaunchRequiresArgv(t *testing.T) {
	_, err := Launch(Plan{}, nil, nil)
	if err == nil {
		t.Fatal("expected an error when there is nothing to run")
	}
}

func TestWindowsPreviewDenyList(t *testing.T) {
	if got := Preview(Plan{}); got != nil {
		t.Errorf("Preview with no deny list = %v, want nil", got)
	}
	if got := Preview(Plan{Deny: []string{`C:\secret`}}); len(got) == 0 {
		t.Error("expected a note about the temporary nature of the deny ACEs")
	}
}

func TestWindowsDescribeReportsIcacls(t *testing.T) {
	mech, _ := Describe()
	if mech != "icacls deny (per run)" {
		t.Errorf("Describe() mechanism = %q, want icacls deny (per run)", mech)
	}
}

func TestSystemBinaryFallsBackToBareNameWhenMissing(t *testing.T) {
	t.Setenv("SystemRoot", `C:\sg-definitely-not-a-real-root`)
	got := systemBinary("icacls")
	if got != "icacls" {
		t.Errorf("systemBinary() = %q, want the bare name when SystemRoot does not resolve", got)
	}
}

func TestSystemBinaryResolvesUnderSystemRoot(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		t.Skip("no SystemRoot set on this machine")
	}
	got := systemBinary("icacls")
	if !strings.HasPrefix(got, root) {
		t.Logf("systemBinary() = %q (System32/icacls.exe not present, bare-name fallback used)", got)
	}
}
