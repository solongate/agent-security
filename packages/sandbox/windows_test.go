// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build windows

package sandbox

import (
	"os"
	"os/exec"
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

// icacls is the one point every deny and cleanup ACL call goes through, so its
// error format is locked in here rather than only through Launch.
func TestWindowsIcaclsWrapsFailureAndReturnsNilOnSuccess(t *testing.T) {
	missing := t.TempDir() + `\sg-definitely-missing`
	cmd := exec.Command(systemBinary("icacls"), missing, "/deny", `*S-1-1-0:(F)`)
	captured, commandErr := cmd.CombinedOutput()
	if commandErr == nil {
		t.Fatalf("icacls on a missing path succeeded, want a failure (output %q)", captured)
	}
	wantOutput := strings.TrimSpace(string(captured))
	if wantOutput == "" {
		t.Fatal("icacls on a missing path produced no diagnostic output")
	}

	err := icacls(missing, "/deny", `*S-1-1-0:(F)`)
	if err == nil {
		t.Fatal("icacls on a missing path returned nil, want an error")
	}
	if !strings.HasPrefix(err.Error(), "icacls: ") || !strings.Contains(err.Error(), wantOutput) {
		t.Errorf("icacls error = %q, want prefix %q and captured command output %q", err.Error(), "icacls: ", wantOutput)
	}

	if err := icacls(t.TempDir()); err != nil {
		t.Errorf("icacls on an existing directory = %v, want nil", err)
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
