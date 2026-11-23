// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build darwin

package sandbox

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinLaunchRequiresArgv(t *testing.T) {
	_, err := Launch(Plan{}, nil, nil)
	if err == nil {
		t.Fatal("expected an error when there is nothing to run")
	}
}

func TestDarwinDescribeReportsSeatbelt(t *testing.T) {
	mech, _ := Describe()
	if mech != "Seatbelt" {
		t.Errorf("Describe() mechanism = %q, want Seatbelt", mech)
	}
}

func TestDarwinPreviewDenyList(t *testing.T) {
	if got := Preview(Plan{}); got != nil {
		t.Errorf("Preview with an empty deny list = %v, want nil (everything resolved)", got)
	}
	got := Preview(Plan{Deny: []string{"/this/path/does/not/exist"}})
	if len(got) == 0 {
		t.Error("expected a note about an unresolved deny path")
	}
}

func TestDarwinPreviewWorkspaceReportsMissingPaths(t *testing.T) {
	ws := t.TempDir()
	read := t.TempDir()
	missing := filepath.Join(ws, "does-not-exist")
	got := Preview(Plan{Workspace: ws, RuntimeRead: []string{read, missing}})
	if len(got) == 0 {
		t.Fatal("expected a note about the missing RuntimeRead path")
	}
	if !strings.Contains(got[0], missing) {
		t.Errorf("note %q does not name the missing path %q", got[0], missing)
	}
}

func TestDarwinPreviewWorkspaceIgnoresDenyList(t *testing.T) {
	ws := t.TempDir()
	if got := Preview(Plan{Workspace: ws, Deny: []string{"/this/path/does/not/exist"}}); got != nil {
		t.Errorf("Preview in workspace mode = %v, want nil (the deny list is not consulted when workspace-confined)", got)
	}
}

func TestDarwinPreviewWorkspaceOkWhenEverythingExists(t *testing.T) {
	ws := t.TempDir()
	read := t.TempDir()
	write := t.TempDir()
	if got := Preview(Plan{Workspace: ws, RuntimeRead: []string{read}, RuntimeWrite: []string{write}}); got != nil {
		t.Errorf("Preview with all paths present = %v, want nil", got)
	}
}

func TestDarwinPreviewWorkspaceReportsProfileError(t *testing.T) {
	got := Preview(Plan{Workspace: "relative/path"})
	if len(got) == 0 {
		t.Error("expected a note when the workspace profile cannot be built")
	}
}
