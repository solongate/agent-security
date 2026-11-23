// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build darwin

package sandbox

import (
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

func TestDarwinPreviewDenyListNamesMissingPaths(t *testing.T) {
	present := t.TempDir()
	missing := "/this/path/does/not/exist"
	got := Preview(Plan{Deny: []string{present, missing}})
	if len(got) == 0 {
		t.Fatal("expected a note about the missing deny path")
	}
	if !strings.Contains(got[0], missing) {
		t.Errorf("note %q does not name the missing path %q", got[0], missing)
	}
	if strings.Contains(got[0], present) {
		t.Errorf("note %q names the existing path %q", got[0], present)
	}
}

func TestDarwinPreviewDenyListOkWhenAllExist(t *testing.T) {
	if got := Preview(Plan{Deny: []string{t.TempDir(), t.TempDir()}}); got != nil {
		t.Errorf("Preview with all deny paths present = %v, want nil", got)
	}
}
