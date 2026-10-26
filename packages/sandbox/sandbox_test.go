// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPlanConfinedAndAllowlist(t *testing.T) {
	cases := []struct {
		name        string
		plan        Plan
		confined    bool
		allowlisted bool
	}{
		{"empty plan", Plan{}, false, false},
		{"deny only", Plan{Deny: []string{"/etc/passwd"}}, true, false},
		{"workspace only", Plan{Workspace: "/tmp/ws"}, true, true},
		{"both", Plan{Workspace: "/tmp/ws", Deny: []string{"/etc/passwd"}}, true, true},
	}
	for _, tc := range cases {
		if got := tc.plan.Confined(); got != tc.confined {
			t.Errorf("%s: Confined()=%v, want %v", tc.name, got, tc.confined)
		}
		if got := tc.plan.Allowlist(); got != tc.allowlisted {
			t.Errorf("%s: Allowlist()=%v, want %v", tc.name, got, tc.allowlisted)
		}
	}
}

func TestLaunchTargetPathsEmptyName(t *testing.T) {
	if got := LaunchTargetPaths(""); got != nil {
		t.Errorf("LaunchTargetPaths(\"\")=%v, want nil", got)
	}
}

func TestLaunchTargetPathsUnknownBinary(t *testing.T) {
	if got := LaunchTargetPaths("sg-definitely-not-a-real-binary"); got != nil {
		t.Errorf("expected nil for an unresolvable binary, got %v", got)
	}
}

func TestLaunchTargetPathsKnownBinary(t *testing.T) {
	got := LaunchTargetPaths("ls")
	if len(got) == 0 {
		t.Fatal("expected at least one path for a binary that is on PATH")
	}
	for _, p := range got {
		if p == "/" {
			t.Errorf("the root should never be included: %v", got)
		}
	}
}

func TestPackageRootStripsKnownBuildDirs(t *testing.T) {
	cases := []struct {
		dir  string
		want string
	}{
		{"/opt/agent/bin", "/opt/agent"},
		{"/opt/agent/lib", "/opt/agent"},
		{"/opt/agent/dist", "/opt/agent"},
		{"/opt/agent/build", "/opt/agent"},
		{"/opt/agent", "/opt/agent"},
	}
	for _, tc := range cases {
		if got := packageRoot(tc.dir); got != tc.want {
			t.Errorf("packageRoot(%q)=%q, want %q", tc.dir, got, tc.want)
		}
	}
}

func TestPackageRootStopsAtScopedNodeModulesPackage(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "node_modules", "@scope", "pkg", "bin")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	got := packageRoot(dir)
	want := filepath.Join(root, "node_modules", "@scope", "pkg")
	if got != want {
		t.Errorf("packageRoot(%q)=%q, want %q", dir, got, want)
	}
}

func TestDefaultRuntimeReadAndDevicesAreNonEmpty(t *testing.T) {
	if len(DefaultRuntimeRead()) == 0 {
		t.Error("DefaultRuntimeRead() should list at least the base system paths")
	}
	if len(DefaultRuntimeDevices()) == 0 {
		t.Error("DefaultRuntimeDevices() should list at least the base devices")
	}
	if got := DefaultRuntimeWrite("/home/u"); got != nil {
		t.Errorf("DefaultRuntimeWrite() = %v, want nil (no default write paths)", got)
	}
}
