// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckHookRuntimeLauncherMissing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	rt := CheckHookRuntime()
	if rt.OK {
		t.Error("CheckHookRuntime().OK = true with no launcher installed")
	}
	if !strings.Contains(rt.Detail, "repair") {
		t.Errorf("CheckHookRuntime().Detail = %q, want a hint to run repair", rt.Detail)
	}
}

func TestCheckHookRuntimeLauncherReportsBinary(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	hooksDir := GlobalPaths().HooksDir
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(hooksDir, LauncherName)
	script := "#!/bin/sh\necho /path/to/guard\nexit 0\n"
	if err := os.WriteFile(launcher, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	rt := CheckHookRuntime()
	if !rt.OK {
		t.Fatalf("CheckHookRuntime().OK = false, want true; Detail=%q", rt.Detail)
	}
	if rt.Detail != "/path/to/guard" {
		t.Errorf("CheckHookRuntime().Detail = %q, want %q", rt.Detail, "/path/to/guard")
	}
}

func TestCheckHookRuntimeLauncherFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	hooksDir := GlobalPaths().HooksDir
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(hooksDir, LauncherName)
	script := "#!/bin/sh\nexit 1\n"
	if err := os.WriteFile(launcher, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	rt := CheckHookRuntime()
	if rt.OK {
		t.Error("CheckHookRuntime().OK = true even though the launcher exited non-zero")
	}
	if !strings.Contains(rt.Detail, "no guard binary") {
		t.Errorf("CheckHookRuntime().Detail = %q, want it to mention no guard binary", rt.Detail)
	}
}

func TestCheckHookRuntimeLauncherEmptyOutput(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	hooksDir := GlobalPaths().HooksDir
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(hooksDir, LauncherName)
	script := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(launcher, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	rt := CheckHookRuntime()
	if rt.OK {
		t.Error("CheckHookRuntime().OK = true with empty launcher output")
	}
}

func TestBeatsSortedNewestFirst(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	beatDir := filepath.Join(GlobalPaths().SGDir, BeatDirName)
	if err := os.MkdirAll(beatDir, 0o755); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	write := func(hook, status string, at time.Time) {
		f := filepath.Join(beatDir, hook)
		if err := os.WriteFile(f, []byte(status), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(f, at, at); err != nil {
			t.Fatal(err)
		}
	}
	write(guardKind, "ok", now.Add(-time.Minute))
	write(auditKind, "no-binary", now)

	beats := Beats()
	if len(beats) != 2 {
		t.Fatalf("Beats() = %d entries, want 2", len(beats))
	}
	if beats[0].Hook != auditKind {
		t.Errorf("Beats()[0].Hook = %q, want the most recent (%q)", beats[0].Hook, auditKind)
	}
	if beats[1].Hook != guardKind {
		t.Errorf("Beats()[1].Hook = %q, want %q", beats[1].Hook, guardKind)
	}
	if beats[1].Status != "ok" {
		t.Errorf("Beats()[1].Status = %q, want %q", beats[1].Status, "ok")
	}
}

func TestBeatsEmptyWhenNoBeatDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if beats := Beats(); len(beats) != 0 {
		t.Errorf("Beats() = %v, want empty with no beat directory", beats)
	}
}

func TestGuardBeat(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if GuardBeat() != nil {
		t.Error("GuardBeat() != nil with no beats recorded")
	}

	beatDir := filepath.Join(GlobalPaths().SGDir, BeatDirName)
	if err := os.MkdirAll(beatDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(beatDir, auditKind), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if GuardBeat() != nil {
		t.Error("GuardBeat() != nil when only an audit beat exists")
	}

	if err := os.WriteFile(filepath.Join(beatDir, guardKind), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	beat := GuardBeat()
	if beat == nil || beat.Hook != guardKind {
		t.Errorf("GuardBeat() = %+v, want the guard beat", beat)
	}
}

func TestAgo(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		at   time.Time
		want string
	}{
		{"just now", now, "just now"},
		{"a few seconds", now.Add(-2 * time.Second), "just now"},
		{"future clock skew", now.Add(5 * time.Second), "just now"},
		{"seconds ago", now.Add(-30 * time.Second), "30s ago"},
		{"minutes ago", now.Add(-2 * time.Minute), "2m ago"},
		{"hours ago", now.Add(-3 * time.Hour), "3h ago"},
		{"days ago", now.Add(-48 * time.Hour), "2d ago"},
	}
	for _, tc := range cases {
		if got := Ago(tc.at); got != tc.want {
			t.Errorf("%s: Ago() = %q, want %q", tc.name, got, tc.want)
		}
	}
}