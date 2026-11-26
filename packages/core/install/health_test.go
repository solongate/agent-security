// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeTestGuardBinary(t *testing.T, path string, exitCode int, stdout string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		script := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" != \"--sg-version\" ]; then exit 2; fi\nprintf '%%s' %q\nexit %d\n", stdout, exitCode)
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return
	}
	srcDir := t.TempDir()
	src := filepath.Join(srcDir, "main.go")
	code := fmt.Sprintf("package main\nimport (\n\t\"fmt\"\n\t\"os\"\n)\nfunc main() {\n\tif len(os.Args) < 2 || os.Args[1] != \"--sg-version\" {\n\t\tos.Exit(2)\n\t}\n\tfmt.Print(%q)\n\tos.Exit(%d)\n}\n", stdout, exitCode)
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", path, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build fake guard binary: %v\n%s", err, out)
	}
}

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

func TestCheckGuardBinary(t *testing.T) {
	t.Run("missing binary", func(t *testing.T) {
		rt := checkGuardBinary(filepath.Join(t.TempDir(), guardBinaryName()))
		if rt.OK {
			t.Error("checkGuardBinary().OK = true for missing binary")
		}
		if !strings.Contains(rt.Detail, "missing") || !strings.Contains(rt.Detail, "repair") {
			t.Errorf("checkGuardBinary().Detail = %q, want missing + repair hint", rt.Detail)
		}
	})

	t.Run("truncated binary", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), guardBinaryName())
		if err := os.WriteFile(bin, nil, 0o755); err != nil {
			t.Fatal(err)
		}
		rt := checkGuardBinary(bin)
		if rt.OK {
			t.Error("checkGuardBinary().OK = true for truncated binary")
		}
		if !strings.Contains(rt.Detail, "self-check") || !strings.Contains(rt.Detail, "repair") {
			t.Errorf("checkGuardBinary().Detail = %q, want self-check + repair hint", rt.Detail)
		}
	})

	t.Run("corrupt binary", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), guardBinaryName())
		if err := os.WriteFile(bin, []byte("not-a-valid-executable"), 0o755); err != nil {
			t.Fatal(err)
		}
		rt := checkGuardBinary(bin)
		if rt.OK {
			t.Error("checkGuardBinary().OK = true for corrupt binary")
		}
		if !strings.Contains(rt.Detail, "self-check") || !strings.Contains(rt.Detail, "repair") {
			t.Errorf("checkGuardBinary().Detail = %q, want self-check + repair hint", rt.Detail)
		}
	})

	t.Run("non-zero exit", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), guardBinaryName())
		writeTestGuardBinary(t, bin, 1, "113\n")
		rt := checkGuardBinary(bin)
		if rt.OK {
			t.Error("checkGuardBinary().OK = true when binary exits non-zero")
		}
		if !strings.Contains(rt.Detail, "repair") {
			t.Errorf("checkGuardBinary().Detail = %q, want repair hint", rt.Detail)
		}
	})

	t.Run("empty output", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), guardBinaryName())
		writeTestGuardBinary(t, bin, 0, "")
		rt := checkGuardBinary(bin)
		if rt.OK {
			t.Error("checkGuardBinary().OK = true when binary prints empty output")
		}
	})

	t.Run("non-version output", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), guardBinaryName())
		writeTestGuardBinary(t, bin, 0, "unexpected\n")
		rt := checkGuardBinary(bin)
		if rt.OK {
			t.Error("checkGuardBinary().OK = true when binary prints non-version output")
		}
	})

	t.Run("healthy binary", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), guardBinaryName())
		writeTestGuardBinary(t, bin, 0, "113\n")
		rt := checkGuardBinary(bin)
		if !rt.OK {
			t.Fatalf("checkGuardBinary().OK = false, want true; Detail=%q", rt.Detail)
		}
		if rt.Detail != bin {
			t.Errorf("checkGuardBinary().Detail = %q, want %q", rt.Detail, bin)
		}
	})
}

func TestCheckHookRuntimeWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific CheckHookRuntime branch")
	}

	t.Run("missing binary", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		rt := CheckHookRuntime()
		if rt.OK {
			t.Error("CheckHookRuntime().OK = true with no guard binary installed")
		}
		if !strings.Contains(rt.Detail, "repair") {
			t.Errorf("CheckHookRuntime().Detail = %q, want repair hint", rt.Detail)
		}
	})

	t.Run("truncated binary", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		bin := GlobalPaths().GuardBinaryPath()
		if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bin, nil, 0o755); err != nil {
			t.Fatal(err)
		}

		rt := CheckHookRuntime()
		if rt.OK {
			t.Error("CheckHookRuntime().OK = true for a truncated guard binary")
		}
		if !strings.Contains(rt.Detail, "repair") {
			t.Errorf("CheckHookRuntime().Detail = %q, want repair hint", rt.Detail)
		}
	})

	t.Run("non-zero exit binary", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		bin := GlobalPaths().GuardBinaryPath()
		writeTestGuardBinary(t, bin, 1, "113\n")

		rt := CheckHookRuntime()
		if rt.OK {
			t.Error("CheckHookRuntime().OK = true even though guard binary exited non-zero")
		}
		if !strings.Contains(rt.Detail, "repair") {
			t.Errorf("CheckHookRuntime().Detail = %q, want repair hint", rt.Detail)
		}
	})

	t.Run("healthy binary", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)

		bin := GlobalPaths().GuardBinaryPath()
		writeTestGuardBinary(t, bin, 0, "113\n")

		rt := CheckHookRuntime()
		if !rt.OK {
			t.Fatalf("CheckHookRuntime().OK = false, want true; Detail=%q", rt.Detail)
		}
		if rt.Detail != bin {
			t.Errorf("CheckHookRuntime().Detail = %q, want %q", rt.Detail, bin)
		}
	})
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