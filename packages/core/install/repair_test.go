// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReportLine(t *testing.T) {
	r := reportLine("thing", true, "fine", "broken")
	if !r.OK || r.Label != "thing" || r.Detail != "fine" {
		t.Errorf("reportLine(true) = %+v, want OK detail %q", r, "fine")
	}
	r = reportLine("thing", false, "fine", "broken")
	if r.OK || r.Detail != "broken" {
		t.Errorf("reportLine(false) = %+v, want not-OK detail %q", r, "broken")
	}
}

func TestRepairWithoutAGuardBinaryReturnsBeforeOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("SOLONGATE_NO_OS_LOCK", "1")

	rep := Repair()
	if rep.OK {
		t.Fatalf("Repair() = %+v, want OK=false with no guard binary available", rep)
	}
	if len(rep.Before) == 0 {
		t.Error("Repair() has an empty Before report")
	}
	if len(rep.After) != 0 {
		t.Error("Repair() should not produce an After report when Install() fails")
	}

	if len(rep.Before) == 0 || rep.Before[0].Label != "guard binary" {
		t.Fatalf("Repair().Before[0] = %+v, want the \"guard binary\" presence line first", rep.Before)
	}
	if rep.Before[0].OK {
		t.Error("Before[0].OK = true, want false: no binary exists")
	}
	if rep.Before[0].Detail != "MISSING" {
		t.Errorf("Before[0].Detail = %q, want MISSING", rep.Before[0].Detail)
	}
}

func TestSweepStrayScratchDirsRemovesAStrayDirFullOfScratchFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	stray := filepath.Join(home, "projects", "myapp", ".solongate")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
	}
	for name := range scratchFiles {
		if err := os.WriteFile(filepath.Join(stray, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	n := SweepStrayScratchDirs(home)
	if n != 1 {
		t.Fatalf("SweepStrayScratchDirs() removed %d, want 1", n)
	}
	if Exists(stray) {
		t.Error("the stray .solongate directory still exists after sweeping")
	}
}

func TestSweepScratchLeavesDirsWithUnknownFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	stray := filepath.Join(home, "projects", "myapp", ".solongate")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stray, ".last-eval"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stray, "config.json"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	n := sweepScratch(home, scratchMaxDepth, scratchBudget)
	if n != 0 {
		t.Errorf("sweepScratch() removed %d, want 0 because an unrecognized file remains", n)
	}
	if !Exists(stray) {
		t.Error("the .solongate directory was removed even though it had an unrecognized file")
	}
	if !Exists(filepath.Join(stray, "config.json")) {
		t.Error("the unrecognized file itself was removed")
	}
}

func TestSweepScratchNeverTouchesTheRealSGDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	store := filepath.Join(home, ".solongate")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	for name := range scratchFiles {
		if err := os.WriteFile(filepath.Join(store, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	n := SweepStrayScratchDirs(home)
	if n != 0 {
		t.Errorf("SweepStrayScratchDirs() removed %d, want 0: the real SGDir must never be swept", n)
	}
	if !Exists(store) {
		t.Error("the real .solongate directory was removed")
	}
}

func TestSweepScratchSkipsListedDirectories(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	for _, skip := range []string{"node_modules", ".git", "dist", ".next", "build"} {
		stray := filepath.Join(home, skip, ".solongate")
		if err := os.MkdirAll(stray, 0o755); err != nil {
			t.Fatal(err)
		}
		for name := range scratchFiles {
			if err := os.WriteFile(filepath.Join(stray, name), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	n := SweepStrayScratchDirs(home)
	if n != 0 {
		t.Errorf("SweepStrayScratchDirs() removed %d, want 0: everything is under a skipped directory", n)
	}
}

func TestSweepScratchRespectsMaxDepth(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	nested := filepath.Join(home, "sub", ".solongate")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	for name := range scratchFiles {
		if err := os.WriteFile(filepath.Join(nested, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if n := sweepScratch(home, 0, scratchBudget); n != 0 {
		t.Errorf("sweepScratch(maxDepth=0) removed %d, want 0: the stray dir is one level too deep", n)
	}
	if n := sweepScratch(home, 1, scratchBudget); n != 1 {
		t.Errorf("sweepScratch(maxDepth=1) removed %d, want 1", n)
	}
}

func TestSweepScratchRespectsBudget(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	strayNested := filepath.Join(home, "sub", ".solongate")
	if err := os.MkdirAll(strayNested, 0o755); err != nil {
		t.Fatal(err)
	}
	for name := range scratchFiles {
		if err := os.WriteFile(filepath.Join(strayNested, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if n := sweepScratch(home, scratchMaxDepth, 0); n != 0 {
		t.Errorf("sweepScratch(budget=0) removed %d, want 0: nested dirs are cut off by the budget", n)
	}
}

func TestSweepOne(t *testing.T) {
	dir := t.TempDir()
	stray := filepath.Join(dir, ".solongate")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatal(err)
	}
	for name := range scratchFiles {
		if err := os.WriteFile(filepath.Join(stray, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !sweepOne(stray) {
		t.Error("sweepOne() = false for a directory containing only recognized scratch files")
	}
	if Exists(stray) {
		t.Error("sweepOne() did not remove the directory")
	}

	stray2 := filepath.Join(dir, ".solongate2")
	if err := os.MkdirAll(stray2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stray2, "keep.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if sweepOne(stray2) {
		t.Error("sweepOne() = true for a directory containing an unrecognized file")
	}
	if !Exists(stray2) {
		t.Error("sweepOne() removed a directory it should have left alone")
	}

	if sweepOne(filepath.Join(dir, "does-not-exist")) {
		t.Error("sweepOne() = true for a directory that cannot be read")
	}
}