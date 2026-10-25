// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRing(t *testing.T, project, contents string) {
	t.Helper()
	dir := filepath.Join(Dir(), "projects", project)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".eval-ring.jsonl"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNewestEvalRecordNoProjectsDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if got := NewestEvalRecord(); got != nil {
		t.Errorf("NewestEvalRecord() = %+v, want nil", got)
	}
}

func TestNewestEvalRecordPicksHighestTimestampAcrossProjects(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	writeRing(t, "proj-a", `{"ts":100,"tool":"old"}`+"\n"+`not json`+"\n"+`{"ts":0,"tool":"zero"}`+"\n")
	writeRing(t, "proj-b", `{"ts":500,"tool":"newest","client":"cli","session":"s1"}`+"\n")

	got := NewestEvalRecord()
	if got == nil {
		t.Fatal("expected a record, got nil")
	}
	if got.Ts != 500 || got.Tool != "newest" || got.Client != "cli" || got.Session != "s1" {
		t.Errorf("NewestEvalRecord() = %+v, want the ts=500 record", got)
	}
}

func TestNewestEvalRecordIgnoresFilesInsteadOfDirs(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := filepath.Join(Dir(), "projects")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "stray-file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRing(t, "proj", `{"ts":42}`+"\n")

	got := NewestEvalRecord()
	if got == nil || got.Ts != 42 {
		t.Errorf("NewestEvalRecord() = %+v, want ts=42", got)
	}
}

func TestEvalRecordAt(t *testing.T) {
	r := &EvalRecord{Ts: 1700000000000}
	if got := r.At(); got.UnixMilli() != 1700000000000 {
		t.Errorf("At().UnixMilli() = %d, want 1700000000000", got.UnixMilli())
	}
}

func TestTailRingLinesMissingFile(t *testing.T) {
	if got := tailRingLines(filepath.Join(t.TempDir(), "missing.jsonl")); got != nil {
		t.Errorf("tailRingLines(missing) = %v, want nil", got)
	}
}

func TestTailRingLinesSmallFileReturnsAllNonEmptyLines(t *testing.T) {
	file := filepath.Join(t.TempDir(), "ring.jsonl")
	content := "line1\n\nline2\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got := tailRingLines(file)
	want := []string{"line1", "line2"}
	if len(got) != len(want) {
		t.Fatalf("tailRingLines() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestTailRingLinesDropsPartialFirstLineWhenTruncated(t *testing.T) {
	file := filepath.Join(t.TempDir(), "ring.jsonl")
	var b strings.Builder
	for i := 0; i < 2000; i++ {
		b.WriteString(`{"ts":1}`)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(file, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	got := tailRingLines(file)
	if len(got) == 0 {
		t.Fatal("expected some lines back")
	}
	for _, l := range got {
		if l != `{"ts":1}` {
			t.Errorf("got a mangled line: %q", l)
		}
	}

	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() <= 8192 {
		t.Fatalf("test fixture too small to exercise truncation: %d bytes", info.Size())
	}
}