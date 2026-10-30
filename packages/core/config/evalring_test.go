// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package config

import (
	"fmt"
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

// Issue #225: the window used to drop its first line unconditionally, so a
// window opening exactly after a newline, or on one, lost a complete entry.
func TestTailRingLinesKeepsACompleteFirstLineOnABoundary(t *testing.T) {
	entry := func(i int) string { return fmt.Sprintf(`{"ts":%08d}`, i) }
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		b.WriteString(entry(i)) // 16 bytes with the newline, a divisor of 8192
		b.WriteByte('\n')
	}
	entries := b.String()

	cases := []struct {
		name, last string
		wantFirst  string
		wantLen    int
	}{
		// 16000 bytes: the window opens on the first byte of entry 488.
		{"right after a newline", "", entry(488), 512},
		// A 15-byte final line moves the window onto entry 488's newline,
		// so entry 489 is the first complete line.
		{"on a newline", `{"ts":9999999}` + "\n", entry(489), 512},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "ring.jsonl")
			if err := os.WriteFile(file, []byte(entries+c.last), 0o600); err != nil {
				t.Fatal(err)
			}
			got := tailRingLines(file)
			if len(got) != c.wantLen {
				t.Fatalf("tailRingLines() returned %d lines, want %d", len(got), c.wantLen)
			}
			if got[0] != c.wantFirst {
				t.Errorf("first line = %q, want %q", got[0], c.wantFirst)
			}
		})
	}
}