// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package term

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestIsattyRegularFileIsNotATerminal(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "regular.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if isatty(f) {
		t.Error("a regular file should not be reported as a terminal")
	}
}

func TestIsattyDevNullIsACharacterDevice(t *testing.T) {
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Skip("no /dev/null on this system")
	}
	defer f.Close()

	if !isatty(f) {
		t.Error("/dev/null is a character device, isatty should report it as one")
	}
}

func TestIsattyClosedFileReturnsFalse(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "closed.txt"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	if isatty(f) {
		t.Error("Stat on a closed file errors, isatty should report false")
	}
}

func TestPrintBanner(t *testing.T) {
	out := captureStderr(t, func() { PrintBanner("test subtitle") })
	lines := strings.Split(out, "\n")

	want := len(BannerFull) + 5
	if len(lines) != want {
		t.Fatalf("PrintBanner produced %d lines, want %d: %q", len(lines), want, lines)
	}
	if lines[0] != "" {
		t.Errorf("first line = %q, want blank", lines[0])
	}
	for i, line := range BannerFull {
		want := Bold + BannerColors[i%len(BannerColors)] + line + Reset
		if lines[i+1] != want {
			t.Errorf("banner line %d = %q, want %q", i, lines[i+1], want)
		}
	}
	blankAfter := len(BannerFull) + 1
	if lines[blankAfter] != "" {
		t.Errorf("line after banner = %q, want blank", lines[blankAfter])
	}
	subtitleLine := len(BannerFull) + 2
	wantSubtitle := "  " + Dim + Italic + "test subtitle" + Reset
	if lines[subtitleLine] != wantSubtitle {
		t.Errorf("subtitle line = %q, want %q", lines[subtitleLine], wantSubtitle)
	}
}