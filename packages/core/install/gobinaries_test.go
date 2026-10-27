// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGoBinaryNamesOnThisPlatform(t *testing.T) {
	names := goBinaryNames()
	if runtime.GOOS == "windows" {
		if len(names) != 2 || names[0] != "solongate-guard.exe" || names[1] != "solongate.exe" {
			t.Errorf("goBinaryNames() = %v, want the .exe names on windows", names)
		}
		return
	}
	if len(names) != 2 || names[0] != "solongate-guard" || names[1] != "solongate" {
		t.Errorf("goBinaryNames() = %v, want [solongate-guard solongate]", names)
	}
}

func TestBinDirUnderSGDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got := BinDir()
	want := filepath.Join(GlobalPaths().SGDir, "bin")
	if got != want {
		t.Errorf("BinDir() = %q, want %q", got, want)
	}
}

func TestSelfBinDirReturnsExecutableDirectory(t *testing.T) {
	dir, ok := selfBinDir()
	if !ok {
		t.Fatal("selfBinDir() ok = false, want true inside a test binary")
	}
	if dir == "" {
		t.Error("selfBinDir() returned an empty directory")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	if want := filepath.Dir(self); dir != want {
		t.Errorf("selfBinDir() = %q, want %q", dir, want)
	}
}

func TestSameFile(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if sameFile(a, b) {
		t.Error("sameFile() = true for two distinct files with identical content")
	}
	if !sameFile(a, a) {
		t.Error("sameFile() = false comparing a file against itself")
	}
	if sameFile(a, filepath.Join(dir, "missing")) {
		t.Error("sameFile() = true when one side does not exist")
	}

	link := filepath.Join(dir, "link")
	if err := os.Link(a, link); err != nil {
		t.Skipf("hard links unsupported here: %v", err)
	}
	if !sameFile(a, link) {
		t.Error("sameFile() = false for a hard link to the same inode")
	}
}

func TestCopyExecutable(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "src")
	to := filepath.Join(dir, "dst")
	if err := os.WriteFile(from, []byte("binary content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyExecutable(from, to); err != nil {
		t.Fatalf("copyExecutable() error: %v", err)
	}
	got, err := os.ReadFile(to)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "binary content" {
		t.Errorf("copied content = %q, want %q", got, "binary content")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(to)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("copied file mode = %v, want 0700", info.Mode().Perm())
		}
	}
	if _, err := os.Stat(to + ".new"); !os.IsNotExist(err) {
		t.Errorf("leftover temp file %s.new was not cleaned up", to)
	}
}

func TestCopyExecutableMissingSource(t *testing.T) {
	dir := t.TempDir()
	if err := copyExecutable(filepath.Join(dir, "missing"), filepath.Join(dir, "dst")); err == nil {
		t.Error("copyExecutable() with a missing source should return an error")
	}
}

func TestCopyFromCopiesKnownBinariesAndSkipsOthers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	src := t.TempDir()
	for _, name := range goBinaryNames() {
		if err := os.WriteFile(filepath.Join(src, name), []byte("fake "+name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(src, "unrelated-file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(src, goBinaryNames()[0]+"-dir"), 0o755); err != nil {
		t.Fatal(err)
	}

	placed := copyFrom(src)
	if len(placed) != len(goBinaryNames()) {
		t.Fatalf("copyFrom() placed %v, want exactly %v", placed, goBinaryNames())
	}
	for _, name := range goBinaryNames() {
		dst := filepath.Join(BinDir(), name)
		b, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("reading copied binary %q: %v", name, err)
		}
		if string(b) != "fake "+name {
			t.Errorf("copied binary %q content = %q, want %q", name, b, "fake "+name)
		}
	}
	if Exists(filepath.Join(BinDir(), "unrelated-file")) {
		t.Error("copyFrom() copied a file that is not in goBinaryNames()")
	}
}

func TestCopyFromSkipsAlreadyIdenticalBinary(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	src := t.TempDir()
	name := goBinaryNames()[0]
	from := filepath.Join(src, name)
	if err := os.WriteFile(from, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}

	if placed := copyFrom(src); len(placed) == 0 {
		t.Fatal("first copyFrom() placed nothing")
	}

	to := filepath.Join(BinDir(), name)
	if err := os.Remove(to); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(from, to); err != nil {
		t.Skipf("hard links unsupported here: %v", err)
	}

	placed := copyFrom(src)
	found := false
	for _, p := range placed {
		if p == name {
			found = true
		}
	}
	if !found {
		t.Errorf("copyFrom() with a same-inode destination should still report %q as placed, got %v", name, placed)
	}
	if !sameFile(from, to) {
		t.Error("copyFrom() replaced a same-inode destination instead of skipping the copy")
	}
}

func TestInstallGoBinariesCreatesBinDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	InstallGoBinaries()
	info, err := os.Stat(BinDir())
	if err != nil {
		t.Fatalf("BinDir() was not created by InstallGoBinaries(): %v", err)
	}
	if !info.IsDir() {
		t.Error("BinDir() exists but is not a directory")
	}
}