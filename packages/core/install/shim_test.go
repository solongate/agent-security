// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func wrappedShimBlock(body string) string {
	return shimBegin + "\n" + body + "\n" + shimEnd
}

func TestWriteShimBlockInsertsAndIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "nested", ".bashrc")

	if err := writeShimBlock(file, wrappedShimBlock("claude() { echo v1; }")); err != nil {
		t.Fatalf("writeShimBlock() error: %v", err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(b), shimBegin) != 1 {
		t.Fatalf("expected exactly one shim block, got: %s", b)
	}

	if err := writeShimBlock(file, wrappedShimBlock("claude() { echo v2; }")); err != nil {
		t.Fatalf("writeShimBlock() second write error: %v", err)
	}
	b, err = os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(b), shimBegin) != 1 {
		t.Errorf("writeShimBlock() left more than one block: %s", b)
	}
	if !strings.Contains(string(b), "v2") || strings.Contains(string(b), "v1") {
		t.Errorf("writeShimBlock() did not replace the old block content: %s", b)
	}
}

func TestWriteShimBlockPreservesSurroundingContent(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, ".bashrc")
	if err := os.WriteFile(file, []byte("export PATH=$PATH:/custom\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeShimBlock(file, wrappedShimBlock("claude() { echo hi; }")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "export PATH=$PATH:/custom") {
		t.Errorf("writeShimBlock() dropped pre-existing content: %s", b)
	}
	if idx := strings.Index(string(b), shimBegin); idx < strings.Index(string(b), "export PATH") {
		t.Errorf("shim block should come after the pre-existing content: %s", b)
	}
}

func TestWriteShimBlockRemovesBlockWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, ".bashrc")
	if err := os.WriteFile(file, []byte("keep me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeShimBlock(file, wrappedShimBlock("claude() { echo hi; }")); err != nil {
		t.Fatal(err)
	}
	if err := writeShimBlock(file, ""); err != nil {
		t.Fatalf("writeShimBlock(empty) error: %v", err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), shimBegin) {
		t.Errorf("writeShimBlock(empty) did not remove the block: %s", b)
	}
	if !strings.Contains(string(b), "keep me") {
		t.Errorf("writeShimBlock(empty) dropped unrelated content: %s", b)
	}
}

func TestShimTargetsOnlyReturnsExistingFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shimTargets() takes a PowerShell-specific path on windows")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	if got := shimTargets(); len(got) != 0 {
		t.Errorf("shimTargets() = %v, want none with no rc files present", got)
	}

	zshrc := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(zshrc, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	got := shimTargets()
	if len(got) != 1 || got[0] != zshrc {
		t.Errorf("shimTargets() = %v, want only %q", got, zshrc)
	}

	bashrc := filepath.Join(home, ".bashrc")
	profile := filepath.Join(home, ".profile")
	for _, f := range []string{bashrc, profile} {
		if err := os.WriteFile(f, []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got = shimTargets()
	want := []string{bashrc, zshrc, profile}
	if len(got) != len(want) {
		t.Fatalf("shimTargets() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("shimTargets()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRemoveClaudeShimClearsAllTargets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shimTargets() takes a PowerShell-specific path on windows")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	bashrc := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(bashrc, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeShimBlock(bashrc, "claude() { echo hi; }"); err != nil {
		t.Fatal(err)
	}

	RemoveClaudeShim()

	b, err := os.ReadFile(bashrc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), shimBegin) {
		t.Errorf("RemoveClaudeShim() left a shim block behind: %s", b)
	}
}

func TestInstallClaudeShimWritesIntoFoundTargets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("InstallClaudeShim() resolves PowerShell profiles on windows")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	bashrc := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(bashrc, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	binDir := t.TempDir()
	fakeClaude := filepath.Join(binDir, "claude")
	if err := os.WriteFile(fakeClaude, []byte("#!/bin/sh\necho fake claude\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+"/usr/bin"+string(os.PathListSeparator)+"/bin")

	p := GlobalPaths()
	if !InstallClaudeShim(p) {
		t.Fatal("InstallClaudeShim() = false, want true with a resolvable claude binary and an existing rc file")
	}
	b, err := os.ReadFile(bashrc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), fakeClaude) {
		t.Errorf("installed shim does not reference the resolved claude binary %q: %s", fakeClaude, b)
	}
	if !strings.Contains(string(b), "shield") {
		t.Errorf("installed shim does not invoke the guard's shield subcommand: %s", b)
	}
}

func TestInstallClaudeShimWithoutClaudeOnPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("InstallClaudeShim() resolves PowerShell profiles on windows")
	}
	realWhich, err := exec.LookPath("which")
	if err != nil {
		t.Skip("no \"which\" binary available to copy into an isolated PATH")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	// An rc file exists, so the only reason InstallClaudeShim() can fail here
	// is that claude itself cannot be resolved.
	if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	// A bare /usr/bin would also contain this machine's own claude binary,
	// so give the subprocess a PATH holding only a copy of "which".
	isolated := t.TempDir()
	data, err := os.ReadFile(realWhich)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(isolated, "which"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", isolated)

	p := GlobalPaths()
	if InstallClaudeShim(p) {
		t.Error("InstallClaudeShim() = true, want false when claude is not on PATH")
	}
}

func TestResolveRealClaudeFindsExecutableOnPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("resolveRealClaude() uses \"where\" on windows")
	}
	binDir := t.TempDir()
	fakeClaude := filepath.Join(binDir, "claude")
	if err := os.WriteFile(fakeClaude, []byte("#!/bin/sh\necho fake claude\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+"/usr/bin"+string(os.PathListSeparator)+"/bin")

	got := resolveRealClaude()
	if got != fakeClaude {
		t.Errorf("resolveRealClaude() = %q, want %q", got, fakeClaude)
	}
}

func TestResolveRealClaudeReturnsEmptyWhenMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("resolveRealClaude() uses \"where\" on windows")
	}
	realWhich, err := exec.LookPath("which")
	if err != nil {
		t.Skip("no \"which\" binary available to copy into an isolated PATH")
	}

	// A bare /usr/bin would also contain this machine's own claude binary,
	// so give the subprocess a PATH holding only a copy of "which".
	isolated := t.TempDir()
	data, err := os.ReadFile(realWhich)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(isolated, "which"), data, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", isolated)

	if got := resolveRealClaude(); got != "" {
		t.Errorf("resolveRealClaude() = %q, want empty with no claude binary on PATH", got)
	}
}

func TestWindowsPowerShellFallsBackWhenMissing(t *testing.T) {
	t.Setenv("SystemRoot", filepath.Join(t.TempDir(), "does-not-exist"))
	if got := windowsPowerShell(); got != "powershell" {
		t.Errorf("windowsPowerShell() = %q, want the bare \"powershell\" fallback", got)
	}
}

func TestWindowsPowerShellResolvesFixedLocationWhenPresent(t *testing.T) {
	// windowsPowerShell() always joins with a literal backslash, so on a
	// non-windows filesystem the "nested" path is really one file whose name
	// contains backslash characters, not a directory tree.
	base := t.TempDir()
	root := filepath.Join(base, "winroot")
	literalName := `winroot\System32\WindowsPowerShell\v1.0\powershell.exe`
	if err := os.WriteFile(filepath.Join(base, literalName), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SystemRoot", root)

	want := root + `\System32\WindowsPowerShell\v1.0\powershell.exe`
	if got := windowsPowerShell(); got != want {
		t.Errorf("windowsPowerShell() = %q, want %q", got, want)
	}
}