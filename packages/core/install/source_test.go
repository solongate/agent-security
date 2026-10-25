// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPackageCandidates(t *testing.T) {
	got := packageCandidates(filepath.FromSlash("/a/b/c"))
	want := []string{
		filepath.FromSlash("/a/b/c/packages/hooks"),
		filepath.FromSlash("/a/b/packages/hooks"),
		filepath.FromSlash("/a/packages/hooks"),
		filepath.FromSlash("/packages/hooks"),
	}
	if len(got) != len(want) {
		t.Fatalf("packageCandidates(/a/b/c) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("packageCandidates()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestPackageCandidatesStopsAtRoot(t *testing.T) {
	got := packageCandidates(filepath.FromSlash("/"))
	want := []string{filepath.FromSlash("/packages/hooks")}
	if len(got) != len(want) || got[0] != want[0] {
		t.Errorf("packageCandidates(/) = %v, want %v", got, want)
	}
}

func TestBakeGuardBinPath(t *testing.T) {
	src := []byte(`const bin = "__SOLONGATE_GUARD_BIN__";`)
	got := string(bakeGuardBinPath(src, "/opt/solongate/bin/solongate-guard"))
	want := `const bin = "/opt/solongate/bin/solongate-guard";`
	if got != want {
		t.Errorf("bakeGuardBinPath() = %q, want %q", got, want)
	}
}

func TestBakeGuardBinPathEscapesBackslashes(t *testing.T) {
	src := []byte(`__SOLONGATE_GUARD_BIN__`)
	got := string(bakeGuardBinPath(src, `C:\sg\solongate-guard.exe`))
	want := `C:\\sg\\solongate-guard.exe`
	if got != want {
		t.Errorf("bakeGuardBinPath() = %q, want %q", got, want)
	}
}

func TestBakeGuardBinPathOnlyReplacesFirstOccurrence(t *testing.T) {
	src := []byte(`__SOLONGATE_GUARD_BIN__ __SOLONGATE_GUARD_BIN__`)
	got := string(bakeGuardBinPath(src, "x"))
	want := `x __SOLONGATE_GUARD_BIN__`
	if got != want {
		t.Errorf("bakeGuardBinPath() = %q, want %q", got, want)
	}
}

func TestHookSourceDirFindsEnvOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, opencodePluginName), []byte("plugin"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOLONGATE_HOOKS_DIR", dir)

	got, ok := hookSourceDir()
	if !ok || got != dir {
		t.Errorf("hookSourceDir() = (%q, %v), want (%q, true)", got, ok, dir)
	}
}

func TestHookSourceDirNotFoundOutsideAnyCheckout(t *testing.T) {
	t.Setenv("SOLONGATE_HOOKS_DIR", "")
	isolated := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(isolated); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	if _, ok := hookSourceDir(); ok {
		t.Error("hookSourceDir() = true, want false with no hooks source reachable from an isolated directory")
	}
}

func TestStageOpencodePluginBakesTheGuardBinPath(t *testing.T) {
	dir := t.TempDir()
	src := `module.exports = "__SOLONGATE_GUARD_BIN__";`
	if err := os.WriteFile(filepath.Join(dir, opencodePluginName), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOLONGATE_HOOKS_DIR", dir)

	p := Paths{OpencodePluginPath: filepath.Join(t.TempDir(), "solongate.js")}
	got, err := stageOpencodePlugin(p, "/bin/solongate-guard")
	if err != nil {
		t.Fatalf("stageOpencodePlugin() error: %v", err)
	}
	if got.sourceMissing {
		t.Error("stageOpencodePlugin() reported sourceMissing when the source was found")
	}
	want := `module.exports = "/bin/solongate-guard";`
	if string(got.plugin) != want {
		t.Errorf("stageOpencodePlugin().plugin = %q, want %q", got.plugin, want)
	}
}

func TestStageOpencodePluginFallsBackToExistingInstall(t *testing.T) {
	t.Setenv("SOLONGATE_HOOKS_DIR", "")
	isolated := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(isolated); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	existing := filepath.Join(t.TempDir(), "solongate.js")
	if err := os.WriteFile(existing, []byte("already installed"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := Paths{OpencodePluginPath: existing}

	got, err := stageOpencodePlugin(p, "/bin/solongate-guard")
	if err != nil {
		t.Fatalf("stageOpencodePlugin() error: %v", err)
	}
	if !got.sourceMissing {
		t.Error("stageOpencodePlugin().sourceMissing = false, want true: no source reachable, but a prior install exists")
	}
	if got.plugin != nil {
		t.Errorf("stageOpencodePlugin().plugin = %v, want nil", got.plugin)
	}
}

func TestStageOpencodePluginErrorsWithNothingToInstall(t *testing.T) {
	t.Setenv("SOLONGATE_HOOKS_DIR", "")
	isolated := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(isolated); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })

	p := Paths{OpencodePluginPath: filepath.Join(t.TempDir(), "solongate.js")}
	_, err = stageOpencodePlugin(p, "/bin/solongate-guard")
	if !errors.Is(err, ErrNoHookSource) {
		t.Errorf("stageOpencodePlugin() error = %v, want ErrNoHookSource", err)
	}
}