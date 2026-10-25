// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGlobalPathsDefaults(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	p := GlobalPaths()
	if p.Home != home {
		t.Errorf("Home = %q, want %q", p.Home, home)
	}
	if p.ClaudeDir != filepath.Join(home, ".claude") {
		t.Errorf("ClaudeDir = %q, want %q", p.ClaudeDir, filepath.Join(home, ".claude"))
	}
	if p.SettingsPath != filepath.Join(home, ".claude", "settings.json") {
		t.Errorf("SettingsPath = %q", p.SettingsPath)
	}
	if p.AntigravityDir != filepath.Join(home, ".gemini", "config") {
		t.Errorf("AntigravityDir = %q, want %q", p.AntigravityDir, filepath.Join(home, ".gemini", "config"))
	}
	if p.CodexDir != filepath.Join(home, ".codex") {
		t.Errorf("CodexDir = %q, want %q", p.CodexDir, filepath.Join(home, ".codex"))
	}
	if p.OpencodeDir != filepath.Join(home, ".config", "opencode") {
		t.Errorf("OpencodeDir = %q, want %q", p.OpencodeDir, filepath.Join(home, ".config", "opencode"))
	}
	if p.OpencodePluginPath != filepath.Join(p.OpencodeDir, "plugins", "solongate.js") {
		t.Errorf("OpencodePluginPath = %q", p.OpencodePluginPath)
	}
}

func TestGlobalPathsHonorsCodexHomeOverride(t *testing.T) {
	home := t.TempDir()
	codexHome := filepath.Join(t.TempDir(), "custom-codex")
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", codexHome)

	p := GlobalPaths()
	want, err := filepath.Abs(codexHome)
	if err != nil {
		t.Fatal(err)
	}
	if p.CodexDir != want {
		t.Errorf("CodexDir = %q, want %q", p.CodexDir, want)
	}
	if p.CodexHooksPath != filepath.Join(want, "hooks.json") {
		t.Errorf("CodexHooksPath = %q", p.CodexHooksPath)
	}
}

func TestGlobalPathsHonorsXDGConfigHomeOverride(t *testing.T) {
	home := t.TempDir()
	xdg := filepath.Join(t.TempDir(), "custom-config")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", xdg)

	p := GlobalPaths()
	want, err := filepath.Abs(xdg)
	if err != nil {
		t.Fatal(err)
	}
	if p.OpencodeDir != filepath.Join(want, "opencode") {
		t.Errorf("OpencodeDir = %q, want %q", p.OpencodeDir, filepath.Join(want, "opencode"))
	}
}

func TestAbsOr(t *testing.T) {
	if got := absOr("", "/fallback"); got != "/fallback" {
		t.Errorf("absOr(\"\", fallback) = %q, want the fallback", got)
	}
	if got := absOr("relative/dir", "/fallback"); got == "/fallback" || !filepath.IsAbs(got) {
		t.Errorf("absOr(relative, fallback) = %q, want an absolute path derived from the value", got)
	}
	if got := absOr("/already/abs", "/fallback"); got != "/already/abs" {
		t.Errorf("absOr(abs, fallback) = %q, want the value unchanged", got)
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	if Exists(filepath.Join(dir, "nope")) {
		t.Error("Exists() = true for a path that was never created")
	}
	f := filepath.Join(dir, "yes")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !Exists(f) {
		t.Error("Exists() = false for a file that was just created")
	}
	if !Exists(dir) {
		t.Error("Exists() = false for a directory")
	}
}

func TestGuardBinaryPathAndName(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	p := GlobalPaths()
	want := filepath.Join(home, ".solongate", "bin", guardBinaryName())
	if got := p.GuardBinaryPath(); got != want {
		t.Errorf("GuardBinaryPath() = %q, want %q", got, want)
	}
	if runtime.GOOS == "windows" {
		if guardBinaryName() != "solongate-guard.exe" {
			t.Errorf("guardBinaryName() = %q, want solongate-guard.exe on windows", guardBinaryName())
		}
	} else if guardBinaryName() != "solongate-guard" {
		t.Errorf("guardBinaryName() = %q, want solongate-guard", guardBinaryName())
	}
}

func TestProtectedTargetsIncludesTheExpectedFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	p := GlobalPaths()

	targets := p.protectedTargets()
	want := []string{
		p.SettingsPath,
		filepath.Join(p.HooksDir, LauncherName),
		p.AntigravityHooksPath,
		p.CodexHooksPath,
		p.OpencodePluginPath,
		p.GuardBinaryPath(),
	}
	if len(targets) != len(want) {
		t.Fatalf("protectedTargets() = %v, want %v", targets, want)
	}
	for i := range want {
		if targets[i] != want[i] {
			t.Errorf("protectedTargets()[%d] = %q, want %q", i, targets[i], want[i])
		}
	}
}

func TestLockAndUnlockProtectedNoPanicWhenFilesAbsent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	LockProtected()
	UnlockProtected()
}

func TestLocksDisabled(t *testing.T) {
	t.Setenv("SOLONGATE_NO_OS_LOCK", "")
	if locksDisabled() {
		t.Error("locksDisabled() = true with the env var unset")
	}
	t.Setenv("SOLONGATE_NO_OS_LOCK", "0")
	if locksDisabled() {
		t.Error("locksDisabled() = true with the env var set to 0")
	}
	t.Setenv("SOLONGATE_NO_OS_LOCK", "1")
	if !locksDisabled() {
		t.Error("locksDisabled() = false with the env var set to 1")
	}
}