// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writePolicy(t *testing.T, contents string) {
	t.Helper()
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Dir(), "policy.json"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLocalLogsSettingNoPolicyFileReturnsDefault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	got := LocalLogsSetting()
	want := LocalLogSetting{Enabled: true, UsableHere: true, File: DefaultLocalLogFile()}
	if got != want {
		t.Errorf("LocalLogsSetting() = %+v, want %+v", got, want)
	}
}

func TestLocalLogsSettingInvalidJSONReturnsDefault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writePolicy(t, "{not json")
	got := LocalLogsSetting()
	if got.File != DefaultLocalLogFile() || !got.UsableHere {
		t.Errorf("LocalLogsSetting() = %+v, want the default", got)
	}
}

func TestLocalLogsSettingNoSecurityBlockReturnsDefault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writePolicy(t, `{"other":"field"}`)
	got := LocalLogsSetting()
	if got.File != DefaultLocalLogFile() || !got.UsableHere {
		t.Errorf("LocalLogsSetting() = %+v, want the default", got)
	}
}

func TestLocalLogsSettingFallsBackFromTopLevelToNestedPolicy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	writePolicy(t, `{"policy":{"security":{"localLogs":{"enabled":true,"path":"`+dir+`"}}}}`)
	got := LocalLogsSetting()
	if got.ConfiguredPath != dir {
		t.Errorf("ConfiguredPath = %q, want %q", got.ConfiguredPath, dir)
	}
	if !got.UsableHere {
		t.Errorf("UsableHere = false, want true because %q exists", dir)
	}
	if got.File != filepath.Join(dir, "solongate-audit.jsonl") {
		t.Errorf("File = %q, want %q", got.File, filepath.Join(dir, "solongate-audit.jsonl"))
	}
}

func TestLocalLogsSettingEmptyPathReturnsDefault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writePolicy(t, `{"security":{"localLogs":{"enabled":true,"path":"   "}}}`)
	got := LocalLogsSetting()
	if got.File != DefaultLocalLogFile() {
		t.Errorf("LocalLogsSetting() = %+v, want the default", got)
	}
}

func TestLocalLogsSettingRelativePathIsNotUsableHere(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writePolicy(t, `{"security":{"localLogs":{"enabled":true,"path":"relative/dir"}}}`)
	got := LocalLogsSetting()
	if got.UsableHere {
		t.Error("expected a relative configured path to be unusable")
	}
	if got.ConfiguredPath != "relative/dir" {
		t.Errorf("ConfiguredPath = %q, want %q", got.ConfiguredPath, "relative/dir")
	}
	if got.File != DefaultLocalLogFile() {
		t.Errorf("File = %q, want the default fallback", got.File)
	}
}

func TestLocalLogsSettingAbsolutePathNotYetOnDiskIsNotUsable(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	missing := filepath.Join(t.TempDir(), "never-created")
	writePolicy(t, `{"security":{"localLogs":{"enabled":true,"path":"`+missing+`"}}}`)
	got := LocalLogsSetting()
	if got.UsableHere {
		t.Error("expected a path that does not exist on disk to be unusable")
	}
	if got.File != DefaultLocalLogFile() {
		t.Errorf("File = %q, want the default fallback", got.File)
	}
}

func TestLocalLogsSettingTrimsTrailingSeparators(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	writePolicy(t, `{"security":{"localLogs":{"enabled":true,"path":"`+dir+`///"}}}`)
	got := LocalLogsSetting()
	if got.File != filepath.Join(dir, "solongate-audit.jsonl") {
		t.Errorf("File = %q, want trailing separators stripped from %q", got.File, dir)
	}
}

func TestLocalLogFileDelegatesToSetting(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if got, want := LocalLogFile(), DefaultLocalLogFile(); got != want {
		t.Errorf("LocalLogFile() = %q, want %q", got, want)
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	if err := os.WriteFile(present, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !exists(present) {
		t.Error("exists() = false for a file that was just created")
	}
	if exists(filepath.Join(dir, "absent")) {
		t.Error("exists() = true for a file that was never created")
	}
}