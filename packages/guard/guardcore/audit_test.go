// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package guardcore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/shared"
)

func TestResolveLocalLogDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	defaultDir := filepath.Join(shared.SGDir(), "local-logs")

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty string", "", ""},
		{"only whitespace", "   ", ""},
		{"a relative path falls back to the default", "logs/here", defaultDir},
		{"an absolute path with a trailing slash is trimmed", "/var/log/sg/", "/var/log/sg"},
		{"an absolute path with trailing backslashes is trimmed", `/var/log/sg\\`, "/var/log/sg"},
		{"an absolute path with no trailing separator is untouched", "/var/log/sg", "/var/log/sg"},
		{"surrounding whitespace is trimmed", "  /var/log/sg  ", "/var/log/sg"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveLocalLogDir(c.in); got != c.want {
				t.Errorf("resolveLocalLogDir(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	s := strings.TrimRight(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func TestWriteLocalLogWithNoSecurityUsesTheDefaultDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	WriteLocalLog(nil, map[string]interface{}{"tool": "Read"})

	path := filepath.Join(shared.SGDir(), "local-logs", "solongate-audit.jsonl")
	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1: %v", len(lines), lines)
	}
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("line is not valid json: %v", err)
	}
	if entry["tool"] != "Read" {
		t.Errorf("entry = %v, want tool=Read", entry)
	}

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != shared.FileMode {
		t.Errorf("log file mode = %o, want %o", perm, shared.FileMode)
	}
}

func TestWriteLocalLogAppendsMultipleEntries(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	WriteLocalLog(nil, map[string]interface{}{"n": float64(1)})
	WriteLocalLog(nil, map[string]interface{}{"n": float64(2)})

	path := filepath.Join(shared.SGDir(), "local-logs", "solongate-audit.jsonl")
	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %v", len(lines), lines)
	}
}

func TestWriteLocalLogHonorsAnAbsoluteCustomDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	custom := filepath.Join(t.TempDir(), "my-logs")

	sec := &shared.Security{LocalLogs: &shared.LocalLogs{Enabled: true, Path: custom}}
	WriteLocalLog(sec, map[string]interface{}{"tool": "Write"})

	path := filepath.Join(custom, "solongate-audit.jsonl")
	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("got %d lines in the custom dir, want 1: %v", len(lines), lines)
	}

	defaultPath := filepath.Join(shared.SGDir(), "local-logs", "solongate-audit.jsonl")
	if _, err := os.Stat(defaultPath); err == nil {
		t.Error("a log was also written to the default dir even though a custom dir was honored")
	}
}

func TestWriteLocalLogWithARelativeCustomDirFallsBackToDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	sec := &shared.Security{LocalLogs: &shared.LocalLogs{Enabled: true, Path: "relative/dir"}}
	WriteLocalLog(sec, map[string]interface{}{"tool": "Bash"})

	path := filepath.Join(shared.SGDir(), "local-logs", "solongate-audit.jsonl")
	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("got %d lines in the default dir, want 1: %v", len(lines), lines)
	}
}

func TestWriteLocalLogFallsBackWhenTheCustomDirCannotBeCreated(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	blocker := filepath.Join(home, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	// blocker exists as a plain file, so treating it as a directory to create
	// must fail and WriteLocalLog must fall back to the default location.
	custom := filepath.Join(blocker, "logs")

	sec := &shared.Security{LocalLogs: &shared.LocalLogs{Enabled: true, Path: custom}}
	WriteLocalLog(sec, map[string]interface{}{"tool": "Edit"})

	path := filepath.Join(shared.SGDir(), "local-logs", "solongate-audit.jsonl")
	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("got %d lines in the fallback dir, want 1: %v", len(lines), lines)
	}
}

func TestWriteLocalLogSilentlyDropsUnmarshalableEntries(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("WriteLocalLog panicked on an unmarshalable entry: %v", r)
		}
	}()
	WriteLocalLog(nil, map[string]interface{}{"bad": func() {}})

	path := filepath.Join(shared.SGDir(), "local-logs", "solongate-audit.jsonl")
	if _, err := os.Stat(path); err == nil {
		t.Error("a log file was written for an entry that cannot be marshaled")
	}
}