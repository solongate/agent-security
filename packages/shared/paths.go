// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package shared

import (
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

const (
	DirMode  = 0o700
	FileMode = 0o600
)

func EnsureSGDir() error {
	dir := SGDir()
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return err
	}
	if info, err := os.Stat(dir); err == nil && info.Mode().Perm() != DirMode {
		_ = os.Chmod(dir, DirMode)
	}
	return nil
}

func SGDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, ".solongate")
}

func AgentKey(agent string) string {
	var b strings.Builder
	for _, u := range utf16.Encode([]rune(agent)) {
		r := rune(u)
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "default"
	}
	return b.String()
}

func ProjectKey(dir string) string {
	var h uint32 = 0x811c9dc5
	for _, u := range utf16.Encode([]rune(dir)) {
		h ^= uint32(u)
		h = h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))
	}
	const hexDigits = "0123456789abcdef"
	if h == 0 {
		return "0"
	}
	var out []byte
	for h > 0 {
		out = append([]byte{hexDigits[h&0xf]}, out...)
		h >>= 4
	}
	return string(out)
}

func ProjectFlagDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		abs = cwd
	}
	return filepath.Join(SGDir(), "projects", ProjectKey(abs))
}

func GuessPermission(tool string) string {
	n := strings.ToLower(tool)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(n, s) {
				return true
			}
		}
		return false
	}
	switch {
	case n == "apply_patch" || n == "applypatch":
		return "WRITE"
	case has("exec", "shell", "run", "eval", "monitor", "worktree", "terminal") || n == "bash" || n == "sh" || n == "zsh":
		return "EXECUTE"
	case has("fetch", "http", "request", "curl", "network", "download", "upload") || n == "websearch":
		return "NETWORK"

	case has("write", "create", "delete", "update", "set", "edit", "remove", "insert",
		"replace", "patch", "modify", "append", "overwrite", "rename", "move", "mkdir", "touch"):
		return "WRITE"
	default:
		return "READ"
	}
}

const (
	AuditLockName = ".solongate-audit.lock"

	AuditLockStaleAfterMS = 5000

	AuditLockWaitMS = 2000
)
