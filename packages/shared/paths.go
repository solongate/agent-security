// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package shared

import (
	"hash/fnv"
	"os"
	"path/filepath"
	"strconv"
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

// ProjectKey maps a project directory to the short name of its directory
// under ~/.solongate/projects. It is the standard FNV-1a hash of the
// directory, hex-encoded, so the same directory always maps to the same
// name. The hash runs over the directory's bytes, so ASCII paths keep the
// exact names the old hand-rolled loop gave them.
func ProjectKey(dir string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(dir))
	return strconv.FormatUint(uint64(h.Sum32()), 16)
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

// destructiveWords are short verbs that must match as whole words. As
// substrings they would also catch "form", "perm" and "confirm".
var destructiveWords = []string{"rm", "rmdir", "unlink", "kill", "chmod", "chown", "reboot", "shutdown"}

// hasWord reports whether any of words appears in name as a whole token,
// where tokens are split on anything that is not a letter.
func hasWord(name string, words ...string) bool {
	tokens := strings.FieldsFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z')
	})
	for _, tok := range tokens {
		for _, w := range words {
			if tok == w {
				return true
			}
		}
	}
	return false
}

// GuessPermission classifies a tool by the verbs in its name. Unknown names
// fall through to READ, so every verb that can destroy data or reach the
// network has to be listed above. Otherwise a READ-only policy would allow
// it: drop_table, purge_cache and send_email all have to map to WRITE or NETWORK.
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
	case has("fetch", "http", "request", "curl", "network", "download", "upload", "send", "publish", "submit") || n == "websearch":
		return "NETWORK"

	case has("write", "create", "delete", "update", "set", "edit", "remove", "insert",
		"replace", "patch", "modify", "append", "overwrite", "rename", "move", "mkdir", "touch",
		"drop", "truncate", "destroy", "purge", "deploy") || hasWord(n, destructiveWords...):
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
