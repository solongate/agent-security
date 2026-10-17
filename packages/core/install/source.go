// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var ErrNoHookSource = errors.New(
	"the hook files were not found next to this binary. They are built by `pnpm build` in packages/hooks and this binary is meant to run from, or beside, that checkout")

var ErrNoNode = errors.New(
	"node was not found on PATH, the guard hooks run under node; install Node 20+ (or set SOLONGATE_NODE) and try again")

func hookSourceDir() (string, bool) {
	for _, dir := range hookSourceCandidates() {
		if hasAllHookSources(dir) {
			return dir, true
		}
	}
	return "", false
}

func hookSourceCandidates() []string {
	var out []string
	if v := os.Getenv("SOLONGATE_HOOKS_DIR"); v != "" {
		out = append(out, v)
	}
	if exe, err := os.Executable(); err == nil {

		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		dir := filepath.Dir(exe)
		out = append(out,
			filepath.Join(dir, "hooks"),
			filepath.Join(dir, "..", "hooks"),
		)
		out = append(out, packageCandidates(dir)...)
	}

	if cwd, err := os.Getwd(); err == nil {
		out = append(out, packageCandidates(cwd)...)
	}
	return out
}

func packageCandidates(start string) []string {
	var out []string
	dir := start
	for i := 0; i < 8; i++ {
		out = append(out, filepath.Join(dir, "packages", "hooks"))
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return out
}

func hasAllHookSources(dir string) bool {
	for _, name := range []string{auditHookName, stopHookName, tokensHookName, shieldHookName, dlpModuleName, opencodePluginName} {
		if !Exists(filepath.Join(dir, name)) {
			return false
		}
	}
	return Exists(filepath.Join(dir, bundledGuardName)) || Exists(filepath.Join(dir, GuardHookName))
}

func readGuardSource(dir string) ([]byte, error) {
	if b, err := os.ReadFile(filepath.Join(dir, bundledGuardName)); err == nil {
		return b, nil
	}
	return os.ReadFile(filepath.Join(dir, GuardHookName))
}

type staged struct {
	hooks map[string][]byte

	plugin []byte

	sourceMissing bool
}

func stageHooks(p Paths, node string) (staged, error) {
	st := staged{hooks: map[string][]byte{}}

	dir, ok := hookSourceDir()
	if !ok {
		for _, name := range []string{GuardHookName, auditHookName, stopHookName} {
			if !Exists(filepath.Join(p.HooksDir, name)) {
				return staged{}, ErrNoHookSource
			}
		}
		st.sourceMissing = true
		return st, nil
	}

	guard, err := readGuardSource(dir)
	if err != nil {
		return staged{}, err
	}
	st.hooks[GuardHookName] = guard
	for _, name := range []string{auditHookName, stopHookName, tokensHookName, shieldHookName, dlpModuleName} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return staged{}, err
		}
		st.hooks[name] = b
	}

	plugin, err := os.ReadFile(filepath.Join(dir, opencodePluginName))
	if err != nil {
		return staged{}, err
	}
	st.plugin = bakeNodePath(plugin, node)
	return st, nil
}

func bakeNodePath(src []byte, node string) []byte {
	escaped := strings.ReplaceAll(node, `\`, `\\`)
	return []byte(strings.Replace(string(src), "__SOLONGATE_NODE__", escaped, 1))
}

func resolveNode(p Paths) (string, error) {
	if v := os.Getenv("SOLONGATE_NODE"); v != "" && Exists(v) {
		return v, nil
	}
	if found, err := exec.LookPath("node"); err == nil {

		if real, err := filepath.EvalSymlinks(found); err == nil {
			found = real
		}
		if abs, err := filepath.Abs(found); err == nil {
			found = abs
		}
		return found, nil
	}
	if n := nodeFromRegistration(p); n != "" {
		return n, nil
	}
	return "", ErrNoNode
}

func nodeFromRegistration(p Paths) string {
	for _, cmd := range []string{
		claudeRegisteredCommand(p),
		codexRegisteredCommand(p),
		antigravityRegisteredCommand(p),
	} {
		if n := firstQuoted(cmd); n != "" && Exists(n) {
			return filepath.FromSlash(n)
		}
	}
	return ""
}

func firstQuoted(s string) string {
	start := strings.IndexByte(s, '"')
	if start < 0 {
		return ""
	}
	rest := s[start+1:]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}