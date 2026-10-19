// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var ErrNoHookSource = errors.New(
	"the OpenCode plugin was not found next to this binary; this binary is meant to run from, or beside, a checkout of this repo")

func hookSourceDir() (string, bool) {
	for _, dir := range hookSourceCandidates() {
		if Exists(filepath.Join(dir, opencodePluginName)) {
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

type staged struct {
	plugin []byte

	sourceMissing bool
}

func stageOpencodePlugin(p Paths, guardBin string) (staged, error) {
	dir, ok := hookSourceDir()
	if !ok {
		if !Exists(p.OpencodePluginPath) {
			return staged{}, ErrNoHookSource
		}
		return staged{sourceMissing: true}, nil
	}

	plugin, err := os.ReadFile(filepath.Join(dir, opencodePluginName))
	if err != nil {
		return staged{}, err
	}
	return staged{plugin: bakeGuardBinPath(plugin, guardBin)}, nil
}

func bakeGuardBinPath(src []byte, guardBin string) []byte {
	escaped := strings.ReplaceAll(guardBin, `\`, `\\`)
	return []byte(strings.Replace(string(src), "__SOLONGATE_GUARD_BIN__", escaped, 1))
}