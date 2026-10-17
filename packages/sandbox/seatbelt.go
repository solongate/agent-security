// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func seatbeltProfile(deny []string) (string, []string) {
	var b strings.Builder
	b.WriteString("(version 1)\n(allow default)\n")

	var got []string
	ancestors := map[string]bool{}

	for _, d := range deny {
		abs, err := filepath.Abs(d)
		if err != nil {
			continue
		}
		abs = filepath.Clean(abs)
		forms := map[string]bool{abs: true}

		if real, err := filepath.EvalSymlinks(abs); err == nil {
			forms[real] = true
		}
		for f := range forms {
			b.WriteString("(deny file-read* (literal " + sbplString(f) + "))\n")
			b.WriteString("(deny file-write* (literal " + sbplString(f) + "))\n")
			b.WriteString("(deny file-read* (subpath " + sbplString(f) + "))\n")
			b.WriteString("(deny file-write* (subpath " + sbplString(f) + "))\n")
			for dir := filepath.Dir(f); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
				ancestors[dir] = true
			}
		}
		got = append(got, abs)
	}

	for dir := range ancestors {
		b.WriteString("(allow file-read-metadata (literal " + sbplString(dir) + "))\n")
		b.WriteString("(deny file-write-unlink (literal " + sbplString(dir) + "))\n")
	}
	return b.String(), got
}

func sbplString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func seatbeltWorkspaceProfile(p Plan) (string, error) {
	ws := filepath.Clean(p.Workspace)
	if !filepath.IsAbs(ws) {
		return "", errors.New("workspace must be an absolute path, got " + p.Workspace)
	}
	if ws == "/" {
		return "", errors.New(`refusing to use "/" as a workspace: that confines nothing`)
	}
	if home, err := os.UserHomeDir(); err == nil && filepath.Clean(home) == ws {
		return "", errors.New("refusing to use the home directory as a workspace: " +
			"it contains ~/.ssh and every other project, which is what this mode exists to keep out")
	}

	var b strings.Builder
	b.WriteString("(version 1)\n(deny default)\n")

	b.WriteString("(allow process-fork)\n")
	b.WriteString("(allow sysctl-read)\n")
	b.WriteString("(allow mach-lookup)\n")
	b.WriteString("(allow signal (target self))\n")
	b.WriteString("(allow file-read-metadata)\n")

	for _, f := range canonicalForms(ws) {
		b.WriteString("(allow file* (subpath " + sbplString(f) + "))\n")
		b.WriteString("(allow process-exec (subpath " + sbplString(f) + "))\n")
	}
	for _, d := range append(p.RuntimeWrite, DefaultRuntimeDevices()...) {
		if d == "" {
			continue
		}
		for _, f := range canonicalForms(filepath.Clean(d)) {
			b.WriteString("(allow file* (subpath " + sbplString(f) + "))\n")
		}
	}
	for _, d := range p.RuntimeRead {
		if d == "" {
			continue
		}
		for _, f := range canonicalForms(filepath.Clean(d)) {
			b.WriteString("(allow file-read* (subpath " + sbplString(f) + "))\n")
			b.WriteString("(allow process-exec (subpath " + sbplString(f) + "))\n")
		}
	}
	return b.String(), nil
}

func canonicalForms(abs string) []string {
	out := []string{abs}
	if real, err := filepath.EvalSymlinks(abs); err == nil && real != abs {
		out = append(out, real)
	}
	return out
}