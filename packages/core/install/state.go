// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

var hookVersionRe = regexp.MustCompile(`HOOK_VERSION\s*=\s*(\d+)`)

func InstalledGuardVersion() *int {
	b, err := os.ReadFile(GlobalPaths().GuardPath())
	if err != nil {
		return nil
	}
	m := hookVersionRe.FindSubmatch(b)
	if m == nil {
		return nil
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return nil
	}
	return &n
}

func ShippedGuardVersion() *int {
	dir, ok := hookSourceDir()
	if !ok {
		return nil
	}
	b, err := readGuardSource(dir)
	if err != nil {
		return nil
	}
	m := hookVersionRe.FindSubmatch(b)
	if m == nil {
		return nil
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return nil
	}
	return &n
}

func GuardHookOutdated() bool {
	installed, err := os.ReadFile(GlobalPaths().GuardPath())
	if err != nil {
		return false
	}
	dir, ok := hookSourceDir()
	if !ok {
		return false
	}
	shipped, err := readGuardSource(dir)
	if err != nil {
		return false
	}
	return !bytes.Equal(installed, shipped)
}

func GuardHooksPresent() bool {
	p := GlobalPaths()
	for _, name := range []string{GuardHookName, auditHookName, stopHookName} {
		if !Exists(filepath.Join(p.HooksDir, name)) {
			return false
		}
	}
	return true
}