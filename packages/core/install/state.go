// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func guardVersionAt(path string) *int {
	if !Exists(path) {
		return nil
	}
	out, err := exec.Command(path, "--sg-version").Output()
	if err != nil {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return nil
	}
	return &n
}

func InstalledGuardVersion() *int {
	return guardVersionAt(filepath.Join(BinDir(), guardBinaryName()))
}

func ShippedGuardVersion() *int {
	dir, ok := selfBinDir()
	if !ok {
		return nil
	}
	return guardVersionAt(filepath.Join(dir, guardBinaryName()))
}