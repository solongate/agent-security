// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"os"
	"path/filepath"
	"strings"
)

const sourceRecordName = ".installed-from"

func SourceRecordPath() string { return filepath.Join(GlobalPaths().SGDir, sourceRecordName) }

func RecordInstallSource() {
	root, ok := CheckoutRoot()
	if !ok {
		return
	}
	_ = os.WriteFile(SourceRecordPath(), []byte(root+"\n"), 0o644)
}

func InstalledFrom() (string, bool) {
	b, err := os.ReadFile(SourceRecordPath())
	if err != nil {
		return "", false
	}
	root := strings.TrimSpace(string(b))
	if root == "" || !isCheckout(root) {
		return "", false
	}
	return root, true
}

func CheckoutRoot() (string, bool) {
	dir, ok := hookSourceDir()
	if !ok {
		return "", false
	}

	for i := 0; i < 6; i++ {
		if isCheckout(dir) {
			abs, err := filepath.Abs(dir)
			if err != nil {
				return dir, true
			}
			return abs, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", false
}

func isCheckout(dir string) bool {
	return Exists(filepath.Join(dir, "scripts", "shell", "install.sh")) && Exists(filepath.Join(dir, ".git"))
}