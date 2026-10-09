// SPDX-License-Identifier: Apache-2.0

package install

import (
	"os"
	"path/filepath"
	"strings"
)

// WHERE THIS INSTALL CAME FROM, so it can be updated without being told again.
//
// An install copies files into the store and the store is all that is left: the binary
// runs from ~/.solongate/bin, and nothing above that directory says anything about the
// checkout it was built in. So `update` had no way to find the source short of asking,
// and asking is the thing the command exists to avoid.
//
// One line of text, written at install time. Not JSON: a path is a path, and a file
// somebody might open by hand should not need a parser to read.
//
// IT CAN BE ABSENT AND THAT IS NORMAL. An npm install has no checkout; a checkout can be
// moved or deleted after the fact. Every reader here treats "no source" and "the source
// is gone" the same way — as a question to answer, not a failure.

const sourceRecordName = ".installed-from"

// SourceRecordPath is the file naming the checkout this install was built from.
func SourceRecordPath() string { return filepath.Join(GlobalPaths().SGDir, sourceRecordName) }

// RecordInstallSource writes down the checkout this install came from, if it came from
// one. Best effort: an install that cannot write this file is still a working install,
// and the only thing lost is `update` knowing where to look.
func RecordInstallSource() {
	root, ok := CheckoutRoot()
	if !ok {
		return
	}
	_ = os.WriteFile(SourceRecordPath(), []byte(root+"\n"), 0o644)
}

// InstalledFrom is the recorded checkout, if it is still a checkout.
//
// Verified rather than trusted: a path that has been deleted, moved, or had its install
// script removed is not a source any more, and reporting it would send `update` to build
// in a directory that cannot build anything.
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

// CheckoutRoot finds the repository this binary was built in, by walking up from the
// packaged hook source — which is the one directory an install already knows how to find.
func CheckoutRoot() (string, bool) {
	dir, ok := hookSourceDir()
	if !ok {
		return "", false
	}
	// From <repo>/packages/hooks, the repository is two levels up; the loop is
	// here so the layout can change without this silently returning the wrong directory.
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

// isCheckout is deliberately strict about what counts: a directory with this product's
// install script AND a git repository in it. Either alone is somebody else's directory.
func isCheckout(dir string) bool {
	return Exists(filepath.Join(dir, "install.sh")) && Exists(filepath.Join(dir, ".git"))
}
