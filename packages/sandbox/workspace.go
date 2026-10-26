// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
)

// checkWorkspaceRoot rejects workspace roots that confine nothing: the root of the
// filesystem and the current user's home directory. Both the candidate and the home
// directory are resolved with filepath.EvalSymlinks before the comparison, so a
// symlink aliasing either of them is caught even though its literal path differs
// (issue #112).
//
// The caller passes an absolute path. The returned error is meant to be shown to the
// person who configured the workspace, so it names the rule that was broken.
func checkWorkspaceRoot(ws string) error {
	if !filepath.IsAbs(ws) {
		return errors.New("workspace must be an absolute path, got " + ws)
	}

	resolved, err := filepath.EvalSymlinks(filepath.Clean(ws))
	if err != nil {
		return errors.New("workspace " + ws + " cannot be read: " + err.Error())
	}

	root := filepath.VolumeName(resolved) + string(filepath.Separator)
	if resolved == root {
		return errors.New(`refusing to use "/" as a workspace: that confines nothing`)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	if real, err := filepath.EvalSymlinks(filepath.Clean(home)); err == nil {
		home = real
	}
	if resolved == filepath.Clean(home) {
		return errors.New("refusing to use the home directory as a workspace: " +
			"it contains ~/.ssh and every other project, which is what this mode exists to keep out")
	}

	return nil
}
