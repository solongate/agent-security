// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"path/filepath"
	"runtime"
)

const LauncherName = "sg-run.sh"

const BeatDirName = ".beat"

func hookCommand(p Paths, node, script, client, label string) string {
	target := filepath.ToSlash(filepath.Join(p.HooksDir, script))
	if runtime.GOOS == "windows" {
		return callPrefix() + `"` + filepath.ToSlash(node) + `" "` + target + `" ` + client + ` "` + label + `"`
	}
	launcher := filepath.ToSlash(filepath.Join(p.HooksDir, LauncherName))
	return `/bin/sh "` + launcher + `" "` + target + `" ` + client + ` "` + label + `"`
}