// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"path/filepath"
	"runtime"
)

const LauncherName = "sg-run.sh"

const BeatDirName = ".beat"

const (
	guardKind  = "guard"
	auditKind  = "audit"
	tokensKind = "tokens"
)

func hookCommand(p Paths, kind, client, label string) string {
	bin := filepath.ToSlash(p.GuardBinaryPath())
	sub := ""
	if kind != guardKind {
		sub = kind + " "
	}
	if runtime.GOOS == "windows" {
		return callPrefix() + `"` + bin + `" ` + sub + client + ` "` + label + `"`
	}
	launcher := filepath.ToSlash(filepath.Join(p.HooksDir, LauncherName))
	return `/bin/sh "` + launcher + `" ` + kind + ` ` + client + ` "` + label + `"`
}