// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package shared

import (
	"os"
	"path/filepath"
	"time"
)

func BeatDir() string {
	return filepath.Join(SGDir(), ".beat")
}

func WriteBeat(hook string) {
	dir := BeatDir()
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, hook), []byte(time.Now().UTC().Format(time.RFC3339)), FileMode)
}

func ReadBeat(hook string) (time.Time, bool) {
	info, err := os.Stat(filepath.Join(BeatDir(), hook))
	if err != nil {
		return time.Time{}, false
	}
	return info.ModTime(), true
}