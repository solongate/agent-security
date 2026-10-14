// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"os"
	"path/filepath"
	"time"
)

// A beat is proof that a hook actually ran, recorded by the hook itself the
// moment it starts, before anything that could fail. It used to also carry
// which node binary a shell launcher resolved, back when "did the runtime
// resolve" was a real question. A static Go binary either execs or the OS
// refuses to run it, there is no resolution step left to record — so a beat
// is now just a timestamp, keyed by which hook left it.
//
// Hook names here are the logical ones (`"guard"`, `"audit"`, `"tokens"`),
// not file names: there is no `guard.mjs` to name a beat after anymore.

// BeatDir is where each hook's beat file lives. The directory name is
// unchanged from the launcher-era layout, so an existing install's beats
// are not silently orphaned by this file's own upgrade.
func BeatDir() string {
	return filepath.Join(SGDir(), ".beat")
}

// WriteBeat records that hook just ran. Best effort, always: a beat is a
// diagnostic for `--sg-doctor` and the TUI, never a condition the guard's
// verdict depends on, so a failure here must never block or alter a tool
// call.
func WriteBeat(hook string) {
	dir := BeatDir()
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, hook), []byte(time.Now().UTC().Format(time.RFC3339)), FileMode)
}

// ReadBeat reports when hook last ran, if ever. The time comes from the
// file's own mtime rather than its parsed contents, so a beat still answers
// correctly even if it is ever written empty.
func ReadBeat(hook string) (time.Time, bool) {
	info, err := os.Stat(filepath.Join(BeatDir(), hook))
	if err != nil {
		return time.Time{}, false
	}
	return info.ModTime(), true
}