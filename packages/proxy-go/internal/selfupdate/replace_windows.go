//go:build windows

package selfupdate

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// stagedSuffix marks a binary this package moved aside. It is matched by a
// prefix rather than an exact name because the timestamp makes each one unique —
// two updates in one session must not fight over a single spare filename.
const stagedSuffix = ".sg-old-"

// stageRunningExecutable moves this binary out of its own way so npm can write
// the new one, and returns the undo.
//
// Windows will not let anything overwrite or delete a running executable, but it
// WILL let it be renamed. `npm install -g` replaces the whole package directory,
// so on a machine running this Go binary the install fails with EBUSY/EPERM
// before it starts — and, worse, npm may have already removed part of the old
// package by then. Renaming first turns that into an ordinary install: the file
// npm wants to write is no longer there, the running image keeps executing from
// its new name, and the leftover is swept on the next run (it cannot be deleted
// while it is still running).
//
// The returned function is the half that matters for the rule that a failed
// install must leave the previous state working: if npm did not put a new binary
// where the old one was, the old one is moved back.
func stageRunningExecutable() (restore func()) {
	noop := func() {}
	exe, err := os.Executable()
	if err != nil {
		return noop
	}
	staged := exe + stagedSuffix + strconv.FormatInt(time.Now().UnixMilli(), 10)
	if os.Rename(exe, staged) != nil {
		// Could not move it. Do nothing rather than guess: npm may still
		// succeed, and if it does not, the machine is exactly as it was.
		return noop
	}
	return func() {
		if _, err := os.Stat(exe); err == nil {
			// npm wrote a new binary. The staged copy is still the running image,
			// so it cannot be deleted yet; SweepStagedReplacements gets it next
			// run.
			return
		}
		_ = os.Rename(staged, exe)
	}
}

// SweepStagedReplacements deletes binaries a previous update moved aside.
//
// It has to happen on a LATER run: the staged file was the running image at the
// time it was staged, and Windows refuses to delete a file that is still
// executing. Every failure here is ignored — another instance may be running
// from one of these right now, and a leftover file is not worth an error the
// user cannot act on.
func SweepStagedReplacements() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	matches, err := filepath.Glob(exe + stagedSuffix + "*")
	if err != nil {
		return
	}
	for _, m := range matches {
		_ = os.Remove(m)
	}
}
