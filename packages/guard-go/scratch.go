package main

import (
	"os"
	"path/filepath"
)

// Files older versions wrote next to the user's code. Nothing else in a folder
// of that name is ours, and that distinction is the whole safety of the sweep.
var scratchFiles = map[string]bool{
	".eval-ring.jsonl": true,
	".last-eval":       true,
	".last-deny":       true,
	".last-tool-call":  true,
	".debug-guard-log": true,
}

// sweepLegacyScratch clears the `./.solongate/` folder an older guard left in
// this working directory.
//
// Those per-call flags used to live beside whatever the agent happened to be
// working on, which scattered a dot-folder through every directory an agent had
// ever touched — config folders and repos without an ignore rule included. They
// live under ~/.solongate/projects/<key> now; this removes what is left behind
// wherever an agent runs again.
//
// Deliberately narrow: only our own filenames go, and the directory only if
// that empties it. A folder someone else created, or one holding anything
// unexpected, is left exactly as it was.
func sweepLegacyScratch() {
	cwd, err := os.Getwd()
	if err != nil {
		return
	}
	dir := filepath.Join(cwd, ".solongate")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // not there, or not readable — either way nothing to do
	}
	remaining := 0
	for _, e := range entries {
		if scratchFiles[e.Name()] {
			if os.Remove(filepath.Join(dir, e.Name())) != nil {
				remaining++
			}
			continue
		}
		remaining++
	}
	if remaining == 0 {
		_ = os.Remove(dir) // fails if it is not empty after all, which is correct
	}
}

// writeEvalRecord leaves the timing the audit hook reads back, in the
// per-project directory rather than in the project.
func writeEvalRecord(dir string, record []byte) {
	if os.MkdirAll(dir, 0o755) != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, ".last-eval"), record, 0o644)
	f, err := os.OpenFile(filepath.Join(dir, ".eval-ring.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(record, '\n'))
}
