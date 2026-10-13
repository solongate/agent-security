// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
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
// ever touched, config folders and repos without an ignore rule included. They
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
		return // not there, or not readable, either way nothing to do
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

// writeDenyFlag records WHICH call was denied, so the post-tool audit hook does
// not file a second, ALLOW-looking row for a call this guard already refused.
//
// The hook has written this file for a long time and this binary did not, so on
// a machine with the binary the suppression never engaged: a denial got its DENY
// row here and an ALLOW row from audit.mjs for the same call.
//
// It carries the CALL's identity rather than just the tool name. Matching on the
// name alone mislabels a DIFFERENT call that merely follows a denial inside the
// flag's ten-second window, and on Codex every shell call is named "Bash", so
// an allowed `echo hi` right after a blocked `cat secret` was filed as a denial
// though it ran normally.
//
// NO `fp` FIELD, DELIBERATELY. The hook also writes an argument fingerprint, as
// FNV-1a over `JSON.stringify(tool_input)`. That is a hash of a specific byte
// string, and JSON.stringify emits object keys in insertion order where
// encoding/json sorts them, so a value computed here would differ for the same
// call and the reader would conclude the denial was a different one. The reader
// prefers the id when both sides have one (see audit.mjs), which is the case for
// every client that sends a tool call id; where one does not, the flag reads as a
// flag from an older guard and falls back to the name-and-time rule, which is
// what it would have got anyway.
func writeDenyFlag(dir, tool, callID string) {
	if os.MkdirAll(dir, 0o755) != nil {
		return
	}
	rec, err := json.Marshal(map[string]interface{}{
		"tool": tool,
		"ts":   time.Now().UnixMilli(),
		"id":   callID,
	})
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, ".last-deny"), rec, 0o644)
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
