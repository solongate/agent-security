// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The guard's eval ring: one record per tool call, written whether the call was
// allowed or refused.
//
// IT IS THE ONLY ARTEFACT WRITTEN ON EVERY CALL. The audit log carries denials
// and, on clients with no post-tool stage, flagged allows; the beat file says
// the hook fired but not what it decided. So this is what answers "has this
// machine actually judged anything, and under what conditions".

// EvalRecord is one line of it. The guard writes argument KEY NAMES and counts,
// never values: the values are the file contents, commands and URLs this whole
// product exists to keep where they belong.
type EvalRecord struct {
	Ms      float64 `json:"ms"`
	Ts      int64   `json:"ts"`
	Tool    string  `json:"tool"`
	Client  string  `json:"client"`
	Cwd     string  `json:"cwd"`
	Perm    string  `json:"perm"`
	Paths   int     `json:"paths"`
	Cmds    int     `json:"cmds"`
	URLs    int     `json:"urls"`
	Session string  `json:"session"`

	// Sandbox is the marker the agent was started with, empty when it was not
	// started by `solongate run`. It is what lets `doctor` tell a machine that
	// is enforcing protected paths with the kernel from one that is enforcing
	// them with a string match, which look identical from everywhere else.
	Sandbox string `json:"sandbox,omitempty"`
}

// NewestEvalRecord returns the most recent call the guard judged, from ANY
// project on this machine.
//
// NOT ProjectFlagDir(). The record is filed under a hash of the directory the
// HOOK process was spawned in, and a client is free to spawn it anywhere;
// Antigravity does. Reading only the caller's own project reports "nothing has
// happened" on a machine where the guard is working perfectly, three
// directories away.
func NewestEvalRecord() *EvalRecord {
	root := filepath.Join(Dir(), "projects")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var best *EvalRecord
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		for _, line := range tailRingLines(filepath.Join(root, e.Name(), ".eval-ring.jsonl")) {
			var rec EvalRecord
			if json.Unmarshal([]byte(line), &rec) != nil || rec.Ts == 0 {
				continue
			}
			if best == nil || rec.Ts > best.Ts {
				c := rec
				best = &c
			}
		}
	}
	return best
}

// At is the record's timestamp as a time.
func (r *EvalRecord) At() time.Time { return time.UnixMilli(r.Ts) }

// tailRingLines reads the last 8 KB of a ring, which is far more than the ring
// ever holds and bounded for the case where something else wrote to the path.
func tailRingLines(file string) []string {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil
	}
	const maxBytes = 8192
	if start := info.Size() - maxBytes; start > 0 {
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return nil
		}
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(buf), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	// The first line of a seeked read is usually a fragment.
	if info.Size() > maxBytes && len(out) > 0 {
		out = out[1:]
	}
	return out
}
