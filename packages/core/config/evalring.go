// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package config

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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

	Sandbox string `json:"sandbox,omitempty"`
}

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

func (r *EvalRecord) At() time.Time { return time.UnixMilli(r.Ts) }

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
	start := max(int64(0), info.Size()-maxBytes)
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	split := strings.Split(string(buf), "\n")
	// Only a window that opens mid-line starts with a fragment. Opening
	// exactly after a newline, the first chunk is a complete ring entry and
	// must be kept (issue #225). The fragment has to go before blank lines
	// are filtered, or a window starting on the newline itself would drop
	// the first real entry in place of the empty fragment.
	if start > 0 && !precededByNewline(f, start) {
		split = split[1:]
	}
	var out []string
	for _, l := range split {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func precededByNewline(f *os.File, off int64) bool {
	b := make([]byte, 1)
	_, err := f.ReadAt(b, off-1)
	return err == nil && b[0] == '\n'
}