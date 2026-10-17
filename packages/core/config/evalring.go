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

	if info.Size() > maxBytes && len(out) > 0 {
		out = out[1:]
	}
	return out
}