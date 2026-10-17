// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

var scratchFiles = map[string]bool{
	".eval-ring.jsonl": true,
	".last-eval":       true,
	".last-deny":       true,
	".last-tool-call":  true,
	".debug-guard-log": true,
}

func sweepLegacyScratch() {
	cwd, err := os.Getwd()
	if err != nil {
		return
	}
	dir := filepath.Join(cwd, ".solongate")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
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
		_ = os.Remove(dir)
	}
}

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