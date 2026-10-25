// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSweepLegacyScratchWithNoSolongateDirIsANoop(t *testing.T) {
	t.Chdir(t.TempDir())
	sweepLegacyScratch() // must not panic
}

func TestSweepLegacyScratchRemovesKnownFilesAndTheDirItself(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)

	dir := filepath.Join(cwd, ".solongate")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name := range scratchFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	sweepLegacyScratch()

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the .solongate dir should have been removed once empty, err=%v", err)
	}
}

func TestSweepLegacyScratchLeavesUnknownFilesAndTheDirectory(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)

	dir := filepath.Join(cwd, ".solongate")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".last-eval"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	sweepLegacyScratch()

	if _, err := os.Stat(filepath.Join(dir, ".last-eval")); !os.IsNotExist(err) {
		t.Errorf("the known scratch file should have been removed, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "policy.json")); err != nil {
		t.Errorf("an unrelated file should survive the sweep: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("the directory should survive while an unrelated file remains: %v", err)
	}
}

func TestWriteDenyFlagWritesExpectedFields(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "flags")
	writeDenyFlag(dir, "Bash", "call-42")

	b, err := os.ReadFile(filepath.Join(dir, ".last-deny"))
	if err != nil {
		t.Fatalf("reading deny flag: %v", err)
	}
	var rec map[string]interface{}
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatalf("deny flag is not valid json: %v", err)
	}
	if rec["tool"] != "Bash" || rec["id"] != "call-42" {
		t.Errorf("rec = %v", rec)
	}
	if _, ok := rec["ts"]; !ok {
		t.Errorf("rec is missing a timestamp: %v", rec)
	}
}

func TestWriteDenyFlagFailsSilentlyWhenTheDirCannotBeCreated(t *testing.T) {
	home := t.TempDir()
	blocker := filepath.Join(home, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(blocker, "flags")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("writeDenyFlag panicked: %v", r)
		}
	}()
	writeDenyFlag(dir, "Bash", "call-1")

	if _, err := os.Stat(filepath.Join(dir, ".last-deny")); err == nil {
		t.Error("a flag was written despite the directory being uncreatable")
	}
}

func TestWriteEvalRecordWritesLastEvalAndAppendsToTheRing(t *testing.T) {
	dir := t.TempDir()

	writeEvalRecord(dir, []byte(`{"n":1}`))
	writeEvalRecord(dir, []byte(`{"n":2}`))

	last, err := os.ReadFile(filepath.Join(dir, ".last-eval"))
	if err != nil {
		t.Fatalf("reading .last-eval: %v", err)
	}
	if string(last) != `{"n":2}` {
		t.Errorf(".last-eval = %q, want only the most recent record", last)
	}

	ring, err := os.ReadFile(filepath.Join(dir, ".eval-ring.jsonl"))
	if err != nil {
		t.Fatalf("reading .eval-ring.jsonl: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(ring), "\n"), "\n")
	if len(lines) != 2 || lines[0] != `{"n":1}` || lines[1] != `{"n":2}` {
		t.Errorf("ring lines = %v, want both records in order", lines)
	}
}

func TestWriteEvalRecordFailsSilentlyWhenTheDirCannotBeCreated(t *testing.T) {
	home := t.TempDir()
	blocker := filepath.Join(home, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(blocker, "flags")

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("writeEvalRecord panicked: %v", r)
		}
	}()
	writeEvalRecord(dir, []byte(`{"n":1}`))

	if _, err := os.Stat(filepath.Join(dir, ".last-eval")); err == nil {
		t.Error("a record was written despite the directory being uncreatable")
	}
}