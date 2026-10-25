// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package shared

import (
	"testing"
	"time"
)

func TestWriteBeatThenReadBeat(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	before := time.Now().Add(-time.Second)
	WriteBeat("hook-a")
	ts, ok := ReadBeat("hook-a")
	if !ok {
		t.Fatal("expected ReadBeat to find a beat just written")
	}
	if ts.Before(before) {
		t.Errorf("beat timestamp %v looks stale relative to %v", ts, before)
	}
}

func TestReadBeatMissingHookReturnsFalse(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, ok := ReadBeat("never-written"); ok {
		t.Error("expected ReadBeat to report false for a hook that was never written")
	}
}

func TestBeatDirIsUnderSGDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	got := BeatDir()
	want := SGDir()
	if len(got) <= len(want) || got[:len(want)] != want {
		t.Errorf("BeatDir() = %q, want it nested under %q", got, want)
	}
}
