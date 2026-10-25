// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"math"
	"strconv"
	"testing"
	"time"
)

func TestHookStartWithNoEnvReturnsNow(t *testing.T) {
	t.Setenv("SOLONGATE_HOOK_ORIGIN_MS", "")
	before := time.Now()
	got := hookStart()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Errorf("hookStart() = %v, want it between %v and %v", got, before, after)
	}
}

func TestHookStartUsesARecentOriginFromEnv(t *testing.T) {
	origin := time.Now().Add(-5 * time.Second)
	t.Setenv("SOLONGATE_HOOK_ORIGIN_MS", strconv.FormatInt(origin.UnixMilli(), 10))
	got := hookStart()
	if diff := got.Sub(origin); diff < -time.Millisecond || diff > time.Millisecond {
		t.Errorf("hookStart() = %v, want it to match the env origin %v (diff %v)", got, origin, diff)
	}
}

func TestHookStartIgnoresAStaleOrigin(t *testing.T) {
	origin := time.Now().Add(-2 * time.Minute)
	t.Setenv("SOLONGATE_HOOK_ORIGIN_MS", strconv.FormatInt(origin.UnixMilli(), 10))
	before := time.Now()
	got := hookStart()
	if got.Before(before) {
		t.Errorf("hookStart() = %v, want it to fall back to now() for a stale origin older than a minute", got)
	}
}

func TestHookStartIgnoresAFutureOrigin(t *testing.T) {
	origin := time.Now().Add(5 * time.Second)
	t.Setenv("SOLONGATE_HOOK_ORIGIN_MS", strconv.FormatInt(origin.UnixMilli(), 10))
	before := time.Now()
	got := hookStart()
	if got.Before(before) {
		t.Errorf("hookStart() = %v, want it to fall back to now() for a future origin", got)
	}
}

func TestHookStartIgnoresAnUnparsableOrigin(t *testing.T) {
	t.Setenv("SOLONGATE_HOOK_ORIGIN_MS", "not-a-number")
	before := time.Now()
	got := hookStart()
	after := time.Now()
	if got.Before(before) || got.After(after) {
		t.Errorf("hookStart() = %v, want it between %v and %v for garbage input", got, before, after)
	}
}

func TestElapsedMsIsNonNegativeAndRoundedToATenth(t *testing.T) {
	got := elapsedMs(time.Now())
	if got < 0 {
		t.Fatalf("elapsedMs = %v, want >= 0", got)
	}
	if got > 1000 {
		t.Errorf("elapsedMs = %v, suspiciously large for an immediate call", got)
	}
	scaled := got * 10
	if diff := math.Abs(scaled - math.Round(scaled)); diff > 1e-9 {
		t.Errorf("elapsedMs = %v is not rounded to the nearest tenth of a millisecond", got)
	}
}

func TestElapsedMsReflectsRealElapsedTime(t *testing.T) {
	started := time.Now()
	time.Sleep(20 * time.Millisecond)
	got := elapsedMs(started)
	if got < 10 {
		t.Errorf("elapsedMs = %v after a 20ms sleep, want at least ~10ms", got)
	}
}