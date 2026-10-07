// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"
	"testing"
	"time"
)

// THE LIVE VIEW HAS TO RENDER, and until now nothing checked that it could.
//
// Every test in this package drives a function and reads a value back. View is the one
// thing a person actually sees, it is several hundred lines of slicing and column
// arithmetic, and a panic in it takes down the whole console — on a security tool,
// mid-session. The failure mode is not a wrong number on screen; it is no screen.
//
// The sizes below are the ones that break layout code: a terminal narrower than the
// panes assume, one row shorter than the panes reserve, and the ordinary case.
func TestTheLiveViewRendersWithoutPanicking(t *testing.T) {
	sizes := []struct {
		name       string
		cols, rows int
	}{
		{"a normal terminal", 120, 40},
		{"a wide one", 220, 60},
		{"narrow", 40, 24},
		{"absurdly narrow", 12, 10},
		{"short", 120, 8},
		{"one row", 120, 1},
	}

	on := true
	for _, size := range sizes {
		for _, state := range liveStates(on) {
			t.Run(size.name+"/"+state.name, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("View panicked at %dx%d: %v", size.cols, size.rows, r)
					}
				}()
				ctx := PanelContext{Cols: size.cols, Rows: size.rows, Now: time.Unix(1_700_000_000, 0)}
				out := state.p.View(ctx)
				if strings.TrimSpace(out) == "" {
					t.Error("View returned nothing to draw")
				}
			})
		}
	}
}

// The states worth rendering: each one is a shape the view has to survive, not a
// variation on the same data.
func liveStates(on bool) []struct {
	name string
	p    *Live
} {
	type state = struct {
		name string
		p    *Live
	}

	// Freshly opened: nothing polled yet. This is the branch that returns "connecting…".
	fresh := &Live{}

	// Running, with nothing recorded — the quiet machine the heartbeat exists for.
	quiet := &Live{localOn: &on}
	for i := 0; i < 20; i++ {
		quiet.beat(int64(1_000 + i))
	}

	// Running, with traffic and a decision in the trace.
	busy := &Live{localOn: &on}
	busy.local = make([]streamItem, 50)
	busy.merged = make([]streamItem, 50)
	for i := 0; i < 60; i++ {
		if i%7 == 0 {
			busy.pulsePending = 30 + i
		}
		busy.beat(int64(1_000 + i))
		busy.eval = append(busy.eval, 28+i%12)
	}

	// A trace longer than any terminal is wide, which is the slicing columnChart does.
	long := &Live{localOn: &on}
	for i := 0; i < 500; i++ {
		long.pulsePending = i % 90
		long.beat(int64(1_000 + i))
	}

	return []state{
		{"fresh", fresh},
		{"quiet", quiet},
		{"busy", busy},
		{"a long trace", long},
	}
}
