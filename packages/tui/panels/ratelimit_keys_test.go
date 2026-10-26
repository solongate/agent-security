// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

var rlNamedKeys = map[string]tea.KeyType{
	"up": tea.KeyUp, "down": tea.KeyDown, "left": tea.KeyLeft, "right": tea.KeyRight,
	"pgup": tea.KeyPgUp, "pgdown": tea.KeyPgDown,
	"shift+left": tea.KeyShiftLeft, "shift+right": tea.KeyShiftRight,
	"ctrl+r": tea.KeyCtrlR,
}

func rlKeyMsg(s string) tea.KeyMsg {
	if typ, ok := rlNamedKeys[s]; ok {
		return tea.KeyMsg{Type: typ}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestRateLimitKeyCtrlR(t *testing.T) {
	t.Run("bound reloads history and insights only", func(t *testing.T) {
		c := rlHome(t)
		p := NewRateLimit(tui.Deps{Client: c})
		p.bound = true
		cmd := p.key(rlKeyMsg("ctrl+r"))
		if cmd == nil {
			t.Fatal("expected a command")
		}
		batch, ok := cmd().(tea.BatchMsg)
		if !ok || len(batch) != 2 {
			t.Fatalf("got %T len=%d, want a 2-command batch", cmd(), len(batch))
		}
		if p.status == "" {
			t.Error("ctrl+r should set a status message")
		}
	})

	t.Run("unbound reloads layers, history and insights", func(t *testing.T) {
		c := rlHome(t)
		p := NewRateLimit(tui.Deps{Client: c})
		cmd := p.key(rlKeyMsg("ctrl+r"))
		batch, ok := cmd().(tea.BatchMsg)
		if !ok || len(batch) != 3 {
			t.Fatalf("got %T len=%d, want a 3-command batch", cmd(), len(batch))
		}
		msg := batch[0]()
		if _, ok := msg.(rlLayersMsg); !ok {
			t.Errorf("first command produced %T, want rlLayersMsg", msg)
		}
	})
}

func TestRateLimitKeySelMovement(t *testing.T) {
	// rows=10 keeps burstBudget() at its floor of 1, for predictable pgup/pgdown steps.
	cases := []struct {
		name      string
		sel       int
		anomalies int
		key       string
		want      int
	}{
		{"up decrements", 2, 0, "up", 1},
		{"up floors at 0", 0, 0, "up", 0},
		{"down increments", 0, 0, "down", 1},
		{"down clamps at the last entry", 3, 0, "down", 3},
		{"pgdown steps by the burst budget", 0, 2, "pgdown", 1},
		{"pgdown clamps at the last entry", 5, 2, "pgdown", 5},
		{"pgup steps by the burst budget", 3, 2, "pgup", 2},
		{"pgup floors at 0", 0, 2, "pgup", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewRateLimit(tui.Deps{})
			p.rows = 10
			for i := 0; i < tc.anomalies; i++ {
				p.insights.Anomalies = append(p.insights.Anomalies, rlAnomaly{})
			}
			p.sel = tc.sel
			p.key(rlKeyMsg(tc.key))
			if p.sel != tc.want {
				t.Errorf("sel = %d, want %d", p.sel, tc.want)
			}
		})
	}
}

func TestRateLimitKeyAdjustArrows(t *testing.T) {
	p := NewRateLimit(tui.Deps{})
	p.hasDraft = true
	p.sel = 1 // PerMinute field

	p.key(rlKeyMsg("right"))
	if p.draft.RateLimit.PerMinute != 1 {
		t.Errorf("right should step PerMinute by 1, got %d", p.draft.RateLimit.PerMinute)
	}
	p.key(rlKeyMsg("shift+right"))
	if p.draft.RateLimit.PerMinute != 11 {
		t.Errorf("shift+right should step PerMinute by 10, got %d", p.draft.RateLimit.PerMinute)
	}
	p.key(rlKeyMsg("left"))
	if p.draft.RateLimit.PerMinute != 10 {
		t.Errorf("left should step PerMinute down by 1, got %d", p.draft.RateLimit.PerMinute)
	}
	p.key(rlKeyMsg("shift+left"))
	if p.draft.RateLimit.PerMinute != 0 {
		t.Errorf("shift+left should step PerMinute down by 10 (clamped at 0), got %d", p.draft.RateLimit.PerMinute)
	}
}

func TestRateLimitKeySaveAndDiscardRespectBound(t *testing.T) {
	p := NewRateLimit(tui.Deps{})
	p.bound = true
	if cmd := p.key(rlKeyMsg("s")); cmd != nil {
		t.Error("'s' on a bound panel should return nil")
	}
	if cmd := p.key(rlKeyMsg("x")); cmd != nil {
		t.Error("'x' on a bound panel should return nil")
	}
}

func TestRateLimitDiscard(t *testing.T) {
	p := NewRateLimit(tui.Deps{})
	p.discard() // no server snapshot yet: must be a no-op, not a panic.

	server := client.SecurityLayers{}
	server.RateLimit.PerDay = 500
	p.server, p.haveSrv = client.SecurityLayersResponse{Layers: server}, true
	p.draft.RateLimit.PerDay = 1
	p.dirty = true

	p.discard()
	if p.draft.RateLimit.PerDay != 500 {
		t.Errorf("discard should revert to the server draft, got %d", p.draft.RateLimit.PerDay)
	}
	if p.dirty {
		t.Error("discard should clear dirty")
	}
	if p.status != "discarded" {
		t.Errorf("status = %q, want 'discarded'", p.status)
	}
}

func TestRateLimitAdjust(t *testing.T) {
	t.Run("without a draft, adjust is a no-op", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		p.adjust(1, 1)
		if p.dirty {
			t.Error("adjust without a draft should not mark the panel dirty")
		}
	})

	t.Run("on an anomaly row, adjust is a no-op", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		p.hasDraft = true
		p.insights.Anomalies = []rlAnomaly{{}}
		p.sel = 4 // first (and only) anomaly row
		p.adjust(1, 1)
		if p.dirty {
			t.Error("adjust on an anomaly row should not mark the panel dirty")
		}
	})

	t.Run("mode field cycles forward and wraps", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		p.hasDraft = true
		p.sel = 0
		for i, want := range []client.LayerMode{client.LayerDetect, client.LayerBlock, client.LayerOff} {
			p.adjust(1, 1)
			if p.draft.RateLimit.Mode != want {
				t.Errorf("after %d forward adjusts, mode = %q, want %q", i+1, p.draft.RateLimit.Mode, want)
			}
		}
	})

	t.Run("mode field cycles backward and wraps", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		p.hasDraft = true
		p.sel = 0
		p.adjust(-1, 1)
		if p.draft.RateLimit.Mode != client.LayerBlock {
			t.Errorf("one backward adjust from off = %q, want block", p.draft.RateLimit.Mode)
		}
	})

	t.Run("numeric fields clamp at zero", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		p.hasDraft = true
		p.sel = 2 // PerHour
		p.draft.RateLimit.PerHour = 5
		p.adjust(-1, 10)
		if p.draft.RateLimit.PerHour != 0 {
			t.Errorf("PerHour = %d, want clamped at 0", p.draft.RateLimit.PerHour)
		}
		p.sel = 3 // PerDay
		p.adjust(1, 7)
		if p.draft.RateLimit.PerDay != 7 {
			t.Errorf("PerDay = %d, want 7", p.draft.RateLimit.PerDay)
		}
	})
}

func TestRateLimitSaveRequiresDraftAndServer(t *testing.T) {
	p := NewRateLimit(tui.Deps{})
	if cmd := p.save(); cmd != nil {
		t.Error("save() without a draft or server snapshot should return nil")
	}
}

func TestRateLimitSavePersistsRateLimitSettings(t *testing.T) {
	c := rlHome(t)
	p := NewRateLimit(tui.Deps{Client: c})
	loaded := p.loadLayers()().(rlLayersMsg)
	if loaded.err != nil {
		t.Fatalf("loadLayers: %v", loaded.err)
	}
	p.server, p.haveSrv = loaded.data, true
	p.draft, p.hasDraft = loaded.data.Layers, true
	p.draft.RateLimit.Mode = client.LayerBlock
	p.draft.RateLimit.PerMinute = 9

	cmd := p.save()
	if cmd == nil {
		t.Fatal("save() should return a command once a draft and server exist")
	}
	saved := cmd().(rlSavedMsg)
	if saved.err != nil {
		t.Fatalf("save: %v", saved.err)
	}
	if saved.layers.RateLimit.PerMinute != 9 {
		t.Errorf("saved RateLimit.PerMinute = %d, want 9", saved.layers.RateLimit.PerMinute)
	}

	again := p.loadLayers()().(rlLayersMsg)
	if again.data.Layers.RateLimit.PerMinute != 9 {
		t.Errorf("rate limit settings did not persist: %+v", again.data.Layers.RateLimit)
	}
}