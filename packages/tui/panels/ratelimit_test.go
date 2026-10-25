// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

var errRLTestBoom = errors.New("boom")

func rlHome(t *testing.T) *client.Client {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return client.New()
}

func TestRateLimitSetBoundAndWantsLeft(t *testing.T) {
	p := NewRateLimit(tui.Deps{})
	sec := client.SecurityLayers{}
	sec.RateLimit.Mode = client.LayerBlock
	p.SetBound(sec, true)

	if !p.bound || !p.hasDraft || !p.dirty {
		t.Errorf("SetBound did not set expected flags: bound=%v hasDraft=%v dirty=%v", p.bound, p.hasDraft, p.dirty)
	}
	if p.Bound().RateLimit.Mode != client.LayerBlock {
		t.Errorf("Bound().RateLimit.Mode = %q, want block", p.Bound().RateLimit.Mode)
	}

	p.sel = 0
	if !p.WantsLeft() {
		t.Error("WantsLeft() on a field row (sel=0) should be true")
	}
	p.sel = 4 // first anomaly row, once any exist
	p.insights.Anomalies = []rlAnomaly{{Agent: "a"}}
	if p.WantsLeft() {
		t.Error("WantsLeft() on an anomaly row should be false")
	}
}

func TestRateLimitInit(t *testing.T) {
	t.Run("bound batches history, insights and the slow tick", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		p.bound = true
		cmd := p.Init(tui.PanelContext{Cols: 7, Rows: 9, Focused: true, Gen: 1})
		if cmd == nil {
			t.Fatal("expected a command")
		}
		msg := cmd()
		batch, ok := msg.(tea.BatchMsg)
		if !ok || len(batch) != 3 {
			t.Fatalf("Init() produced %T len=%d, want a 3-command batch", msg, len(batch))
		}
		if p.cols != 7 || p.rows != 9 || !p.focused || p.gen != 1 {
			t.Error("Init did not apply the panel context")
		}
	})

	t.Run("unbound batches layers, history, insights and both ticks", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		cmd := p.Init(tui.PanelContext{})
		msg := cmd()
		batch, ok := msg.(tea.BatchMsg)
		if !ok || len(batch) != 5 {
			t.Fatalf("Init() produced %T len=%d, want a 5-command batch", msg, len(batch))
		}
	})
}

func TestRateLimitLoaders(t *testing.T) {
	c := rlHome(t)
	p := NewRateLimit(tui.Deps{Client: c})

	layersMsg := p.loadLayers()().(rlLayersMsg)
	if layersMsg.err != nil {
		t.Fatalf("loadLayers: %v", layersMsg.err)
	}
	if layersMsg.data.Layers.RateLimit.Mode != client.LayerOff {
		t.Errorf("fresh machine rate limit mode = %q, want off", layersMsg.data.Layers.RateLimit.Mode)
	}

	historyMsg := p.loadHistory()().(rlHistoryMsg)
	if historyMsg.err != nil || len(historyMsg.data) != 0 {
		t.Errorf("loadHistory on a fresh machine = %+v, want empty with no error", historyMsg)
	}

	insightsMsg := p.loadInsights()().(rlInsightsMsg)
	if insightsMsg.err != nil {
		t.Errorf("loadInsights: %v", insightsMsg.err)
	}
}

func TestRateLimitUpdateLayersMsg(t *testing.T) {
	t.Run("success while clean adopts the draft", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		data := client.SecurityLayersResponse{}
		data.Layers.RateLimit.PerMinute = 42

		next, _ := p.Update(rlLayersMsg{data: data}, tui.PanelContext{})
		pp := next.(*RateLimit)
		if pp.loading {
			t.Error("loading should be cleared")
		}
		if !pp.haveSrv || !pp.hasDraft {
			t.Error("haveSrv and hasDraft should both be set")
		}
		if pp.draft.RateLimit.PerMinute != 42 {
			t.Errorf("draft.RateLimit.PerMinute = %d, want 42", pp.draft.RateLimit.PerMinute)
		}
	})

	t.Run("success while dirty keeps the local draft", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		p.dirty = true
		p.draft.RateLimit.PerMinute = 7
		p.hasDraft = true

		data := client.SecurityLayersResponse{}
		data.Layers.RateLimit.PerMinute = 42
		next, _ := p.Update(rlLayersMsg{data: data}, tui.PanelContext{})
		pp := next.(*RateLimit)
		if pp.draft.RateLimit.PerMinute != 7 {
			t.Errorf("a dirty draft should not be overwritten, got %d", pp.draft.RateLimit.PerMinute)
		}
		if !pp.haveSrv {
			t.Error("the server snapshot should still be recorded")
		}
	})

	t.Run("error sets loadErr", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		next, _ := p.Update(rlLayersMsg{err: errRLTestBoom}, tui.PanelContext{})
		pp := next.(*RateLimit)
		if pp.loadErr != errRLTestBoom {
			t.Errorf("loadErr = %v, want %v", pp.loadErr, errRLTestBoom)
		}
	})
}

func TestRateLimitUpdateHistoryAndInsightsMsg(t *testing.T) {
	p := NewRateLimit(tui.Deps{})
	history := []client.RateLimitChange{{Minute: 1}}
	next, _ := p.Update(rlHistoryMsg{data: history}, tui.PanelContext{})
	pp := next.(*RateLimit)
	if len(pp.history) != 1 {
		t.Errorf("history = %v, want 1 entry", pp.history)
	}

	next, _ = pp.Update(rlHistoryMsg{err: errRLTestBoom}, tui.PanelContext{})
	pp = next.(*RateLimit)
	if len(pp.history) != 1 {
		t.Error("a failed history reload should leave the previous history untouched")
	}

	var ins securityInsights
	ins.Peaks.Minute = 9
	next, _ = pp.Update(rlInsightsMsg{data: ins}, tui.PanelContext{})
	pp = next.(*RateLimit)
	if pp.insLoad {
		t.Error("insLoad should be cleared")
	}
	if pp.insights.Peaks.Minute != 9 {
		t.Errorf("insights.Peaks.Minute = %d, want 9", pp.insights.Peaks.Minute)
	}

	next, _ = pp.Update(rlInsightsMsg{err: errRLTestBoom}, tui.PanelContext{})
	pp = next.(*RateLimit)
	if pp.insErr != errRLTestBoom {
		t.Errorf("insErr = %v, want %v", pp.insErr, errRLTestBoom)
	}
}

func TestRateLimitUpdateSavedMsg(t *testing.T) {
	t.Run("success adopts the saved layers and reloads", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		p.dirty = true
		layers := client.SecurityLayers{}
		layers.RateLimit.PerHour = 11
		next, cmd := p.Update(rlSavedMsg{layers: layers}, tui.PanelContext{})
		pp := next.(*RateLimit)
		if pp.dirty {
			t.Error("a successful save should clear dirty")
		}
		if pp.status != "✓ Saved" {
			t.Errorf("status = %q", pp.status)
		}
		if pp.draft.RateLimit.PerHour != 11 {
			t.Errorf("draft.RateLimit.PerHour = %d, want 11", pp.draft.RateLimit.PerHour)
		}
		if cmd == nil {
			t.Error("a successful save should return a reload command")
		}
	})

	t.Run("error sets a status and returns no command", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		p.dirty = true
		next, cmd := p.Update(rlSavedMsg{err: errRLTestBoom}, tui.PanelContext{})
		pp := next.(*RateLimit)
		if !pp.dirty {
			t.Error("a failed save should leave dirty untouched")
		}
		if pp.status != "✗ "+errRLTestBoom.Error() {
			t.Errorf("status = %q", pp.status)
		}
		if cmd != nil {
			t.Error("a failed save should not return a command")
		}
	})
}

func TestRateLimitUpdateTickMsgs(t *testing.T) {
	t.Run("fast tick: stale token is ignored", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		_, cmd := p.Update(rlFastTickMsg{genTag{tok: p.tok + 1}}, tui.PanelContext{})
		if cmd != nil {
			t.Error("a stale fast tick should return no command")
		}
	})

	t.Run("fast tick while clean reloads layers", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		_, cmd := p.Update(rlFastTickMsg{genTag{tok: p.tok}}, tui.PanelContext{})
		if cmd == nil {
			t.Fatal("expected a batched command")
		}
		if _, ok := cmd().(tea.BatchMsg); !ok {
			t.Error("a clean fast tick should batch the rearm with a reload")
		}
	})

	t.Run("fast tick while dirty only rearms", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		p.dirty = true
		_, cmd := p.Update(rlFastTickMsg{genTag{tok: p.tok}}, tui.PanelContext{})
		if cmd == nil {
			t.Error("expected the rearmed tick command")
		}
	})

	t.Run("slow tick: stale token is ignored", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		_, cmd := p.Update(rlSlowTickMsg{genTag{tok: p.tok + 1}}, tui.PanelContext{})
		if cmd != nil {
			t.Error("a stale slow tick should return no command")
		}
	})

	t.Run("slow tick reloads history and insights", func(t *testing.T) {
		p := NewRateLimit(tui.Deps{})
		_, cmd := p.Update(rlSlowTickMsg{genTag{tok: p.tok}}, tui.PanelContext{})
		msg := cmd()
		batch, ok := msg.(tea.BatchMsg)
		if !ok || len(batch) != 3 {
			t.Fatalf("slow tick produced %T len=%d, want a 3-command batch", msg, len(batch))
		}
	})
}

func TestRateLimitUpdateKeyMsgDispatch(t *testing.T) {
	p := NewRateLimit(tui.Deps{})
	p.hasDraft = true
	next, _ := p.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")}, tui.PanelContext{Focused: false})
	if next.(*RateLimit).status != "" {
		t.Error("a key message while unfocused should not be dispatched")
	}

	p.haveSrv = true
	next, _ = p.Update(tea.KeyMsg{Type: tea.KeyRight}, tui.PanelContext{Focused: true})
	pp := next.(*RateLimit)
	if !pp.dirty {
		t.Error("a focused key message should reach key() and adjust the field")
	}
}

func TestRateLimitSortedAnomalies(t *testing.T) {
	p := NewRateLimit(tui.Deps{})
	original := []rlAnomaly{
		{Agent: "low-but-later", Count: 3, Minute: "2024-01-01T00:05:00Z"},
		{Agent: "high", Count: 10, Minute: "2024-01-01T00:00:00Z"},
		{Agent: "tie-earlier", Count: 5, Minute: "2024-01-01T00:00:00Z"},
		{Agent: "tie-later", Count: 5, Minute: "2024-01-01T00:10:00Z"},
	}
	p.insights.Anomalies = append([]rlAnomaly(nil), original...)

	got := p.sortedAnomalies()
	wantOrder := []string{"high", "tie-later", "tie-earlier", "low-but-later"}
	if len(got) != len(wantOrder) {
		t.Fatalf("got %d anomalies, want %d", len(got), len(wantOrder))
	}
	for i, name := range wantOrder {
		if got[i].Agent != name {
			t.Errorf("position %d = %q, want %q (full order: %v)", i, got[i].Agent, name, got)
		}
	}

	// The original slice (and its order) must be untouched.
	for i, a := range original {
		if p.insights.Anomalies[i] != a {
			t.Errorf("sortedAnomalies mutated the source slice at %d: got %+v, want %+v", i, p.insights.Anomalies[i], a)
		}
	}
}

func TestRateLimitBurstBudget(t *testing.T) {
	cases := []struct {
		name      string
		rows      int
		hasDraft  bool
		perMinute int
		want      int
	}{
		{"compact view floors at 1", 10, false, 0, 1},
		{"tiny view floors at 1", 5, false, 0, 1},
		{"expanded view without a per-minute load", 30, false, 0, 15},
		{"expanded view with a per-minute load adds one more row", 30, true, 5, 14},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewRateLimit(tui.Deps{})
			p.rows = tc.rows
			p.hasDraft = tc.hasDraft
			p.draft.RateLimit.PerMinute = tc.perMinute
			if got := p.burstBudget(); got != tc.want {
				t.Errorf("burstBudget() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRateLimitCursorHelpers(t *testing.T) {
	p := NewRateLimit(tui.Deps{})
	p.insights.Anomalies = []rlAnomaly{{}, {}}
	if got := p.cursorTotal(); got != 6 {
		t.Errorf("cursorTotal() = %d, want 6 (4 fields + 2 anomalies)", got)
	}

	p.sel = 100
	if got := p.selClamped(); got != 5 {
		t.Errorf("selClamped() = %d, want 5 (last valid index)", got)
	}

	cases := []struct {
		sel         int
		wantField   int
		wantCursorB int
	}{
		{0, 0, -1},
		{3, 3, -1},
		{4, -1, 0},
		{5, -1, 1},
	}
	for _, tc := range cases {
		p.sel = tc.sel
		if got := p.fieldIndex(); got != tc.wantField {
			t.Errorf("sel=%d fieldIndex() = %d, want %d", tc.sel, got, tc.wantField)
		}
		if got := p.burstCursor(); got != tc.wantCursorB {
			t.Errorf("sel=%d burstCursor() = %d, want %d", tc.sel, got, tc.wantCursorB)
		}
	}
}