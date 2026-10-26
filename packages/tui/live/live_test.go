// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package live

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/tui"
)

func TestNewLiveDefaults(t *testing.T) {
	a := newLive(tui.Deps{})
	if a.signal != "none" {
		t.Errorf("signal = %q, want %q", a.signal, "none")
	}
	if a.mode != "stream" {
		t.Errorf("mode = %q, want %q", a.mode, "stream")
	}
	if a.notified == nil {
		t.Error("notified map should be initialized, not nil")
	}
	if a.toastQueue == nil {
		t.Error("toastQueue map should be initialized, not nil")
	}

	b := newLive(tui.Deps{})
	if a.tok == b.tok {
		t.Error("two Live instances should receive distinct tokens from nextToken()")
	}
}

func TestLiveInitSchedulesAllPollsAndTicks(t *testing.T) {
	p := newLive(tui.Deps{})
	now := time.UnixMilli(1_700_000_000_000)
	ctx := tui.PanelContext{Cols: 80, Rows: 40, Gen: 7, Now: now}

	cmd := p.Init(ctx)

	if p.gen != 7 {
		t.Errorf("gen = %d, want 7", p.gen)
	}
	if p.openedAt != now.UnixMilli() {
		t.Errorf("openedAt = %d, want %d", p.openedAt, now.UnixMilli())
	}
	if !p.start.Equal(now) {
		t.Errorf("start = %v, want %v", p.start, now)
	}
	if cmd == nil {
		t.Fatal("Init should return a non-nil batch command")
	}

	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		t.Fatalf("Init cmd produced %T, want tea.BatchMsg", msg)
	}
	if len(batch) != 9 {
		t.Errorf("batch has %d commands, want 9 (4 polls + 5 ticks)", len(batch))
	}
}

func TestLivePaused(t *testing.T) {
	p := newLive(tui.Deps{})
	if p.paused() {
		t.Error("fresh Live should not be paused")
	}

	p.frozen = true
	if !p.paused() {
		t.Error("frozen Live should be paused")
	}

	p.frozen = false
	p.pausedUntil = time.Now().Add(time.Hour).UnixMilli()
	if !p.paused() {
		t.Error("Live with a future pausedUntil should be paused")
	}

	p.pausedUntil = time.Now().Add(-time.Hour).UnixMilli()
	if p.paused() {
		t.Error("Live with a past pausedUntil should not be paused")
	}
}

func TestLiveShouldPoll(t *testing.T) {
	cases := []struct {
		name        string
		frozen      bool
		pausedUntil int64
		kind        int
		want        bool
	}{
		{"tickLocal ignores pause, not frozen", false, time.Now().Add(time.Hour).UnixMilli(), tickLocal, true},
		{"tickLocal honors frozen", true, 0, tickLocal, false},
		{"tickStats honors pause", false, time.Now().Add(time.Hour).UnixMilli(), tickStats, false},
		{"tickStats polls when not paused", false, 0, tickStats, true},
		{"tickStats honors frozen too (paused() includes frozen)", true, 0, tickStats, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newLive(tui.Deps{})
			p.frozen = tc.frozen
			p.pausedUntil = tc.pausedUntil
			if got := p.shouldPoll(tc.kind); got != tc.want {
				t.Errorf("shouldPoll(%d) = %v, want %v", tc.kind, got, tc.want)
			}
		})
	}
}

func TestLiveUpdateSetsGenAndDispatchesKeyMsg(t *testing.T) {
	p := newLive(tui.Deps{})
	ctx := tui.PanelContext{Cols: 80, Rows: 40, Gen: 3, Now: time.UnixMilli(1_700_000_000_000)}

	_, _ = p.Update(tea.KeyMsg{Type: tea.KeySpace}, ctx)

	if p.gen != 3 {
		t.Errorf("gen = %d, want 3", p.gen)
	}
	if !p.frozen {
		t.Error("space key routed through Update should toggle frozen on")
	}
}

func TestLiveUpdateStaleTickIsIgnored(t *testing.T) {
	p := newLive(tui.Deps{})
	p.tok = 5
	ctx := tui.PanelContext{Now: time.UnixMilli(1_700_000_000_000)}

	_, cmd := p.Update(liveTick{tok: 1, kind: tickAnim}, ctx)

	if cmd != nil {
		t.Error("a tick carrying a stale token should produce no command")
	}
	if p.tick != 0 {
		t.Errorf("tick = %d, want 0 (stale tick should not advance animation)", p.tick)
	}
}

func TestLiveUpdateLocalResult(t *testing.T) {
	p := newLive(tui.Deps{})
	now := time.UnixMilli(1_700_000_000_000)
	ctx := tui.PanelContext{Now: now}

	setting := config.LocalLogSetting{Enabled: true, File: "whatever.jsonl"}
	ring := &ringStat{avgMs: 12, session: "s1", count: 4}
	lines := []tui.LocalLogLine{{Tool: "Read", At: now.UnixMilli() + 1000}}

	_, _ = p.Update(liveLocalResult{setting: setting, ring: ring, lines: lines}, ctx)

	if p.localSetting.File != "whatever.jsonl" {
		t.Errorf("localSetting.File = %q, want %q", p.localSetting.File, "whatever.jsonl")
	}
	if p.localOn == nil || !*p.localOn {
		t.Error("localOn should be a pointer to true")
	}
	if p.ring != ring {
		t.Error("ring should be adopted from the result")
	}
	if len(p.local) != 1 {
		t.Fatalf("len(local) = %d, want 1 (ingestLocal should have run)", len(p.local))
	}
	if len(p.merged) != 1 {
		t.Errorf("len(merged) = %d, want 1 (afterBuffers should rebuild merged)", len(p.merged))
	}
}

func TestLiveUpdateLocalResultSkipsIngestWhenNoLines(t *testing.T) {
	p := newLive(tui.Deps{})
	ctx := tui.PanelContext{Now: time.UnixMilli(1_700_000_000_000)}

	_, _ = p.Update(liveLocalResult{setting: config.LocalLogSetting{Enabled: false}}, ctx)

	if p.localOn == nil || *p.localOn {
		t.Error("localOn should be a pointer to false when setting.Enabled is false")
	}
	if len(p.local) != 0 {
		t.Errorf("len(local) = %d, want 0 when no lines were delivered", len(p.local))
	}
}

func TestLiveUpdateStatsResult(t *testing.T) {
	p := newLive(tui.Deps{})
	now := time.UnixMilli(1_700_000_000_000)
	ctx := tui.PanelContext{Now: now}

	_, _ = p.Update(liveStatsResult{err: &client.Error{Status: 500, Message: "boom"}}, ctx)
	if p.stats != nil {
		t.Error("stats should not be set when the result carries an error")
	}
	if n := len(p.events); n == 0 {
		t.Error("an api error should push a log line")
	} else if p.events[n-1].level != "bad" {
		t.Errorf("event level = %q, want %q", p.events[n-1].level, "bad")
	}

	_, _ = p.Update(liveStatsResult{stats: client.Stats{TotalCalls: 9}}, ctx)
	if p.stats == nil || p.stats.TotalCalls != 9 {
		t.Error("stats should be adopted on success")
	}
}

func TestLiveUpdateInsightsResult(t *testing.T) {
	p := newLive(tui.Deps{})
	ctx := tui.PanelContext{Now: time.UnixMilli(1_700_000_000_000)}

	_, _ = p.Update(liveInsightsResult{err: &client.Error{Status: 0}}, ctx)
	if p.insightsLoaded {
		t.Error("insightsLoaded should stay false on error")
	}

	bits := insightsBits{}
	bits.DLPByPattern = []insightsPatternHit{{Pattern: "ssn", Count: 2}}
	_, _ = p.Update(liveInsightsResult{bits: bits}, ctx)
	if !p.insightsLoaded {
		t.Error("insightsLoaded should become true on success")
	}
	if len(p.insights.DLPByPattern) != 1 {
		t.Error("insights should be adopted from the result on success")
	}
}

func TestLiveUpdateGuardResult(t *testing.T) {
	p := newLive(tui.Deps{})
	ctx := tui.PanelContext{Now: time.UnixMilli(1_700_000_000_000)}

	_, _ = p.Update(liveGuardResult{err: &client.Error{Status: 500}}, ctx)
	if p.guard != nil {
		t.Error("guard should not be set when the result carries an error")
	}

	_, _ = p.Update(liveGuardResult{status: client.GuardStatus{Latest: 3, DeviceCount: 2}}, ctx)
	if p.guard == nil || p.guard.Latest != 3 || p.guard.DeviceCount != 2 {
		t.Error("guard should be adopted on success")
	}
}

func TestLiveUpdateActionResult(t *testing.T) {
	p := newLive(tui.Deps{})
	now := time.UnixMilli(1_700_000_000_000)
	ctx := tui.PanelContext{Now: now}

	_, _ = p.Update(liveActionResult{text: "done", level: "ok"}, ctx)
	if p.action == nil || p.action.text != "done" || p.action.until != now.UnixMilli()+7000 {
		t.Error("action flash should be populated from the result")
	}
	if len(p.events) != 0 {
		t.Error("an empty logText should not push a log line")
	}

	_, _ = p.Update(liveActionResult{text: "done2", logText: "logged", logLevel: "warn"}, ctx)
	if n := len(p.events); n != 1 {
		t.Fatalf("len(events) = %d, want 1 once logText is non-empty", n)
	} else if p.events[0].msg != "logged" || p.events[0].level != "warn" {
		t.Errorf("event = %+v, want msg=logged level=warn", p.events[0])
	}
}

func TestLiveUpdateUnknownMessageIsNoop(t *testing.T) {
	p := newLive(tui.Deps{})
	ctx := tui.PanelContext{Gen: 2, Now: time.UnixMilli(1_700_000_000_000)}

	panel, cmd := p.Update("not a recognized message", ctx)
	if cmd != nil {
		t.Error("unknown message types should produce no command")
	}
	if panel != p {
		t.Error("Update should return the same panel instance for unknown messages")
	}
}

func TestLiveChartHeight(t *testing.T) {
	p := newLive(tui.Deps{})
	if got := p.chartHeight(tui.PanelContext{Rows: 34}); got != 4 {
		t.Errorf("chartHeight(34) = %d, want 4", got)
	}
	if got := p.chartHeight(tui.PanelContext{Rows: 35}); got != 6 {
		t.Errorf("chartHeight(35) = %d, want 6", got)
	}
}

func TestLiveColHeight(t *testing.T) {
	p := newLive(tui.Deps{})
	if got := p.colHeight(tui.PanelContext{Rows: 30}); got != 5 {
		t.Errorf("colHeight(30) = %d, want 5", got)
	}
	if got := p.colHeight(tui.PanelContext{Rows: 31}); got != 7 {
		t.Errorf("colHeight(31) = %d, want 7", got)
	}
}

func TestLiveBannerRows(t *testing.T) {
	now := int64(1_700_000_000_000)
	cases := []struct {
		name   string
		alerts []alertBanner
		action *flashMsg
		want   int
	}{
		{"nothing active", nil, nil, 0},
		{"alert only", []alertBanner{{until: now + 1000}}, nil, 1},
		{"action only", nil, &flashMsg{until: now + 1000}, 1},
		{"both active", []alertBanner{{until: now + 1000}}, &flashMsg{until: now + 1000}, 2},
		{"expired alert and action don't count", []alertBanner{{until: now - 1}}, &flashMsg{until: now - 1}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newLive(tui.Deps{})
			p.alerts = tc.alerts
			p.action = tc.action
			if got := p.bannerRows(now); got != tc.want {
				t.Errorf("bannerRows() = %d, want %d", got, tc.want)
			}
		})
	}
}