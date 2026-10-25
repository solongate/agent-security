// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package live

import (
	"testing"
	"time"

	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/tui"
)

func TestInsightsRateLimitMode(t *testing.T) {
	var nilPtr *insightsRateLimit
	if got := nilPtr.mode(); got != "" {
		t.Errorf("nil.mode() = %q, want empty", got)
	}
	r := &insightsRateLimit{Mode: "block"}
	if got := r.mode(); got != "block" {
		t.Errorf("mode() = %q, want %q", got, "block")
	}
}

func TestInsightsDLPMode(t *testing.T) {
	var nilPtr *insightsDLP
	if got := nilPtr.mode(); got != "" {
		t.Errorf("nil.mode() = %q, want empty", got)
	}
	d := &insightsDLP{Mode: "redact"}
	if got := d.mode(); got != "redact" {
		t.Errorf("mode() = %q, want %q", got, "redact")
	}
}

func TestInsightsRateLimitSummaryNoLimits(t *testing.T) {
	var nilPtr *insightsRateLimit
	if got := nilPtr.summary(5); got != "no limits set" {
		t.Errorf("nil.summary() = %q, want %q", got, "no limits set")
	}
	zero := &insightsRateLimit{}
	if got := zero.summary(5); got != "no limits set" {
		t.Errorf("zero PerMinute summary() = %q, want %q", got, "no limits set")
	}
}

// TestInsightsRateLimitSummaryZeroLimitRendersDash guards against a
// regression in orDash (live_view.go), which renders a placeholder for a
// zero limit and must produce "-", not a stray ", ".
func TestInsightsRateLimitSummaryZeroLimitRendersDash(t *testing.T) {
	r := &insightsRateLimit{PerMinute: 10, PerHour: 0, PerDay: 5}
	want := "3/10m -h 5d"
	if got := r.summary(3); got != want {
		t.Errorf("summary() = %q, want %q", got, want)
	}
}

func TestInsightsRateLimitSummaryWithAllLimits(t *testing.T) {
	r := &insightsRateLimit{PerMinute: 10, PerHour: 100, PerDay: 1000}
	want := "7/10m 100h 1000d"
	if got := r.summary(7); got != want {
		t.Errorf("summary() = %q, want %q", got, want)
	}
}

func TestBeatIdleAndActive(t *testing.T) {
	p := &Live{}
	now := int64(1_700_000_000_000)

	p.beat(now)
	if n := len(p.events); n != 1 || p.events[0].msg != "idle" {
		t.Fatalf("events = %+v, want a single idle event", p.events)
	}
	if len(p.pulse) != 1 || p.pulse[0] != 0 {
		t.Errorf("pulse = %v, want [0]", p.pulse)
	}

	p.pulsePending, p.pulseCalls = 42, 1
	p.beat(now)
	if got := p.events[len(p.events)-1].msg; got != "42ms · 1 call" {
		t.Errorf("single-call message = %q, want %q", got, "42ms · 1 call")
	}

	p.pulsePending, p.pulseCalls = 99, 3
	p.beat(now)
	if got := p.events[len(p.events)-1].msg; got != "99ms · 3 calls" {
		t.Errorf("multi-call message = %q, want %q", got, "99ms · 3 calls")
	}

	if p.pulsePending != 0 || p.pulseCalls != 0 {
		t.Error("beat should reset pulsePending and pulseCalls")
	}
}

func TestBeatCapsPulseHistory(t *testing.T) {
	p := &Live{pulse: make([]int, 400)}
	for i := range p.pulse {
		p.pulse[i] = i
	}
	p.beat(0)
	if len(p.pulse) != 400 {
		t.Fatalf("len(pulse) = %d, want 400 (capped)", len(p.pulse))
	}
	if p.pulse[0] != 1 {
		t.Errorf("pulse[0] = %d, want 1 (oldest entry dropped)", p.pulse[0])
	}
	if p.pulse[399] != 0 {
		t.Errorf("pulse[399] = %d, want 0 (freshly appended idle sample)", p.pulse[399])
	}
}

func TestPushLogCapsAt60(t *testing.T) {
	p := &Live{}
	for i := 0; i < 60; i++ {
		p.pushLog("m", "info", int64(i))
	}
	p.pushLog("newest", "info", 999)
	if len(p.events) != 60 {
		t.Fatalf("len(events) = %d, want 60", len(p.events))
	}
	if p.events[0].ts != 1 {
		t.Errorf("events[0].ts = %d, want 1 (oldest dropped)", p.events[0].ts)
	}
	if p.events[59].msg != "newest" {
		t.Errorf("events[59].msg = %q, want %q", p.events[59].msg, "newest")
	}
}

func TestRebuildMergedSortsByAtStably(t *testing.T) {
	p := &Live{local: []streamItem{
		{ID: "a", At: 5},
		{ID: "b", At: 5},
		{ID: "c", At: 1},
	}}
	p.rebuildMerged(0)
	want := []string{"c", "a", "b"}
	if len(p.merged) != len(want) {
		t.Fatalf("len(merged) = %d, want %d", len(p.merged), len(want))
	}
	for i, id := range want {
		if p.merged[i].ID != id {
			t.Errorf("merged[%d].ID = %q, want %q (stable order for equal At)", i, p.merged[i].ID, id)
		}
	}
}

func baseCtx(now int64, notifications bool) tui.PanelContext {
	return tui.PanelContext{
		Deps: tui.Deps{Cfg: config.TUIConfig{Notifications: notifications}},
		Now:  time.UnixMilli(now),
	}
}

func TestFireAlertPrefixByLevel(t *testing.T) {
	p := &Live{toastQueue: map[string]*toastItem{}}
	ctx := baseCtx(1000, false)

	p.fireAlert("id1", "title", "bad thing", "bad", false, ctx)
	p.fireAlert("id2", "title2", "warn thing", "warn", false, ctx)

	if p.events[0].msg != "⛔ bad thing" {
		t.Errorf("bad-level message = %q, want prefix ⛔", p.events[0].msg)
	}
	if p.events[1].msg != "⏸ warn thing" {
		t.Errorf("non-bad-level message = %q, want prefix ⏸", p.events[1].msg)
	}
}

func TestFireAlertDedupesByID(t *testing.T) {
	p := &Live{toastQueue: map[string]*toastItem{}}
	ctx := baseCtx(1000, false)

	p.fireAlert("dup", "t", "first", "warn", false, ctx)
	p.fireAlert("dup", "t", "second", "warn", false, ctx)

	if len(p.alerts) != 1 {
		t.Fatalf("len(alerts) = %d, want 1 (same id should replace, not accumulate)", len(p.alerts))
	}
	if p.alerts[0].msg != "second" {
		t.Errorf("alerts[0].msg = %q, want %q", p.alerts[0].msg, "second")
	}
}

func TestFireAlertCapsAtFour(t *testing.T) {
	p := &Live{toastQueue: map[string]*toastItem{}}
	ctx := baseCtx(1000, false)

	for i := 0; i < 5; i++ {
		p.fireAlert(string(rune('a'+i)), "t", "m", "warn", false, ctx)
	}
	if len(p.alerts) != 4 {
		t.Fatalf("len(alerts) = %d, want 4", len(p.alerts))
	}
	if p.alerts[0].id != "b" {
		t.Errorf("alerts[0].id = %q, want %q (oldest alert should be evicted)", p.alerts[0].id, "b")
	}
}

func TestFireAlertSkipsToastWhenNotDesktopOrDisabled(t *testing.T) {
	p := &Live{toastQueue: map[string]*toastItem{}}

	if cmd := p.fireAlert("id", "t", "m", "warn", false, baseCtx(1000, true)); cmd != nil {
		t.Error("desktop=false should never schedule a toast")
	}
	if len(p.toastQueue) != 0 {
		t.Error("toastQueue should stay empty when desktop is false")
	}

	if cmd := p.fireAlert("id2", "t", "m", "warn", true, baseCtx(1000, false)); cmd != nil {
		t.Error("Cfg.Notifications=false should never schedule a toast")
	}
	if len(p.toastQueue) != 0 {
		t.Error("toastQueue should stay empty when notifications are disabled")
	}
}

func TestFireAlertQueuesToastsAndDebouncesTicks(t *testing.T) {
	p := &Live{toastQueue: map[string]*toastItem{}}
	ctx := baseCtx(1000, true)

	cmd1 := p.fireAlert("id1", "Call denied", "m1", "bad", true, ctx)
	if cmd1 == nil {
		t.Fatal("first queued toast should arm a flush tick")
	}
	if !p.toastPending {
		t.Error("toastPending should be true after arming the flush tick")
	}
	if len(p.toastOrder) != 1 || p.toastQueue["Call denied"].count != 1 {
		t.Errorf("toastQueue/toastOrder not populated as expected: %v %+v", p.toastOrder, p.toastQueue)
	}

	cmd2 := p.fireAlert("id2", "Rate-limit burst", "m2", "warn", true, ctx)
	if cmd2 != nil {
		t.Error("a second toast while one is already pending should not arm another tick")
	}
	if len(p.toastOrder) != 2 {
		t.Errorf("len(toastOrder) = %d, want 2", len(p.toastOrder))
	}

	cmd3 := p.fireAlert("id3", "Call denied", "m3", "bad", true, ctx)
	if cmd3 != nil {
		t.Error("still pending, so no new tick should be armed")
	}
	if len(p.toastOrder) != 2 {
		t.Errorf("len(toastOrder) = %d, want 2 (repeated title should not grow toastOrder)", len(p.toastOrder))
	}
	if p.toastQueue["Call denied"].count != 2 {
		t.Errorf("toastQueue[Call denied].count = %d, want 2", p.toastQueue["Call denied"].count)
	}
}

func TestFlushToastsEmptyQueue(t *testing.T) {
	p := &Live{toastPending: true}
	if cmd := p.flushToasts(1000); cmd != nil {
		t.Error("flushing an empty queue should produce no command")
	}
	if p.toastPending {
		t.Error("flushToasts should always clear toastPending")
	}
}

func TestFlushToastsReArmsWhenDebounceWindowStillOpen(t *testing.T) {
	p := &Live{
		toastQueue:   map[string]*toastItem{"DLP hit": {count: 1, msg: "x"}},
		toastOrder:   []string{"DLP hit"},
		lastNotifyAt: 1000,
	}
	// wait = 3000 - (now - lastNotifyAt) = 3000 - 500 = 2500 > 0: must re-arm
	// rather than fire immediately (which would reach the desktopNotify call).
	cmd := p.flushToasts(1500)
	if cmd == nil {
		t.Fatal("flushToasts should re-arm a tick while still inside the debounce window")
	}
	if !p.toastPending {
		t.Error("toastPending should be re-armed (true) while waiting out the debounce window")
	}
	if len(p.toastOrder) != 1 || len(p.toastQueue) != 1 {
		t.Error("the queue should be left untouched while waiting out the debounce window")
	}
}

func TestActiveAlert(t *testing.T) {
	p := &Live{alerts: []alertBanner{
		{id: "a", until: 100},
		{id: "b", until: 200},
		{id: "c", until: 50},
	}}
	if got := p.activeAlert(150); got == nil || got.id != "b" {
		t.Errorf("activeAlert(150) = %+v, want id=b", got)
	}
	if got := p.activeAlert(250); got != nil {
		t.Errorf("activeAlert(250) = %+v, want nil (all expired)", got)
	}
}

func TestActiveAction(t *testing.T) {
	p := &Live{}
	if got := p.activeAction(100); got != nil {
		t.Error("nil action should stay nil")
	}
	p.action = &flashMsg{until: 100}
	if got := p.activeAction(50); got == nil {
		t.Error("an unexpired action should be returned")
	}
	if got := p.activeAction(150); got != nil {
		t.Error("an expired action should be nil")
	}
}

func TestNotifySecurityEvents(t *testing.T) {
	const openedAt = int64(1_700_000_000_000)
	p := &Live{
		notified:   map[string]bool{},
		toastQueue: map[string]*toastItem{},
		openedAt:   openedAt,
		merged: []streamItem{
			{ID: "1", Decision: "ALLOW", At: openedAt + 100}, // not DLP/burst/deny: ignored entirely
			{ID: "2", Decision: "ALLOW", DLP: true, Tool: "Read", Agent: "agentX", Detail: "ssn 123", At: openedAt + 200},
			{ID: "3", Decision: "DENY", Tool: "Write", Rule: "rule-1", Detail: "ignored because Rule wins", At: openedAt + 300},
			{ID: "4", Decision: "DENY", Tool: "Write", Detail: "no rule given", At: openedAt + 400},
			{ID: "5", Decision: "ALLOW", Burst: true, Tool: "Exec", At: openedAt + 500},
			{ID: "6", Decision: "DENY", Tool: "Old", At: openedAt},                         // At <= openedAt: marked notified, no alert
			{ID: "3", Decision: "DENY", Tool: "Write", Rule: "rule-1", At: openedAt + 300}, // duplicate id "3"
		},
	}
	ctx := baseCtx(openedAt+1000, false)

	p.notifySecurityEvents(ctx)

	for _, id := range []string{"2", "3", "4", "5", "6"} {
		if !p.notified[id] {
			t.Errorf("event %q should be marked notified", id)
		}
	}
	if p.notified["1"] {
		t.Error("a plain ALLOW with no DLP/burst should never be marked notified")
	}

	byID := map[string]alertBanner{}
	for _, a := range p.alerts {
		byID[a.id] = a
	}
	if len(p.alerts) != 4 {
		t.Fatalf("len(alerts) = %d, want 4 (events 2,3,4,5; 6 is pre-opened, 3 is a duplicate)", len(p.alerts))
	}

	dlp, ok := byID["sec:2"]
	if !ok || dlp.msg != "SECRET in Read · agentX: ssn 123" {
		t.Errorf("DLP alert = %+v, want msg about SECRET in Read · agentX", dlp)
	}
	denyRule, ok := byID["sec:3"]
	if !ok || denyRule.msg != "DENY Write: rule-1" {
		t.Errorf("deny-with-rule alert = %+v, want DENY Write: rule-1", denyRule)
	}
	denyDetail, ok := byID["sec:4"]
	if !ok || denyDetail.msg != "DENY Write: no rule given" {
		t.Errorf("deny-without-rule alert = %+v, want detail fallback", denyDetail)
	}
	burst, ok := byID["sec:5"]
	if !ok || burst.msg != "BURST Exec" {
		t.Errorf("burst alert = %+v, want BURST Exec", burst)
	}
	if _, ok := byID["sec:6"]; ok {
		t.Error("an event at/before openedAt should never produce an alert")
	}
}