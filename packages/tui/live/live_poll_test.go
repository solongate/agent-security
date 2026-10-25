// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package live

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

func f64(v float64) *float64 { return &v }

func TestIngestLocalDefaultsAndDetailFallback(t *testing.T) {
	p := &Live{}
	p.ingestLocal([]tui.LocalLogLine{{At: 100, Reason: "something happened"}})

	if len(p.local) != 1 {
		t.Fatalf("len(local) = %d, want 1", len(p.local))
	}
	item := p.local[0]
	if item.Tool != "?" {
		t.Errorf("Tool = %q, want default %q", item.Tool, "?")
	}
	if item.Decision != "ALLOW" {
		t.Errorf("Decision = %q, want default %q", item.Decision, "ALLOW")
	}
	if item.Detail != "something happened" {
		t.Errorf("Detail = %q, want the Reason fallback", item.Detail)
	}
	if p.lastLocalTS != 100 {
		t.Errorf("lastLocalTS = %d, want 100", p.lastLocalTS)
	}
}

func TestIngestLocalArgumentsPreferredOverReason(t *testing.T) {
	p := &Live{}
	p.ingestLocal([]tui.LocalLogLine{{At: 100, Tool: "Read", Arguments: []byte(`{"a":1}`), Reason: "ignored"}})

	if got := p.local[0].Detail; got != `{"a":1}` {
		t.Errorf("Detail = %q, want the raw Arguments", got)
	}
}

func TestIngestLocalNullArgumentsFallBackToReason(t *testing.T) {
	p := &Live{}
	p.ingestLocal([]tui.LocalLogLine{{At: 100, Arguments: []byte("null"), Reason: "fallback reason"}})

	if got := p.local[0].Detail; got != "fallback reason" {
		t.Errorf("Detail = %q, want the Reason fallback when Arguments is literal null", got)
	}
}

func TestIngestLocalDLPNamesFromJSON(t *testing.T) {
	p := &Live{}
	p.ingestLocal([]tui.LocalLogLine{{At: 100, DLP: []byte(`["ssn","email"]`)}})

	item := p.local[0]
	if !item.DLP {
		t.Error("DLP should be true for a non-empty, non-null/false DLP payload")
	}
	if len(item.DLPNames) != 2 || item.DLPNames[0] != "ssn" || item.DLPNames[1] != "email" {
		t.Errorf("DLPNames = %v, want [ssn email]", item.DLPNames)
	}
}

func TestIngestLocalDLPFalseLiteralFallsBackToReasonSignals(t *testing.T) {
	p := &Live{}
	p.ingestLocal([]tui.LocalLogLine{{
		At:     100,
		DLP:    []byte("false"),
		Reason: "blocked by security layer (dlp): contains a SSN.",
	}})

	item := p.local[0]
	// json.Unmarshal("false", &[]string{}) fails, so dlpNames stays empty and
	// falls back to tui.ReasonSignals. The DLP bool itself stays false
	// because the literal "false" payload is explicitly excluded.
	if item.DLP {
		t.Error("DLP bool should be false for the literal \"false\" payload")
	}
	if len(item.DLPNames) != 1 || item.DLPNames[0] != "SSN" {
		t.Errorf("DLPNames = %v, want [SSN] from the reason-signal fallback", item.DLPNames)
	}
}

func TestIngestLocalBurstFromRateLimitFlagOrReason(t *testing.T) {
	p := &Live{}
	p.ingestLocal([]tui.LocalLogLine{
		{At: 100, RateLimitBurst: true},
		{At: 200, Reason: "blocked by security layer (rate limit): exceeded 5 calls"},
		{At: 300},
	})

	if !p.local[0].Burst {
		t.Error("RateLimitBurst=true should set Burst")
	}
	if !p.local[1].Burst {
		t.Error("a rate-limit reason should set Burst via ReasonSignals")
	}
	if p.local[2].Burst {
		t.Error("no flag and no matching reason should leave Burst false")
	}
}

func TestIngestLocalSkipsStaleLines(t *testing.T) {
	p := &Live{lastLocalTS: 500}
	p.ingestLocal([]tui.LocalLogLine{{At: 400}, {At: 600}})

	if len(p.local) != 1 || p.local[0].At != 600 {
		t.Fatalf("local = %+v, want only the At=600 line", p.local)
	}
	if p.lastLocalTS != 600 {
		t.Errorf("lastLocalTS = %d, want 600", p.lastLocalTS)
	}
}

func TestIngestLocalAllStaleIsNoop(t *testing.T) {
	p := &Live{lastLocalTS: 500}
	p.ingestLocal([]tui.LocalLogLine{{At: 100}, {At: 200}})

	if len(p.local) != 0 {
		t.Errorf("local = %+v, want untouched", p.local)
	}
	if p.lastLocalTS != 500 {
		t.Errorf("lastLocalTS = %d, want unchanged 500", p.lastLocalTS)
	}
}

func TestIngestLocalBackfillDoesNotMovePulseButLivePollDoes(t *testing.T) {
	p := &Live{}
	// First call: lastLocalTS starts at 0, so this is a "backfill" and must
	// not disturb the pulse counters used for the live activity indicator.
	p.ingestLocal([]tui.LocalLogLine{{At: 100, EvaluationTimeMs: f64(50)}})
	if p.pulsePending != 0 || p.pulseCalls != 0 {
		t.Errorf("backfill should not touch pulse counters, got pending=%d calls=%d", p.pulsePending, p.pulseCalls)
	}
	if len(p.eval) != 1 || p.eval[0] != 50 {
		t.Errorf("eval = %v, want [50] even during backfill", p.eval)
	}

	// Second call: lastLocalTS is now non-zero, so new lines count toward
	// the live pulse.
	p.ingestLocal([]tui.LocalLogLine{{At: 200, EvaluationTimeMs: f64(80)}})
	if p.pulsePending != 80 || p.pulseCalls != 1 {
		t.Errorf("post-backfill pulse = pending=%d calls=%d, want pending=80 calls=1", p.pulsePending, p.pulseCalls)
	}
}

func TestIngestLocalCapsLocalAt400(t *testing.T) {
	p := &Live{lastLocalTS: 395}
	p.local = make([]streamItem, 395)
	for i := range p.local {
		p.local[i] = streamItem{At: int64(i + 1)}
	}
	var fresh []tui.LocalLogLine
	for i := 396; i <= 405; i++ {
		fresh = append(fresh, tui.LocalLogLine{At: int64(i)})
	}
	p.ingestLocal(fresh)

	if len(p.local) != 400 {
		t.Fatalf("len(local) = %d, want 400 (capped)", len(p.local))
	}
	if p.local[0].At != 6 {
		t.Errorf("local[0].At = %d, want 6 (oldest entries evicted)", p.local[0].At)
	}
}

func TestIngestLocalCapsEvalAt240(t *testing.T) {
	p := &Live{lastLocalTS: 1000}
	p.eval = make([]int, 235)
	for i := range p.eval {
		p.eval[i] = i
	}
	var fresh []tui.LocalLogLine
	for i := 0; i < 10; i++ {
		fresh = append(fresh, tui.LocalLogLine{At: int64(1001 + i), EvaluationTimeMs: f64(float64(i))})
	}
	p.ingestLocal(fresh)

	if len(p.eval) != 240 {
		t.Fatalf("len(eval) = %d, want 240 (capped)", len(p.eval))
	}
	if p.eval[0] != 5 {
		t.Errorf("eval[0] = %d, want 5 (oldest entries evicted)", p.eval[0])
	}
}

func TestAfterBuffersRebuildsMergedAndBatchesNotifications(t *testing.T) {
	ctx := tui.PanelContext{Now: time.UnixMilli(1_000_000)}

	quiet := &Live{notified: map[string]bool{}, local: []streamItem{{ID: "a", At: 5, Decision: "ALLOW"}}}
	if cmd := quiet.afterBuffers(ctx); cmd != nil {
		t.Error("afterBuffers should produce a nil command when nothing needs to notify")
	}
	if len(quiet.merged) != 1 {
		t.Errorf("merged = %v, want it rebuilt from local", quiet.merged)
	}

	// fireAlert only returns a non-nil command once desktop notifications are
	// enabled in the config (otherwise the alert is still recorded, but the
	// toast-debounce command collapses to nil). Enable it here so the DENY
	// path actually exercises the command it returns.
	noisyCtx := ctx
	noisyCtx.Cfg.Notifications = true
	noisy := &Live{
		notified:   map[string]bool{},
		toastQueue: map[string]*toastItem{},
		local:      []streamItem{{ID: "b", At: 5, Decision: "DENY"}},
	}
	if cmd := noisy.afterBuffers(noisyCtx); cmd == nil {
		t.Error("afterBuffers should produce a command when a deny needs to notify and notifications are enabled")
	}
	if !noisy.notified["b"] {
		t.Error("the deny event should be marked as notified")
	}
}

func TestApiErrorRateLimited(t *testing.T) {
	p := &Live{}
	now := int64(1000)
	p.apiError(&client.Error{Status: 429}, now)

	if p.pausedUntil != now+30_000 {
		t.Errorf("pausedUntil = %d, want %d", p.pausedUntil, now+30_000)
	}
	if n := len(p.events); n != 1 || !strings.Contains(p.events[0].msg, "rate limited") {
		t.Fatalf("events = %+v, want a single rate-limited log line", p.events)
	}

	// While still paused, a repeat 429 should be silently ignored.
	p.apiError(&client.Error{Status: 429}, now+1000)
	if len(p.events) != 1 {
		t.Errorf("events = %+v, want unchanged while already paused", p.events)
	}
}

func TestApiErrorNetworkFailureLogsOnThirdOccurrence(t *testing.T) {
	p := &Live{}
	for i := 1; i <= 2; i++ {
		p.apiError(&client.Error{Status: 0}, int64(i))
		if len(p.events) != 0 {
			t.Fatalf("after %d network failures, events = %+v, want none yet", i, p.events)
		}
	}
	p.apiError(&client.Error{Status: 0}, 3)
	if n := len(p.events); n != 1 || !strings.Contains(p.events[0].msg, "network unreachable") {
		t.Fatalf("events after 3rd failure = %+v, want a network-unreachable log line", p.events)
	}
	if p.netFails != 3 {
		t.Errorf("netFails = %d, want 3", p.netFails)
	}
}

func TestApiErrorGenericLogsImmediately(t *testing.T) {
	p := &Live{}
	p.apiError(&client.Error{Status: 500, Message: "server exploded"}, 1000)
	if n := len(p.events); n != 1 || !strings.Contains(p.events[0].msg, "server exploded") {
		t.Fatalf("events = %+v, want a log line mentioning the error", p.events)
	}
	if p.events[0].level != "bad" {
		t.Errorf("level = %q, want bad", p.events[0].level)
	}
}

func TestApiErrorNonClientErrorType(t *testing.T) {
	p := &Live{}
	p.apiError(errPlain("boom"), 1000)
	if n := len(p.events); n != 1 || !strings.Contains(p.events[0].msg, "boom") {
		t.Fatalf("events = %+v, want a log line mentioning the plain error", p.events)
	}
}

type errPlain string

func (e errPlain) Error() string { return string(e) }

func TestTickCmdCarriesGenTokKind(t *testing.T) {
	p := &Live{gen: 3, tok: 9}
	cmd := p.tickCmd(tickStats, time.Millisecond)
	msg, ok := cmd().(liveTick)
	if !ok {
		t.Fatalf("tickCmd produced %T, want liveTick", msg)
	}
	if msg.gen != 3 || msg.tok != 9 || msg.kind != tickStats {
		t.Errorf("liveTick = %+v, want gen=3 tok=9 kind=tickStats", msg)
	}
}

func TestCadenceSkipsPollWhenShouldNotPoll(t *testing.T) {
	p := &Live{gen: 1, tok: 1, frozen: true}
	stub := func() tea.Cmd { return func() tea.Msg { return "should not run" } }

	cmd := p.cadence(tickLocal, time.Millisecond, stub)
	msg := cmd()
	if _, ok := msg.(liveTick); !ok {
		t.Fatalf("cadence while frozen produced %T, want a bare liveTick (poll skipped)", msg)
	}
}

func TestCadenceBatchesPollWhenShouldPoll(t *testing.T) {
	p := &Live{gen: 1, tok: 1}
	stub := func() tea.Cmd { return func() tea.Msg { return "stub result" } }

	cmd := p.cadence(tickStats, time.Millisecond, stub)
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	if !ok || len(batch) != 2 {
		t.Fatalf("cadence while active produced %T (len %v), want a 2-command batch", msg, msg)
	}
}

func TestOnTickStaleTokenIsIgnored(t *testing.T) {
	p := &Live{tok: 5}
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}
	if cmd := p.onTick(liveTick{tok: 1, kind: tickAnim}, ctx); cmd != nil {
		t.Error("a tick with a stale token should produce no command")
	}
	if p.tick != 0 {
		t.Errorf("tick = %d, want 0", p.tick)
	}
}

func TestOnTickAnimFrozenReArmsWithoutAdvancing(t *testing.T) {
	p := &Live{tok: 1, frozen: true}
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}
	cmd := p.onTick(liveTick{tok: 1, kind: tickAnim}, ctx)
	if cmd == nil {
		t.Fatal("frozen anim tick should still re-arm the next tick")
	}
	if p.tick != 0 {
		t.Errorf("tick = %d, want 0 while frozen", p.tick)
	}
}

func TestOnTickAnimAdvancesAndBeatsEveryTenth(t *testing.T) {
	p := &Live{tok: 1}
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}
	for i := 0; i < 10; i++ {
		p.onTick(liveTick{tok: 1, kind: tickAnim}, ctx)
	}
	if p.tick != 10 {
		t.Fatalf("tick = %d, want 10", p.tick)
	}
	if len(p.events) != 1 {
		t.Errorf("events = %+v, want exactly one beat logged at the 10th tick", p.events)
	}
}

func TestOnTickToastWithEmptyQueueIsNoop(t *testing.T) {
	p := &Live{tok: 1}
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}
	if cmd := p.onTick(liveTick{tok: 1, kind: tickToast}, ctx); cmd != nil {
		t.Error("flushing an empty toast queue should produce no command")
	}
}

func TestOnTickPollKindDispatchesThroughCadence(t *testing.T) {
	p := newLive(tui.Deps{})
	p.tok = 1
	ctx := tui.PanelContext{Now: time.UnixMilli(1000)}
	cmd := p.onTick(liveTick{tok: 1, kind: tickLocal}, ctx)
	if cmd == nil {
		t.Fatal("tickLocal should dispatch through cadence and return a command")
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); !ok || len(batch) != 2 {
		t.Errorf("onTick(tickLocal) = %T (len %v), want a 2-command batch (next tick + poll)", msg, msg)
	}
}

func TestPollLocalComputesRingAverageAndLatestSession(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	ring := ringPath()
	if err := os.MkdirAll(filepath.Dir(ring), 0o755); err != nil {
		t.Fatal(err)
	}
	content := strings.Join([]string{
		`{"ms":10,"session":"s1"}`,
		`{"ms":20,"session":"s2"}`,
		`{"ms":30}`,
		`not json`,
		`{"session":"s3"}`,
	}, "\n")
	if err := os.WriteFile(ring, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &Live{gen: 4}
	msg := p.pollLocal()().(liveLocalResult)

	if msg.gen != 4 {
		t.Errorf("gen = %d, want 4", msg.gen)
	}
	if msg.ring == nil {
		t.Fatal("ring should be populated when the ring file has ms samples")
	}
	if msg.ring.avgMs != 20 {
		t.Errorf("avgMs = %d, want 20", msg.ring.avgMs)
	}
	if msg.ring.count != 3 {
		t.Errorf("count = %d, want 3", msg.ring.count)
	}
	if msg.ring.session != "s3" {
		t.Errorf("session = %q, want %q (session is updated on every line that carries one)", msg.ring.session, "s3")
	}
}

func TestPollLocalTrimsRingToLast30Lines(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	ring := ringPath()
	if err := os.MkdirAll(filepath.Dir(ring), 0o755); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for i := 0; i < 35; i++ {
		lines = append(lines, `{"ms":1}`)
	}
	if err := os.WriteFile(ring, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &Live{}
	msg := p.pollLocal()().(liveLocalResult)

	if msg.ring == nil || msg.ring.count != 30 {
		t.Fatalf("ring = %+v, want count=30 (only the last 30 lines considered)", msg.ring)
	}
}

func TestPollLocalNoRingFileYieldsNilRing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	p := &Live{}
	msg := p.pollLocal()().(liveLocalResult)
	if msg.ring != nil {
		t.Errorf("ring = %+v, want nil when no ring file exists", msg.ring)
	}
}