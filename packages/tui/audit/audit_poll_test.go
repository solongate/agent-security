// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package audit

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
)

func TestTickCmd(t *testing.T) {
	p := newTestAudit(t)
	p.gen, p.tok = 3, 9

	cmd := p.tickCmd(auditTickLogs, time.Millisecond)
	msg := cmd()
	tick, ok := msg.(auditTick)
	if !ok {
		t.Fatalf("tickCmd msg type = %T, want auditTick", msg)
	}
	if tick.gen != 3 || tick.tok != 9 || tick.kind != auditTickLogs {
		t.Errorf("tick = %+v, want gen=3 tok=9 kind=auditTickLogs", tick)
	}
}

func TestLoadStats(t *testing.T) {
	p := newTestAudit(t)
	p.gen = 4
	writeLogLines(t,
		`{"ts":"2026-01-01T00:00:00Z","tool":"Bash","decision":"ALLOW"}`,
		`{"ts":"2026-01-01T00:01:00Z","tool":"Write","decision":"DENY"}`,
	)

	msg := p.loadStats()()
	res, ok := msg.(auditStatsResult)
	if !ok {
		t.Fatalf("loadStats msg type = %T, want auditStatsResult", msg)
	}
	if res.gen != 4 {
		t.Errorf("gen = %d, want 4", res.gen)
	}
	if res.err != nil {
		t.Fatalf("unexpected error: %v", res.err)
	}
	if res.stats.TotalCalls != 2 {
		t.Errorf("TotalCalls = %d, want 2", res.stats.TotalCalls)
	}
}

func TestLoadLogsSetsBusyUnlessQuiet(t *testing.T) {
	p := newTestAudit(t)

	p.busy = false
	_ = p.loadLogs()
	if !p.busy {
		t.Error("loadLogs() did not set busy")
	}

	p.busy = false
	_ = p.loadLogsQuiet()
	if p.busy {
		t.Error("loadLogsQuiet() set busy, want it left alone")
	}
}

func TestLoadLogsExecutesTheQuery(t *testing.T) {
	p := newTestAudit(t)
	p.gen = 7
	writeLogLines(t, `{"ts":"2026-01-01T00:00:00Z","tool":"Bash","decision":"ALLOW"}`)

	msg := p.loadLogs()()
	res, ok := msg.(auditLogsResult)
	if !ok {
		t.Fatalf("loadLogs msg type = %T, want auditLogsResult", msg)
	}
	if res.gen != 7 {
		t.Errorf("gen = %d, want 7", res.gen)
	}
	if res.err != nil {
		t.Fatalf("unexpected error: %v", res.err)
	}
	if res.list.Total != 1 {
		t.Errorf("Total = %d, want 1", res.list.Total)
	}
}

func TestPageRows(t *testing.T) {
	p := newTestAudit(t)

	rows, total := p.pageRows()
	if rows != nil || total != 0 {
		t.Errorf("pageRows() with no list = %v, %d; want nil, 0", rows, total)
	}

	p.list = &client.AuditList{
		Total: 5,
		Entries: []client.AuditEntry{
			{ID: "old", ToolName: "A", Decision: "ALLOW", CreatedAt: "2026-01-01T00:00:00Z"},
			{ID: "new", ToolName: "B", Decision: "ALLOW", CreatedAt: "2026-01-02T00:00:00Z"},
			{ID: "mid", ToolName: "C", Decision: "ALLOW", CreatedAt: "2026-01-01T12:00:00Z"},
		},
	}
	rows, total = p.pageRows()
	if total != 5 {
		t.Errorf("total = %d, want the list's Total field (5), not len(Entries)", total)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
	if rows[0].tool != "B" || rows[1].tool != "C" || rows[2].tool != "A" {
		t.Errorf("rows = %v, want sorted newest (B, C, A)", rows)
	}
}

func TestOnTickStaleTokenIsIgnored(t *testing.T) {
	p := newTestAudit(t)
	if cmd := p.onTick(auditTick{tok: p.tok + 1, kind: auditTickStats}); cmd != nil {
		t.Error("onTick with a mismatched token returned a non-nil cmd, want nil")
	}
}

// batchLen executes a cmd produced by tea.Batch and returns how many
// sub-commands it carries. tea.Batch's returned func only wraps the
// sub-commands into a tea.BatchMsg; it does not invoke them, so calling it
// here is instantaneous and starts no timers or I/O of its own.
func batchLen(t *testing.T, cmd tea.Cmd) int {
	t.Helper()
	if cmd == nil {
		return 0
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		return len(batch)
	}
	return 1
}

func TestOnTickStatsBatchesARefreshUnlessFrozen(t *testing.T) {
	p := newTestAudit(t)
	p.tok = 1

	// Not frozen: batches the next tick alongside a stats reload.
	if n := batchLen(t, p.onTick(auditTick{tok: 1, kind: auditTickStats})); n != 2 {
		t.Errorf("onTick (unfrozen, stats) batch length = %d, want 2", n)
	}

	// Frozen: onTick still schedules the next tick (we deliberately do not
	// invoke it, since it carries a real 15s timer), but must not be nil.
	p.frozen = true
	if cmd := p.onTick(auditTick{tok: 1, kind: auditTickStats}); cmd == nil {
		t.Error("onTick (frozen, stats) returned nil, want the rescheduled tick")
	}
}

func TestOnTickLogsBatchesARefreshOnlyWhenEligible(t *testing.T) {
	p := newTestAudit(t)
	p.tok = 1

	if n := batchLen(t, p.onTick(auditTick{tok: 1, kind: auditTickLogs})); n != 2 {
		t.Errorf("onTick (eligible, logs) batch length = %d, want 2", n)
	}

	cases := []struct {
		name string
		mod  func(*Audit)
	}{
		{"frozen", func(p *Audit) { p.frozen = true }},
		{"editing", func(p *Audit) { p.editing = "tool" }},
		{"paged past the first page", func(p *Audit) { p.page = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestAudit(t)
			p.tok = 1
			tc.mod(p)
			// We only assert non-nil here (not invoke-and-count): the
			// returned cmd is the bare rescheduled tick, which carries a
			// real 6s timer we do not want to start pointlessly in a test.
			if cmd := p.onTick(auditTick{tok: 1, kind: auditTickLogs}); cmd == nil {
				t.Error("onTick returned nil, want the rescheduled tick even when skipping the reload")
			}
		})
	}
}