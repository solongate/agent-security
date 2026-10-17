// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"context"
	"sort"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
)

const (
	auditTickStats = iota
	auditTickLogs
)

type auditTick struct {
	gen  int
	tok  int
	kind int
}

func (m auditTick) Generation() int { return m.gen }

func (p *Audit) tickCmd(kind int, d time.Duration) tea.Cmd {
	gen, tok := p.gen, p.tok
	return tea.Tick(d, func(time.Time) tea.Msg { return auditTick{gen: gen, tok: tok, kind: kind} })
}

type auditStatsResult struct {
	gen   int
	stats client.Stats
	err   error
}

func (m auditStatsResult) Generation() int { return m.gen }

type auditLogsResult struct {
	gen  int
	list client.AuditList
	err  error
}

func (m auditLogsResult) Generation() int { return m.gen }

type auditNoteResult struct {
	gen     int
	note    auditNote
	reload  bool
	toTop   bool
	refresh bool
}

func (m auditNoteResult) Generation() int { return m.gen }

func (p *Audit) loadStats() tea.Cmd {
	gen, client := p.gen, p.deps.Client
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		s, err := client.Stats.Get(ctx)
		return auditStatsResult{gen: gen, stats: s, err: err}
	}
}

func (p *Audit) loadLogs() tea.Cmd { return p.loadLogsMode(false) }

func (p *Audit) loadLogsQuiet() tea.Cmd { return p.loadLogsMode(true) }

func (p *Audit) loadLogsMode(quiet bool) tea.Cmd {
	gen := p.gen

	if !quiet {
		p.busy = true
	}
	client, q := p.deps.Client, p.query()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		list, err := client.Audit.List(ctx, q)
		return auditLogsResult{gen: gen, list: list, err: err}
	}
}

func (p *Audit) pageRows() (rows []logRow, total int) {
	if p.list == nil {
		return nil, 0
	}
	rows = make([]logRow, 0, len(p.list.Entries))
	for _, e := range p.list.Entries {
		rows = append(rows, cloudRow(e))
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].at > rows[j].at })
	return rows, p.list.Total
}

func (p *Audit) onTick(m auditTick) tea.Cmd {

	if m.tok != p.tok {
		return nil
	}
	switch m.kind {
	case auditTickStats:
		next := p.tickCmd(auditTickStats, 15*time.Second)
		if p.frozen {
			return next
		}
		return tea.Batch(next, p.loadStats())
	case auditTickLogs:
		next := p.tickCmd(auditTickLogs, 6*time.Second)

		if p.frozen || p.editing != "" || p.page != 0 {
			return next
		}
		return tea.Batch(next, p.loadLogsQuiet())
	}
	return nil
}