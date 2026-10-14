// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"context"
	"sort"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
)

// ── data ───────────────────────────────────────────────────────────────────

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

// auditLocalResult carried the second read's rows. One read, one result type.

type auditNoteResult struct {
	gen     int
	note    auditNote
	reload  bool
	toTop   bool
	refresh bool // also refresh the stats strip
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

// loadLogs fetches the current page from whichever source is selected. `quiet`
// is the background poll: it leaves the visible spinner alone so "loading…" is
// reserved for something the user did.
func (p *Audit) loadLogs() tea.Cmd { return p.loadLogsMode(false) }

func (p *Audit) loadLogsQuiet() tea.Cmd { return p.loadLogsMode(true) }

func (p *Audit) loadLogsMode(quiet bool) tea.Cmd {
	gen := p.gen
	// A SECOND PATH stood here, reading the same file directly and filtering it in
	// memory, selected by `p.source == "local"`. Both paths read
	// security.localLogs.path now, so the only difference left was which one paged,
	// and this one pages through the store, which is what `solongate audit` uses.
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

// pageRows is the current page and the size of the whole result. Filtering and paging
// happen in the store, against the file, so the panel and `solongate audit` cannot
// disagree about what matches.
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
	// A ticker armed by a previous mount of this section dies here; re-arming it
	// would leave the panel with two chains and twice the poll rate.
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
		// Only page 0 auto-refreshes: a deeper page stays put while it is read.
		if p.frozen || p.editing != "" || p.page != 0 {
			return next
		}
		return tea.Batch(next, p.loadLogsQuiet())
	}
	return nil
}