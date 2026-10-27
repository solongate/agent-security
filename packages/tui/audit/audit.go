// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package audit

import (
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

func init() { tui.Register(tui.SectionAudit, func(d tui.Deps) tui.Panel { return newAudit(d) }) }

var tokens int

func nextToken() int { tokens++; return tokens }

const (
	auditPage      = 500
	auditKeyColumn = 19
	// exportPageSize is the largest page Audit.List honours. Exports walk pages
	// of this size instead of trusting one oversized request, which used to cut
	// the file off at the same number of rows.
	exportPageSize = client.MaxAuditPage
)

var (
	auditDecisions = []string{"", "DENY", "ALLOW"}
	auditSignals   = []string{"", "dlp", "ratelimit"}
)

type logRow struct {
	id         string
	at         int64
	tool       string
	decision   string
	permission string
	trust      string
	agent      string
	session    string
	reason     string
	rule       string
	evalMs     *float64
	dlp        []string
	burst      bool
	args       string
}

type auditExport struct {
	ID         string   `json:"id"`
	At         int64    `json:"at"`
	Tool       string   `json:"tool"`
	Decision   string   `json:"decision"`
	Permission string   `json:"permission"`
	Trust      string   `json:"trust"`
	Agent      *string  `json:"agent"`
	Session    *string  `json:"session"`
	Reason     *string  `json:"reason"`
	Rule       *string  `json:"rule"`
	EvalMs     *float64 `json:"evalMs"`
	DLP        []string `json:"dlp"`
	Burst      bool     `json:"burst"`
	Args       *string  `json:"args"`
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (r logRow) export() auditExport {
	dlp := r.dlp
	if dlp == nil {
		dlp = []string{}
	}
	return auditExport{
		ID: r.id, At: r.at, Tool: r.tool, Decision: r.decision, Permission: r.permission,
		Trust: r.trust, Agent: nilIfEmpty(r.agent), Session: nilIfEmpty(r.session),
		Reason: nilIfEmpty(r.reason), Rule: nilIfEmpty(r.rule), EvalMs: r.evalMs,
		DLP: dlp, Burst: r.burst, Args: nilIfEmpty(r.args),
	}
}

func (r logRow) stream() tui.StreamRow {
	detail := r.args
	if detail == "" {
		detail = r.reason
	}
	return tui.StreamRow{
		At: r.at, Tool: r.tool, Decision: r.decision, Permission: tui.Truncate4(r.permission),
		Detail: tui.CollapseSpace(detail), DLP: len(r.dlp) > 0, Burst: r.burst,
		Agent: r.agent, EvalMs: r.evalMs, Rule: r.rule,
	}
}

func cloudRow(e client.AuditEntry) logRow {
	at, _ := tui.ParseMillis(e.CreatedAt)
	reason := ""
	if e.Reason != nil {
		reason = *e.Reason
	}
	dlpFromReason, burstFromReason := tui.ReasonSignals(reason)
	r := logRow{
		id: e.ID, at: at, tool: e.ToolName, decision: e.Decision,
		permission: e.Permission, trust: e.TrustLevel, reason: reason,
		evalMs: e.EvaluationTimeMs, dlp: e.DLPMatches,
		burst: e.RateLimitBurst || burstFromReason,
	}
	if len(r.dlp) == 0 {
		r.dlp = dlpFromReason
	}
	if e.AgentName != nil {
		r.agent = *e.AgentName
	}
	if e.SessionID != nil {
		r.session = *e.SessionID
	}
	if e.MatchedRuleID != nil {
		r.rule = *e.MatchedRuleID
	}
	if len(e.ArgumentsSummary) > 0 && string(e.ArgumentsSummary) != "null" {
		r.args = string(e.ArgumentsSummary)
	}
	return r
}

type confirmState struct {
	kind string
	key  string
}

type auditNote struct {
	text  string
	level string
}

type Audit struct {
	deps tui.Deps
	gen  int

	tok int

	view string

	di, gi int
	tool   string
	agent  string
	search string
	page   int
	sel    int

	detailScroll int
	editing      string
	input        textinput.Model

	confirm *confirmState
	note    *auditNote
	help    bool
	frozen  bool

	stats *client.Stats

	list *client.AuditList
	err  error
	busy bool
}

func newAudit(d tui.Deps) *Audit {
	in := textinput.New()
	in.Prompt = ""
	in.CharLimit = 200
	return &Audit{deps: d, tok: nextToken(), view: "logs", input: in}
}

func (p *Audit) Init(ctx tui.PanelContext) tea.Cmd {
	p.gen = ctx.Gen
	return tea.Batch(
		p.loadStats(), p.loadLogs(),
		p.tickCmd(auditTickStats, 15*time.Second),
		p.tickCmd(auditTickLogs, 6*time.Second),
	)
}

func (p *Audit) query() client.AuditQuery {
	return client.AuditQuery{
		Filter:    auditDecisions[p.di],
		Signal:    auditSignals[p.gi],
		Tool:      p.tool,
		AgentName: p.agent,
		Search:    p.search,
		Limit:     auditPage,
		Offset:    p.page * auditPage,
	}
}

// filterActive reports whether the view shows only a subset of the log, i.e.
// whether "delete all" is meant to stop at the visible entries.
func (p *Audit) filterActive() bool {
	return p.tool != "" || p.agent != "" || p.search != "" ||
		auditDecisions[p.di] != "" || auditSignals[p.gi] != ""
}

func (p *Audit) pages(total int) int {
	n := (total + auditPage - 1) / auditPage
	if n < 1 {
		return 1
	}
	return n
}

func (p *Audit) current(rows []logRow) (logRow, bool) {
	if len(rows) == 0 {
		return logRow{}, false
	}
	return rows[tui.MinInt(p.sel, len(rows)-1)], true
}

func (p *Audit) logsLoading() bool { return p.busy && p.editing == "" }

func (p *Audit) logsError() error { return p.err }

func (p *Audit) CapturingKeys() bool { return p.editing != "" }

func (p *Audit) Update(msg tea.Msg, ctx tui.PanelContext) (tui.Panel, tea.Cmd) {
	p.gen = ctx.Gen
	switch m := msg.(type) {
	case tea.KeyMsg:
		return p, p.onKey(m, ctx)

	case auditTick:
		return p, p.onTick(m)

	case auditStatsResult:
		if m.err == nil {
			s := m.stats
			p.stats = &s
		}
		return p, nil

	case auditLogsResult:
		p.busy = false
		if m.err != nil {
			p.err = m.err
			return p, nil
		}
		list := m.list
		p.list, p.err = &list, nil
		return p, nil

	case auditNoteResult:
		note := m.note
		p.note = &note
		var cmds []tea.Cmd
		if m.toTop {
			p.sel = 0
		}
		if m.reload {
			cmds = append(cmds, p.loadLogs())
		}
		if m.refresh {
			cmds = append(cmds, p.loadStats())
		}
		return p, tea.Batch(cmds...)
	}
	return p, nil
}