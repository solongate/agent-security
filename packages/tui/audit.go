// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
)

func init() { Register(SectionAudit, func(d Deps) Panel { return newAudit(d) }) }

const (
	auditPage      = 500
	auditKeyColumn = 19
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

func (r logRow) stream() StreamRow {
	detail := r.args
	if detail == "" {
		detail = r.reason
	}
	return StreamRow{
		At: r.at, Tool: r.tool, Decision: r.decision, Permission: truncate4(r.permission),
		Detail: collapseSpace(detail), DLP: len(r.dlp) > 0, Burst: r.burst,
		Agent: r.agent, EvalMs: r.evalMs, Rule: r.rule,
	}
}

func cloudRow(e client.AuditEntry) logRow {
	at, _ := parseMillis(e.CreatedAt)
	reason := ""
	if e.Reason != nil {
		reason = *e.Reason
	}
	dlpFromReason, burstFromReason := reasonSignals(reason)
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
	deps Deps
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

func newAudit(d Deps) *Audit {
	in := textinput.New()
	in.Prompt = ""
	in.CharLimit = 200
	return &Audit{deps: d, tok: nextPanelToken(), view: "logs", input: in}
}

func (p *Audit) Init(ctx PanelContext) tea.Cmd {
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
	return rows[minInt(p.sel, len(rows)-1)], true
}

func (p *Audit) logsLoading() bool { return p.busy && p.editing == "" }

func (p *Audit) logsError() error { return p.err }

func (p *Audit) CapturingKeys() bool { return p.editing != "" }

func (p *Audit) Update(msg tea.Msg, ctx PanelContext) (Panel, tea.Cmd) {
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