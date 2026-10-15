// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
)

// Audit, the Live console's tool stream, over the FULL history.
//
// Rows use the SAME renderer as Live ([HH:MM:SS LOC|CLD] DECISION tool perm
// eval agent dlp: rl: {args}) and enter opens the SAME entry inspector; the only
// thing Audit adds over Live is that it shows every log, not just the live
// buffer: every call, newest first, 500 per page (←→ pages, and the selection
// jumps to the top on a page change). Filters: f decision, g signal, t tool,
// n agent, / search, c clear. enter = full entry.
//
// There is ONE source: the JSONL file the hooks write on this machine, read through the
// api-client store, the same path `solongate audit` reads, so the panel and the command
// cannot disagree about what matches a filter. `s` used to toggle between that store and
// a second in-memory read of the same file, labelled "cloud" against "local".

func init() { Register(SectionAudit, func(d Deps) Panel { return newAudit(d) }) }

const (
	auditPage      = 500
	auditKeyColumn = 19
)

var (
	auditDecisions = []string{"", "DENY", "ALLOW"}
	auditSignals   = []string{"", "dlp", "ratelimit"}
)

// logRow is one row, unified across cloud entries and local JSONL lines.
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
	args       string // the raw JSON string of the arguments
}

// auditExport is the export file's shape. It is separate from logRow so the
// file keeps the field names and the nulls the TypeScript writes: someone's
// script reads these files, and a field that changed from null to "" between
// two implementations of the same command is a silent breakage.
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

// stream is the shared row shape, identical rows to the Live console.
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

// cloudRow prefers the API's own fields and falls back to the reason string, so
// a redacted or blocked DLP hit and a rate-limit burst are still detectable
// when the columns are not there to say so.
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
	kind string // one | all
	key  string
}

type auditNote struct {
	text  string
	level string // ok | bad
}

// Audit is the panel.
type Audit struct {
	deps Deps
	gen  int
	// tok identifies THIS mount of the panel; see nextPanelToken.
	tok int

	view string // logs | detail

	di, gi int
	tool   string
	agent  string
	search string
	page   int
	sel    int

	detailScroll int
	editing      string // "" | tool | agent | search
	input        textinput.Model

	confirm *confirmState
	note    *auditNote
	help    bool
	frozen  bool

	stats *client.Stats
	// The page, and whether it is in flight. These were `cloud`/`cloudErr`/`cloudBusy`,
	// beside a second set, `local`/`localErr`/`localBusy`, for the other source. Both
	// read the same file, so one set is all there is to be in.
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

// Visible loading states. They also lock the keyboard below, because a queued
// keypress would otherwise double-page or land on a row that is about to be
// replaced.
func (p *Audit) logsLoading() bool { return p.busy && p.editing == "" }

func (p *Audit) logsError() error { return p.err }

// ── update ─────────────────────────────────────────────────────────────────

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