package tui

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// Audit — the Live console's tool stream, over the FULL history.
//
// Rows use the SAME renderer as Live ([HH:MM:SS LOC|CLD] DECISION tool perm
// eval agent dlp: rl: {args}) and enter opens the SAME entry inspector; the only
// thing Audit adds over Live is that it shows every log, not just the live
// buffer. Two sub-views over ONE source toggle:
//
//	logs     : every call, newest first, 500 per page (←→ pages, and the
//	           selection jumps to the top on a page change). Filters: f decision,
//	           g signal, t tool, n agent, / search, c clear. enter = full entry.
//	sessions : every session with its own independent filters (f status,
//	           / search). enter = that session's logs.
//
// `s` toggles the source everywhere: cloud (the API) against local (the JSONL
// file the hooks write on this machine). `v` toggles logs against sessions.

func init() { Register(SectionAudit, func(d Deps) Panel { return newAudit(d) }) }

const (
	auditPage      = 500
	localMaxBytes  = 16 * 1024 * 1024 // read up to 16MB of local history
	auditKeyColumn = 19
)

var (
	auditDecisions = []string{"", "DENY", "ALLOW"}
	auditSignals   = []string{"", "dlp", "ratelimit"}
	auditSessState = []string{"", "active", "idle", "ended"}
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

// stream is the shared row shape — identical rows to the Live console.
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
func cloudRow(e api.AuditEntry) logRow {
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

// loadLocalRows reads the local file. The hooks do not write the dlp and burst
// fields, so both are derived from the reason — otherwise the signal filters
// would silently match nothing on the local source.
func loadLocalRows() []logRow {
	lines := parseLocalLines(tailLines(config.LocalLogFile(), localMaxBytes))
	out := make([]logRow, 0, len(lines))
	for i, j := range lines {
		dlpFromReason, burstFromReason := reasonSignals(j.Reason)
		var explicit []string
		if len(j.DLP) > 0 && string(j.DLP) != "null" && string(j.DLP) != "false" {
			var names []string
			if json.Unmarshal(j.DLP, &names) == nil {
				explicit = names
			} else {
				explicit = []string{"dlp"}
			}
		}
		if len(explicit) == 0 {
			explicit = dlpFromReason
		}
		r := logRow{
			id: "l:" + strconv.FormatInt(j.At, 10) + ":" + strconv.Itoa(i), at: j.At,
			tool: j.Tool, decision: j.Decision, permission: j.Permission, trust: j.TrustLevel,
			agent: j.AgentName, session: j.SessionID, reason: j.Reason, rule: j.MatchedRuleID,
			evalMs: j.EvaluationTimeMs, dlp: explicit,
			burst: j.RateLimitBurst || burstFromReason,
		}
		if r.tool == "" {
			r.tool = "?"
		}
		if r.decision == "" {
			r.decision = "ALLOW"
		}
		if r.permission == "" {
			r.permission = "—"
		}
		if r.trust == "" {
			r.trust = "—"
		}
		if len(j.Arguments) > 0 && string(j.Arguments) != "null" {
			r.args = string(j.Arguments)
		}
		out = append(out, r)
	}
	// Newest first, always date-ordered.
	sort.SliceStable(out, func(i, k int) bool { return out[i].at > out[k].at })
	return out
}

type auditSess struct {
	id     string
	agent  string
	status string
	calls  int
	denies int
	dlp    int
	trust  *float64
	lastAt int64
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

	source string // cloud | local
	view   string // logs | sessions | detail

	di, gi     int
	tool       string
	agent      string
	search     string
	sessFilter string
	page       int
	sel        int

	detailScroll int
	editing      string // "" | tool | agent | search | sess-search
	input        textinput.Model

	si         int
	sessSearch string
	sessSel    int

	confirm *confirmState
	note    *auditNote
	help    bool
	frozen  bool

	stats     *api.Stats
	cloud     *api.AuditList
	cloudErr  error
	cloudBusy bool

	local     []logRow
	localErr  error
	localBusy bool

	agents     *api.LiveAgents
	agentsErr  error
	agentsBusy bool
}

func newAudit(d Deps) *Audit {
	in := textinput.New()
	in.Prompt = ""
	in.CharLimit = 200
	return &Audit{deps: d, tok: nextPanelToken(), source: "cloud", view: "logs", input: in}
}

// ── data ───────────────────────────────────────────────────────────────────

const (
	auditTickStats = iota
	auditTickLogs
	auditTickSessions
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
	stats api.Stats
	err   error
}

func (m auditStatsResult) Generation() int { return m.gen }

type auditLogsResult struct {
	gen  int
	list api.AuditList
	err  error
}

func (m auditLogsResult) Generation() int { return m.gen }

type auditLocalResult struct {
	gen  int
	rows []logRow
}

func (m auditLocalResult) Generation() int { return m.gen }

type auditAgentsResult struct {
	gen    int
	agents api.LiveAgents
	err    error
}

func (m auditAgentsResult) Generation() int { return m.gen }

type auditNoteResult struct {
	gen     int
	note    auditNote
	reload  bool
	toTop   bool
	refresh bool // also refresh the stats strip
}

func (m auditNoteResult) Generation() int { return m.gen }

func (p *Audit) Init(ctx PanelContext) tea.Cmd {
	p.gen = ctx.Gen
	return tea.Batch(
		p.loadStats(), p.loadLogs(), p.loadSessions(),
		p.tickCmd(auditTickStats, 15*time.Second),
		p.tickCmd(auditTickLogs, 6*time.Second),
		p.tickCmd(auditTickSessions, 8*time.Second),
	)
}

func (p *Audit) query() api.AuditQuery {
	return api.AuditQuery{
		Filter:    auditDecisions[p.di],
		Signal:    auditSignals[p.gi],
		Tool:      p.tool,
		AgentName: p.agent,
		Search:    p.search,
		SessionID: p.sessFilter,
		Limit:     auditPage,
		Offset:    p.page * auditPage,
	}
}

func (p *Audit) loadStats() tea.Cmd {
	if p.source != "cloud" {
		return nil
	}
	gen, client := p.gen, p.deps.API
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
	if p.source == "local" {
		if !quiet {
			p.localBusy = true
		}
		return func() tea.Msg { return auditLocalResult{gen: gen, rows: loadLocalRows()} }
	}
	if !quiet {
		p.cloudBusy = true
	}
	client, q := p.deps.API, p.query()
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		list, err := client.Audit.List(ctx, q)
		return auditLogsResult{gen: gen, list: list, err: err}
	}
}

func (p *Audit) loadSessions() tea.Cmd {
	if p.source != "cloud" {
		return nil
	}
	gen, client := p.gen, p.deps.API
	p.agentsBusy = true
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		a, err := client.Agents.Live(ctx, 100, true)
		return auditAgentsResult{gen: gen, agents: a, err: err}
	}
}

// ── derived ────────────────────────────────────────────────────────────────

func (p *Audit) localFiltered() []logRow {
	q := strings.ToLower(strings.TrimSpace(p.search))
	out := make([]logRow, 0, len(p.local))
	for _, r := range p.local {
		if d := auditDecisions[p.di]; d != "" && r.decision != d {
			continue
		}
		if auditSignals[p.gi] == "dlp" && len(r.dlp) == 0 {
			continue
		}
		if auditSignals[p.gi] == "ratelimit" && !r.burst {
			continue
		}
		if p.tool != "" && !strings.Contains(strings.ToLower(r.tool), strings.ToLower(p.tool)) {
			continue
		}
		if p.agent != "" && !strings.EqualFold(r.agent, p.agent) {
			continue
		}
		if p.sessFilter != "" && r.session != p.sessFilter {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(r.tool+" "+r.agent+" "+r.reason+" "+r.args), q) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// pageRows and total are the current page and the size of the whole result. The
// cloud pages server-side; the local file is filtered and paged here.
func (p *Audit) pageRows() (rows []logRow, total int) {
	if p.source == "cloud" {
		if p.cloud == nil {
			return nil, 0
		}
		rows = make([]logRow, 0, len(p.cloud.Entries))
		for _, e := range p.cloud.Entries {
			rows = append(rows, cloudRow(e))
		}
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].at > rows[j].at })
		return rows, p.cloud.Total
	}
	filtered := p.localFiltered()
	start := p.page * auditPage
	if start > len(filtered) {
		start = len(filtered)
	}
	end := start + auditPage
	if end > len(filtered) {
		end = len(filtered)
	}
	return filtered[start:end], len(filtered)
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

func (p *Audit) sessions() []auditSess {
	var out []auditSess
	if p.source == "cloud" {
		if p.agents == nil {
			return nil
		}
		for _, a := range p.agents.Agents {
			name := a.SessionID
			if a.AgentName != nil && *a.AgentName != "" {
				name = *a.AgentName
			}
			status := a.Status
			if status == "deactivated" {
				status = "ended"
			}
			last, _ := parseMillis(a.LastSeenAt)
			trust := a.TrustScore
			out = append(out, auditSess{
				id: a.SessionID, agent: name, status: status, calls: a.TotalCalls,
				denies: a.DeniedCalls, dlp: a.DLPEvents, trust: &trust, lastAt: last,
			})
		}
		return out
	}
	order := []string{}
	byID := map[string]*auditSess{}
	for _, r := range p.local {
		if r.session == "" {
			continue
		}
		cur := byID[r.session]
		if cur == nil {
			agent := r.agent
			if agent == "" {
				agent = "local agent"
			}
			cur = &auditSess{id: r.session, agent: agent, status: "ended"}
			byID[r.session] = cur
			order = append(order, r.session)
		}
		cur.calls++
		if r.decision != "ALLOW" {
			cur.denies++
		}
		if len(r.dlp) > 0 {
			cur.dlp++
		}
		if r.at > cur.lastAt {
			cur.lastAt = r.at
		}
		if r.agent != "" {
			cur.agent = r.agent
		}
	}
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}

func (p *Audit) sessionsFiltered(now int64) []auditSess {
	q := strings.ToLower(strings.TrimSpace(p.sessSearch))
	var out []auditSess
	for _, s := range p.sessions() {
		if p.source != "cloud" {
			s.status = sessStatus(s.lastAt, now)
		}
		if want := auditSessState[p.si]; want != "" && s.status != want {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(s.agent+" "+s.id), q) {
			continue
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].lastAt > out[j].lastAt })
	return out
}

// Visible loading states. They also lock the keyboard below, because a queued
// keypress would otherwise double-page or land on a row that is about to be
// replaced.
func (p *Audit) logsLoading() bool {
	busy := p.cloudBusy
	if p.source == "local" {
		busy = p.localBusy
	}
	return busy && p.editing == ""
}

func (p *Audit) sessLoading() bool {
	if p.source == "cloud" {
		return p.agentsBusy
	}
	return p.localBusy
}

func (p *Audit) logsError() error {
	if p.source == "cloud" {
		return p.cloudErr
	}
	return p.localErr
}

func (p *Audit) sessError() error {
	if p.source == "cloud" {
		return p.agentsErr
	}
	return p.localErr
}

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
		p.cloudBusy = false
		if m.err != nil {
			p.cloudErr = m.err
			return p, nil
		}
		list := m.list
		p.cloud, p.cloudErr = &list, nil
		return p, nil

	case auditLocalResult:
		p.localBusy = false
		p.local, p.localErr = m.rows, nil
		return p, nil

	case auditAgentsResult:
		p.agentsBusy = false
		if m.err != nil {
			p.agentsErr = m.err
			return p, nil
		}
		a := m.agents
		p.agents, p.agentsErr = &a, nil
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

func (p *Audit) onTick(m auditTick) tea.Cmd {
	// A ticker armed by a previous mount of this section dies here; re-arming it
	// would leave the panel with two chains and twice the poll rate.
	if m.tok != p.tok {
		return nil
	}
	switch m.kind {
	case auditTickStats:
		next := p.tickCmd(auditTickStats, 15*time.Second)
		if p.frozen || p.source != "cloud" {
			return next
		}
		return tea.Batch(next, p.loadStats())
	case auditTickLogs:
		next := p.tickCmd(auditTickLogs, 6*time.Second)
		// Only page 0 auto-refreshes: a deeper page stays put while it is read.
		if p.frozen || p.view != "logs" || p.editing != "" || p.page != 0 {
			return next
		}
		return tea.Batch(next, p.loadLogsQuiet())
	case auditTickSessions:
		next := p.tickCmd(auditTickSessions, 8*time.Second)
		if p.frozen || p.source != "cloud" || p.view != "sessions" {
			return next
		}
		return tea.Batch(next, p.loadSessions())
	}
	return nil
}

func (p *Audit) onKey(k tea.KeyMsg, ctx PanelContext) tea.Cmd {
	if p.editing != "" {
		return p.editField(k)
	}
	str := k.String()

	// Copy mode first: space toggles, and while frozen ONLY space works.
	if str == " " {
		p.frozen = !p.frozen
		return nil
	}
	if p.frozen {
		return nil
	}
	// ^R refetches the active source on demand, so a change made elsewhere (the
	// dashboard, another session) shows up without waiting for a poll.
	if k.Type == tea.KeyCtrlR {
		p.note = &auditNote{text: "⟳ refreshed " + ctx.Now.Format("15:04:05"), level: "ok"}
		if p.source == "cloud" {
			return tea.Batch(p.loadLogs(), p.loadSessions(), p.loadStats())
		}
		return p.loadLogs()
	}
	// `?` works from any view, even mid-load; any key closes it.
	if p.help {
		p.help = false
		return nil
	}
	if str == "?" {
		p.help = true
		return nil
	}

	if p.view == "detail" {
		switch k.Type {
		case tea.KeyLeft, tea.KeyEsc:
			p.view = "logs"
		case tea.KeyUp:
			p.detailScroll = maxInt(0, p.detailScroll-1)
		case tea.KeyDown:
			p.detailScroll++ // clamped at render
		case tea.KeyPgUp:
			p.detailScroll = maxInt(0, p.detailScroll-10)
		case tea.KeyPgDown:
			p.detailScroll += 10
		}
		return nil
	}

	// Keyboard LOCK while data is loading.
	if p.view == "logs" && p.logsLoading() {
		return nil
	}
	if p.view == "sessions" && p.sessLoading() {
		return nil
	}
	// Any key other than the delete keys disarms a pending confirmation.
	if p.confirm != nil && str != "x" && str != "X" {
		p.confirm = nil
		p.note = nil
	}

	if str == "s" {
		if p.source == "cloud" {
			p.source = "local"
		} else {
			p.source = "cloud"
		}
		p.page, p.sel, p.sessSel = 0, 0, 0
		return tea.Batch(p.loadLogs(), p.loadSessions(), p.loadStats())
	}
	if str == "v" {
		if p.view == "logs" {
			p.view = "sessions"
		} else {
			p.view = "logs"
		}
		return nil
	}

	if p.view == "sessions" {
		sessions := p.sessionsFiltered(ctx.Now.UnixMilli())
		switch {
		case k.Type == tea.KeyUp:
			p.sessSel = maxInt(0, p.sessSel-1)
		case k.Type == tea.KeyDown:
			p.sessSel = minInt(len(sessions)-1, p.sessSel+1)
		case k.Type == tea.KeyPgUp:
			p.sessSel = maxInt(0, p.sessSel-10)
		case k.Type == tea.KeyPgDown:
			p.sessSel = minInt(len(sessions)-1, p.sessSel+10)
		case k.Type == tea.KeyEnter:
			if len(sessions) > 0 {
				p.sessFilter = sessions[minInt(p.sessSel, len(sessions)-1)].id
				p.page, p.sel = 0, 0
				p.view = "logs"
				return p.loadLogs()
			}
		case str == "f":
			p.si = (p.si + 1) % len(auditSessState)
			p.sessSel = 0
		case str == "/":
			return p.beginEdit("sess-search")
		case str == "c":
			p.si, p.sessSearch, p.sessSel = 0, "", 0
		}
		return nil
	}

	// logs view
	rows, total := p.pageRows()
	pages := p.pages(total)
	switch {
	case k.Type == tea.KeyUp:
		p.sel = maxInt(0, p.sel-1)
	case k.Type == tea.KeyDown:
		p.sel = minInt(len(rows)-1, p.sel+1)
	case k.Type == tea.KeyPgUp:
		p.sel = maxInt(0, p.sel-10)
	case k.Type == tea.KeyPgDown:
		p.sel = minInt(len(rows)-1, p.sel+10)
	case k.Type == tea.KeyEnter:
		if _, ok := p.current(rows); ok {
			p.detailScroll = 0
			p.view = "detail"
		}
	case k.Type == tea.KeyRight:
		if p.page < pages-1 {
			p.page++
			p.sel = 0
			return p.loadLogs()
		}
	case k.Type == tea.KeyLeft:
		if p.page > 0 {
			p.page--
			p.sel = 0
			return p.loadLogs()
		}
	case str == "f":
		p.di = (p.di + 1) % len(auditDecisions)
		p.page, p.sel = 0, 0
		return p.loadLogs()
	case str == "g":
		p.gi = (p.gi + 1) % len(auditSignals)
		p.page, p.sel = 0, 0
		return p.loadLogs()
	case str == "x":
		cur, ok := p.current(rows)
		if !ok {
			return nil
		}
		if p.confirm == nil || p.confirm.kind != "one" || p.confirm.key != cur.id {
			p.confirm = &confirmState{kind: "one", key: cur.id}
			p.note = &auditNote{level: "bad", text: "x = delete ONLY the selected entry: " +
				cur.decision + " " + cur.tool + " (" + agoAt(cur.at, ctx.Now) + " ago) — press x again"}
			return nil
		}
		p.confirm = nil
		return p.doDelete("one", cur)
	case str == "X":
		if p.confirm == nil || p.confirm.kind != "all" {
			p.confirm = &confirmState{kind: "all", key: "all"}
			p.note = &auditNote{level: "bad", text: "⚠ X = delete ALL " + p.source +
				" logs — every one of the " + strconv.Itoa(total) + " matched entries! press X again"}
			return nil
		}
		p.confirm = nil
		return p.doDelete("all", logRow{})
	case str == "e":
		return p.doExport("page", rows)
	case str == "E":
		return p.doExport("all", rows)
	case str == "t":
		return p.beginEdit("tool")
	case str == "n":
		return p.beginEdit("agent")
	case str == "/":
		return p.beginEdit("search")
	case str == "c":
		p.di, p.gi = 0, 0
		p.tool, p.agent, p.search, p.sessFilter = "", "", "", ""
		p.page, p.sel = 0, 0
		return p.loadLogs()
	}
	return nil
}

func (p *Audit) beginEdit(field string) tea.Cmd {
	p.editing = field
	switch field {
	case "tool":
		p.input.SetValue(p.tool)
	case "agent":
		p.input.SetValue(p.agent)
	case "search":
		p.input.SetValue(p.search)
	case "sess-search":
		p.input.SetValue(p.sessSearch)
	}
	p.input.CursorEnd()
	return p.input.Focus()
}

// editField runs the one-line filter editor. Enter commits and closes, esc
// closes without discarding what was typed — Ink's text input answered neither
// key, which left esc reaching the shell and unfocusing the panel mid-edit.
func (p *Audit) editField(k tea.KeyMsg) tea.Cmd {
	if k.Type == tea.KeyEnter || k.Type == tea.KeyEsc {
		field := p.editing
		p.editing = ""
		p.input.Blur()
		if field == "sess-search" {
			return nil
		}
		return p.loadLogs()
	}
	var cmd tea.Cmd
	p.input, cmd = p.input.Update(k)
	v := p.input.Value()
	switch p.editing {
	case "tool":
		if v != p.tool {
			p.tool, p.page, p.sel = v, 0, 0
		}
	case "agent":
		if v != p.agent {
			p.agent, p.page, p.sel = v, 0, 0
		}
	case "search":
		if v != p.search {
			p.search, p.page, p.sel = v, 0, 0
		}
	case "sess-search":
		if v != p.sessSearch {
			p.sessSearch, p.sessSel = v, 0
		}
	}
	return cmd
}

// doDelete removes the selected entry, or every entry of the current source.
func (p *Audit) doDelete(kind string, cur logRow) tea.Cmd {
	p.note = &auditNote{text: "deleting…", level: "ok"}
	gen, client, source := p.gen, p.deps.API, p.source
	return func() tea.Msg {
		fail := func(err error) tea.Msg {
			return auditNoteResult{gen: gen, note: auditNote{text: "✗ " + err.Error(), level: "bad"}}
		}
		if source == "cloud" {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			var err error
			if kind == "one" {
				_, err = client.Audit.Remove(ctx, []string{cur.id})
			} else {
				_, err = client.Audit.RemoveAll(ctx)
			}
			if err != nil {
				return fail(err)
			}
		} else {
			n := 0
			if kind == "one" {
				n = deleteLocalEntry(cur.at, cur.tool, cur.session)
			} else {
				n = clearLocalLog()
			}
			if n == 0 {
				return fail(errors.New("entry not found in the local file"))
			}
		}
		text := "✓ entry deleted"
		if kind != "one" {
			text = "✓ ALL " + source + " logs deleted"
		}
		return auditNoteResult{gen: gen, note: auditNote{text: text, level: "ok"},
			reload: true, toTop: true, refresh: source == "cloud"}
	}
}

// doExport writes the current page (e) or everything matching the filters (E).
func (p *Audit) doExport(kind string, pageRows []logRow) tea.Cmd {
	p.note = &auditNote{text: "exporting…", level: "ok"}
	gen, client, source := p.gen, p.deps.API, p.source
	q := p.query()
	local := p.localFiltered()
	return func() tea.Msg {
		fail := func(err error) tea.Msg {
			return auditNoteResult{gen: gen,
				note: auditNote{text: "✗ export failed: " + err.Error(), level: "bad"}}
		}
		rows := pageRows
		if kind == "all" {
			if source == "cloud" {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				q.Limit, q.Offset = 10_000, 0
				list, err := client.Audit.List(ctx, q)
				if err != nil {
					return fail(err)
				}
				rows = make([]logRow, 0, len(list.Entries))
				for _, e := range list.Entries {
					rows = append(rows, cloudRow(e))
				}
				sort.SliceStable(rows, func(i, j int) bool { return rows[i].at > rows[j].at })
			} else {
				rows = local
			}
		}
		dir := config.Dir()
		file := filepath.Join(dir, "audit-export-"+source+".jsonl")
		var b strings.Builder
		for _, r := range rows {
			line, err := json.Marshal(r.export())
			if err != nil {
				continue
			}
			b.Write(line)
			b.WriteByte('\n')
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fail(err)
		}
		if err := os.WriteFile(file, []byte(b.String()), 0o644); err != nil {
			return fail(err)
		}
		return auditNoteResult{gen: gen, note: auditNote{
			text: "✓ exported " + strconv.Itoa(len(rows)) + " rows → " + file, level: "ok"}}
	}
}

// ── rendering ──────────────────────────────────────────────────────────────

var auditHelp = []helpGroup{
	{"Logs", [][2]string{
		{"↑↓ / PgUp PgDn", "select a row (window follows)"},
		{"enter", "open the FULL entry (reason + arguments)"},
		{"← →", "previous / next page (500 per page, jumps to top)"},
		{"f", "decision filter: all → DENY → ALLOW"},
		{"g", "signal filter: all → dlp → ratelimit"},
		{"t / n", "tool / agent filter (type, enter done)"},
		{"/", "free-text search"},
		{"x", "delete ONLY the selected entry (press x twice)"},
		{"X", "delete ALL matched logs of the source (press X twice)"},
		{"e", "export this page → ~/.solongate/audit-export-<src>.jsonl"},
		{"E", "export ALL matched rows (cloud: up to 10k)"},
		{"c", "clear every filter (incl. session)"},
	}},
	{"Sessions", [][2]string{
		{"↑↓", "select a session"},
		{"enter", "open that session's logs"},
		{"f", "status filter: all → active → idle → ended"},
		{"/", "search agent / session id"},
		{"c", "clear session filters"},
	}},
	{"Anywhere in Audit", [][2]string{
		{"v", "switch logs ↔ sessions"},
		{"s", "switch source cloud ↔ local file"},
		{"space", "copy mode: freeze screen for mouse selection"},
		{"?", "this help · any key closes"},
		{"esc", "back to the menu"},
	}},
	{"Entry (full content)", [][2]string{
		{"↑↓ / PgUp PgDn", "scroll the reason + arguments"},
		{"space", "copy mode (freeze, then select)"},
		{"← / esc", "back to the list"},
	}},
}

func (p *Audit) View(ctx PanelContext) string {
	var lines []string
	switch {
	case p.help:
		lines = p.viewHelp(ctx)
	case p.view == "detail" && p.hasRows():
		lines = p.viewEntry(ctx)
	case p.view == "sessions":
		lines = p.viewSessions(ctx)
	default:
		lines = p.viewLogs(ctx)
	}
	// The panel clips itself: the help overlay and a long entry are both taller
	// than the box on purpose, and a frame that grows past its budget is the
	// full-screen repaint the budget exists to avoid.
	return clampBlock(strings.Join(lines, "\n"), ctx.Cols, ctx.Rows)
}

func (p *Audit) hasRows() bool {
	rows, _ := p.pageRows()
	return len(rows) > 0
}

func (p *Audit) viewHelp(ctx PanelContext) []string {
	note := "· press any key to close · space = copy mode (works here too)"
	if p.frozen {
		note = "· screen frozen — space resumes, other keys are locked"
	}
	lines := []string{}
	if b := p.copyBanner(ctx.Cols); b != "" {
		lines = append(lines, b)
	}
	lines = append(lines, renderRow(ctx.Cols,
		sgb("AUDIT — all keys ", theme.AccentBright), sg(note, theme.Dim)), "")
	// TWO columns, as in the TypeScript: the flat list is taller than the panel
	// box, and the half that does not fit is not scrollable from here — it would
	// simply be cut off, which is a key reference that silently omits keys.
	half := maxInt(20, (ctx.Cols-2)/2)
	left := helpBlock(auditHelp[:1], auditKeyColumn, half)
	right := helpBlock(auditHelp[1:], auditKeyColumn, half)
	rows := maxInt(len(left), len(right))
	return append(lines, joinColumns([][]string{left, right}, []int{half, half}, rows)...)
}

func (p *Audit) copyBanner(width int) string {
	if !p.frozen {
		return ""
	}
	return renderRow(width, seg{
		text: " ⏵ COPY MODE — screen frozen, select & copy freely · space resume ",
		fg:   lipgloss.Color(hexOKFG), bg: lipgloss.Color(hexOKBG), bold: true})
}

// strip is the merged Stats page: the totals for whichever source is selected.
func (p *Audit) strip(width int) string {
	if p.source == "cloud" {
		calls, allow, deny, policies := "····", "···", "··", "·"
		if p.stats != nil {
			calls = strconv.Itoa(p.stats.TotalCalls)
			allow = strconv.Itoa(p.stats.Allowed)
			deny = strconv.Itoa(p.stats.Denied)
			policies = strconv.Itoa(p.stats.ActivePolicies)
		}
		return renderRow(width,
			seg{text: calls, bold: true}, sg(" calls · ", theme.Dim),
			sg(allow+" allow", theme.OK), sg(" · ", theme.Dim),
			sg(deny+" deny", theme.Bad), sg(" · "+policies+" policies", theme.Dim))
	}
	allow, deny := 0, 0
	for _, r := range p.local {
		if r.decision == "ALLOW" {
			allow++
		} else {
			deny++
		}
	}
	return renderRow(width,
		seg{text: strconv.Itoa(len(p.local)), bold: true},
		sg(" calls in local file · ", theme.Dim),
		sg(strconv.Itoa(allow)+" allow", theme.OK), sg(" · ", theme.Dim),
		sg(strconv.Itoa(deny)+" deny", theme.Bad),
		sg(" · "+config.LocalLogFile(), theme.Dim))
}

func (p *Audit) srcChip() []seg {
	color := lipgloss.TerminalColor(lipgloss.Color("#4f6db8"))
	if p.source == "local" {
		color = theme.OK
	}
	return []seg{sg("src:", theme.Dim), seg{text: p.source, fg: color, bold: true}, sg(" (s) ", theme.Dim)}
}

func chip(label, value string, on bool) []seg {
	color := lipgloss.TerminalColor(theme.Dim)
	if on {
		color = theme.AccentBright
	}
	return []seg{sg(label+":", theme.Dim), seg{text: value, fg: color}, plain(" ")}
}

func orDot(s string) string {
	if s == "" {
		return "·"
	}
	return s
}

// viewEntry is the COMPLETE entry, scrollable, in the Live inspector's shape.
func (p *Audit) viewEntry(ctx PanelContext) []string {
	rows, _ := p.pageRows()
	e, ok := p.current(rows)
	if !ok {
		return p.viewLogs(ctx)
	}
	loc := p.source == "local"
	bodyW := maxInt(20, ctx.Cols-4)
	width := ctx.Cols - 2

	// FULL CONTENT surfaces the denial reason — Audit's forensic value — ABOVE
	// the arguments. Live folds the reason into the row only when the arguments
	// are absent, but an audit browser should always show WHY a call was denied.
	var content []string
	if e.reason != "" && e.decision != "ALLOW" {
		content = append(content, wrapLines("reason: "+e.reason, bodyW)...)
		content = append(content, "")
	}
	argsText := "(no arguments recorded)"
	switch {
	case e.args != "":
		argsText = prettyJson(e.args)
	case e.reason != "" && e.decision == "ALLOW":
		argsText = e.reason
	}
	content = append(content, wrapLines(argsText, bodyW)...)

	// ENTRY header (3) + pane title + footer + the copy banner when it is up.
	bodyRows := maxInt(4, ctx.Rows-6-boolInt(p.frozen))
	maxScroll := maxInt(0, len(content)-bodyRows)
	off := minInt(p.detailScroll, maxScroll)

	locLabel, locColor := "CLD", lipgloss.TerminalColor(theme.White)
	if loc {
		locLabel, locColor = "LOC", theme.OK
	}
	head := []seg{
		{text: " ENTRY ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
		sgb("  "+e.decision, decisionColor(e.decision)),
		sgb("  "+e.tool, theme.Accent),
		{text: "  " + locLabel, fg: locColor},
	}
	if len(e.dlp) > 0 {
		head = append(head, sg("  DLP!", theme.Bad))
	}
	if e.burst {
		head = append(head, sg("  BURST", theme.Warn))
	}
	head = append(head, sg("  ← back", theme.Dim))

	evalText, evalColor := "—", lipgloss.TerminalColor(nil)
	if e.evalMs != nil {
		evalText = num(*e.evalMs) + "ms"
		if *e.evalMs > 500 {
			evalColor = theme.Warn
		}
	}
	rule, ruleColor := e.rule, lipgloss.TerminalColor(theme.Dim)
	if rule == "" {
		rule = "—"
	} else if e.decision != "ALLOW" {
		ruleColor = theme.Bad
	}
	scrollNote := ""
	if maxScroll > 0 {
		scrollNote = " · ▼" + strconv.Itoa(maxScroll-off) + " more · ↑↓ scroll"
	}

	lines := []string{}
	if b := p.copyBanner(width); b != "" {
		lines = append(lines, b)
	}
	lines = append(lines,
		renderRow(width, head...),
		renderRow(width,
			sg("│ when ", theme.Dim), plain(time.UnixMilli(e.at).Format("2006-01-02 15:04:05")),
			sg(" │ perm ", theme.Dim), plain(orEmDash(e.permission)),
			sg(" │ trust ", theme.Dim), plain(orEmDash(e.trust)),
			sg(" │ eval ", theme.Dim), seg{text: evalText, fg: evalColor},
			sg(" │ agent ", theme.Dim), plain(orEmDash(e.agent)),
			sg(" │", theme.Dim)),
		renderRow(width,
			sg("│ session ", theme.Dim), sg(orEmDash(e.session), theme.Dim),
			sg(" │ rule ", theme.Dim), seg{text: rule, fg: ruleColor},
			sg(" │", theme.Dim)),
		paneTitle("FULL CONTENT", strconv.Itoa(len(content))+" lines"+scrollNote+
			" · space copy · ← back", width))
	for i := 0; i < bodyRows; i++ {
		if off+i >= len(content) {
			lines = append(lines, "")
			continue
		}
		lines = append(lines, renderRow(width, plain(content[off+i])))
	}
	return append(lines, renderRow(width,
		seg{text: " ENTRY ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
		seg{text: " " + e.id + " ", fg: theme.White, bg: lipgloss.Color(hexFooterBG)},
		seg{text: " ↑↓ scroll · space copy · ? all keys · ← back · esc menu ",
			fg: theme.White, bg: lipgloss.Color(hexPanelBG)}))
}

func (p *Audit) viewSessions(ctx PanelContext) []string {
	width := ctx.Cols
	sessions := p.sessionsFiltered(ctx.Now.UnixMilli())
	headerRows := 5 + boolInt(p.editing != "")
	listRows := maxInt(4, ctx.Rows-headerRows)
	sel := minInt(p.sessSel, maxInt(0, len(sessions)-1))
	start := minInt(maxInt(0, sel-(listRows-1)/2), maxInt(0, len(sessions)-listRows))
	end := minInt(start+listRows, len(sessions))

	head := append([]seg{}, p.srcChip()...)
	head = append(head, sgb("SESSIONS", theme.AccentBright), sg(" · logs (v) ", theme.Dim))
	head = append(head, chip("status", orAll(auditSessState[p.si]), p.si != 0)...)
	head = append(head, chip("search", orDot(p.sessSearch), p.sessSearch != "")...)

	hint := "press → to browse"
	if ctx.Focused {
		hint = "↑↓ select · enter → session logs · v logs · ^R refresh · ? all keys"
	}

	var body []string
	body = append(body, p.strip(width))
	if b := p.copyBanner(width); b != "" {
		body = append(body, b)
	}
	body = append(body, renderRow(width, head...), renderRow(width, sg(hint, theme.Dim)))
	if p.editing == "sess-search" {
		body = append(body, renderRow(width, sg("search: ", theme.Warn))+p.input.View())
	}
	counts := strconv.Itoa(len(sessions)) + " sessions · " + strconv.Itoa(sel+1) + "/" + strconv.Itoa(len(sessions))
	if start > 0 {
		counts += " · ▲" + strconv.Itoa(start)
	}
	if start+listRows < len(sessions) {
		counts += " · ▼" + strconv.Itoa(len(sessions)-start-listRows)
	}
	body = append(body, renderRow(width, sg(counts, theme.Dim)))

	columns := []Column{
		{"", 2}, {"STATUS", 8}, {"AGENT", 18}, {"SESSION", 10},
		{"CALLS", 6}, {"DENY", 5}, {"DLP", 4}, {"TRUST", 5}, {"LAST", 6},
	}
	rows := make([][]Cell, 0, end-start)
	for i := start; i < end; i++ {
		r := sessions[i]
		st := statusStyleOf(r.status)
		isSel := i == sel && ctx.Focused
		cursor := ""
		if isSel {
			cursor = "▸"
		}
		trust := "—"
		if r.trust != nil {
			trust = num(*r.trust)
		}
		denyCell := Cell{Value: strconv.Itoa(r.denies), Dim: r.denies == 0}
		if r.denies > 0 {
			denyCell.Color = theme.Bad
		}
		dlpCell := Cell{Value: strconv.Itoa(r.dlp), Dim: r.dlp == 0}
		if r.dlp > 0 {
			dlpCell.Color = theme.Bad
		}
		rows = append(rows, []Cell{
			{Value: cursor, Color: theme.AccentBright},
			{Value: st.dot + " " + r.status, Color: st.color},
			{Value: truncate(r.agent, 18), Color: theme.Accent, Bold: isSel},
			{Value: firstN(r.id, 8), Dim: true},
			{Value: strconv.Itoa(r.calls)},
			denyCell,
			dlpCell,
			{Value: trust, Dim: true},
			{Value: agoAt(r.lastAt, ctx.Now), Dim: true},
		})
	}
	body = append(body, table(columns, rows, width)...)
	if len(sessions) == 0 {
		where := ""
		if p.source == "local" {
			where = " in the local file"
		}
		body = append(body, renderRow(width, sg("(no sessions"+where+")", theme.Dim)))
	}
	return dataView(p.sessLoading() && !p.frozen, p.sessError(), false, "", width, body)
}

func (p *Audit) viewLogs(ctx PanelContext) []string {
	width := ctx.Cols
	rows, total := p.pageRows()
	pages := p.pages(total)

	headerRows := 6 + boolInt(p.editing != "" && p.editing != "sess-search") +
		boolInt(p.note != nil) + boolInt(p.frozen)
	listRows := maxInt(4, ctx.Rows-headerRows)
	sel := minInt(p.sel, maxInt(0, len(rows)-1))
	start := minInt(maxInt(0, sel-(listRows-1)/2), maxInt(0, len(rows)-listRows))
	end := minInt(start+listRows, len(rows))

	head := append([]seg{}, p.srcChip()...)
	head = append(head, sgb("LOGS", theme.AccentBright), sg(" · sessions (v) ", theme.Dim))
	head = append(head, chip("dec", orAll(auditDecisions[p.di]), p.di != 0)...)
	head = append(head, chip("sig", orAll(auditSignals[p.gi]), p.gi != 0)...)
	head = append(head, chip("tool", orDot(p.tool), p.tool != "")...)
	head = append(head, chip("agent", orDot(p.agent), p.agent != "")...)
	head = append(head, chip("search", orDot(p.search), p.search != "")...)
	if p.sessFilter != "" {
		head = append(head, chip("sess", firstN(p.sessFilter, 8), true)...)
	}

	hint := "press → to browse"
	if ctx.Focused {
		hint = "↑↓ select · enter full entry · ←→ page · v sessions · ^R refresh · ? all keys"
	}

	var body []string
	body = append(body, p.strip(width))
	if b := p.copyBanner(width); b != "" {
		body = append(body, b)
	}
	body = append(body, renderRow(width, head...), renderRow(width, sg(hint, theme.Dim)))
	if p.note != nil {
		color := theme.OK
		if p.note.level == "bad" {
			color = theme.Bad
		}
		body = append(body, renderRow(width, sg(truncate(p.note.text, width), color)))
	}
	if p.editing != "" && p.editing != "sess-search" {
		body = append(body, renderRow(width, sg(p.editing+": ", theme.Warn))+p.input.View())
	}

	counts := strconv.Itoa(total) + " matched · page " + strconv.Itoa(minInt(p.page+1, pages)) +
		"/" + strconv.Itoa(pages) + " · " + strconv.Itoa(auditPage) + "/page · "
	if len(rows) > 0 {
		counts += strconv.Itoa(sel + 1)
	} else {
		counts += "0"
	}
	counts += "/" + strconv.Itoa(len(rows))
	if start > 0 {
		counts += " · ▲" + strconv.Itoa(start) + " newer"
	}
	if start+listRows < len(rows) {
		counts += " · ▼" + strconv.Itoa(len(rows)-start-listRows) + " older"
	}
	body = append(body, renderRow(width, sg(counts, theme.Dim)))

	for i := start; i < end; i++ {
		body = append(body, streamLine(rows[i].stream(), p.source == "local",
			i == sel && ctx.Focused, true, width))
	}
	if len(rows) == 0 {
		where := ""
		if p.source == "local" {
			where = " in the local file"
		}
		body = append(body, renderRow(width, sg("(no entries"+where+" — c clears filters)", theme.Dim)))
	}
	return dataView(p.logsLoading() && !p.frozen, p.logsError(), false, "", width, body)
}

func orAll(s string) string {
	if s == "" {
		return "all"
	}
	return s
}

func orEmDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
