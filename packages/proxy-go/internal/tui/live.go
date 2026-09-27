package tui

import (
	"context"
	"encoding/json"
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

// Live — the fullscreen realtime ops console.
//
// Copying: SPACE toggles COPY MODE — the screen freezes completely (polls skip,
// in-flight responses are dropped, the tick halts) so terminal mouse selection
// works and the user copies whatever they want. There is no auto-copy key.
//
// Keys (stream mode): ↑↓ select a row · w whitelist a DENY · b block an ALLOW ·
// d/x/r deny/dlp/ratelimit filter · f source LOC/CLD · / search · s sessions ·
// l layers · e export · space copy-mode · esc menu · q quit. Security events
// (deny, dlp, burst) and session-idle transitions raise a banner, a bell and a
// desktop toast.
//
// TRAFFIC uses 10-second buckets over the last 10 minutes, anchored to
// wall-clock slots — fast flow with activity, zero movement without.

func init() { Register(SectionLive, func(d Deps) Panel { return newLive(d) }) }

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// streamItem is one row of the merged live buffer. The json tags are the export
// format (`e`), so they are the TypeScript field names rather than Go ones.
type streamItem struct {
	ID         string   `json:"id"`
	At         int64    `json:"at"`
	Tool       string   `json:"tool"`
	Decision   string   `json:"decision"`
	Permission string   `json:"permission"`
	Detail     string   `json:"detail"`
	DLP        bool     `json:"dlp"`
	Burst      bool     `json:"burst"`
	Source     string   `json:"source"` // "local" | "cloud"
	Session    string   `json:"session,omitempty"`
	Agent      string   `json:"agent,omitempty"`
	EvalMs     *float64 `json:"evalMs,omitempty"`
	Rule       string   `json:"rule,omitempty"`
}

func (e streamItem) row() StreamRow {
	return StreamRow{
		At: e.At, Tool: e.Tool, Decision: e.Decision, Permission: e.Permission,
		Detail: e.Detail, DLP: e.DLP, Burst: e.Burst, Agent: e.Agent,
		EvalMs: e.EvalMs, Rule: e.Rule,
	}
}

// isLoc means the record is on THIS MACHINE'S DISK. Nothing else.
//
// It used to mean "happened here", inferred from the session id in the eval
// ring, so a call made on this machine read LOC even with local logging off and
// the record sitting only in the cloud. That is indefensible: the setting says
// local storage is off, so nothing may be labelled local. Storage is the
// question the label answers, and it is answered by where the entry was read.
func (e streamItem) isLoc() bool { return e.Source == "local" }

type logLine struct {
	ts    int64
	msg   string
	level string // ok | warn | bad
}

type alertBanner struct {
	id    string
	msg   string
	level string // warn | bad
	until int64
}

type flashMsg struct {
	text  string
	level string // ok | bad
	until int64
}

type ringStat struct {
	avgMs   int
	session string
	count   int
}

type sessRow struct {
	source string // local | cloud
	id     string
	agent  string
	calls  int
	denies int
	lastAt int64
	status string
	trust  *float64
	isMe   bool
}

// sessStatus: active under 60s since the last call, idle under 5m, ended after.
func sessStatus(lastAt, now int64) string {
	switch {
	case now-lastAt < 60_000:
		return "active"
	case now-lastAt < 300_000:
		return "idle"
	}
	return "ended"
}

type statusStyle struct {
	dot   string
	label string
	color lipgloss.Color
}

func statusStyleOf(s string) statusStyle {
	switch s {
	case "active":
		return statusStyle{"●", "ACTIVE", theme.OK}
	case "idle":
		return statusStyle{"◐", "IDLE", theme.Warn}
	}
	return statusStyle{"○", "ENDED", theme.Dim}
}

// insightsBits is the slice of /stats/security-insights this console reads. The
// endpoint returns more and keeps growing; decoding only what is rendered means
// a new field upstream cannot break the console.
//
// Every layer is a POINTER because absent and off are different answers: a
// project with no rate limit configured shows "?", one with the layer switched
// off shows "off", and collapsing them would tell someone their limits are
// enforced when nothing is set.
type insightsBits struct {
	Layers struct {
		RateLimit *insightsRateLimit `json:"rateLimit"`
		DLP       *insightsDLP       `json:"dlp"`
		Ghost     *insightsGhost     `json:"ghost"`
	} `json:"layers"`
	DLPByPattern []insightsPatternHit `json:"dlpByPattern"`
}

type insightsRateLimit struct {
	PerMinute int    `json:"perMinute"`
	PerHour   int    `json:"perHour"`
	PerDay    int    `json:"perDay"`
	Mode      string `json:"mode"`
}

type insightsDLP struct {
	Mode     string           `json:"mode"`
	Patterns []string         `json:"patterns"`
	Custom   []insightsCustom `json:"custom"`
}

type insightsCustom struct {
	Name string `json:"name"`
	Re   string `json:"re"`
}

type insightsGhost struct {
	Mode     string   `json:"mode"`
	Patterns []string `json:"patterns"`
}

type insightsPatternHit struct {
	Pattern string `json:"pattern"`
	Count   int    `json:"count"`
}

func (r *insightsRateLimit) mode() string {
	if r == nil {
		return ""
	}
	return r.Mode
}

func (d *insightsDLP) mode() string {
	if d == nil {
		return ""
	}
	return d.Mode
}

func (g *insightsGhost) mode() string {
	if g == nil {
		return ""
	}
	return g.Mode
}

// summary is the one-line rate-limit state in the LAYERS column.
func (r *insightsRateLimit) summary(minuteNow int) string {
	if r == nil || r.PerMinute == 0 {
		return "no limits set"
	}
	return strconv.Itoa(minuteNow) + "/" + strconv.Itoa(r.PerMinute) + "m " +
		orDash(r.PerHour) + "h " + orDash(r.PerDay) + "d"
}

// Live is the panel.
type Live struct {
	deps Deps
	gen  int
	// tok identifies THIS mount of the panel; see nextPanelToken.
	tok int

	stats  *api.Stats
	lat    []int
	cloud  []streamItem
	local  []streamItem
	merged []streamItem

	localOn      *bool
	localSetting config.LocalLogSetting
	ring         *ringStat

	events []logLine
	filter string // all | local | cloud
	signal string // none | deny | dlp | ratelimit

	search        string
	editingSearch bool
	input         textinput.Model

	sel    int
	action *flashMsg

	mode          string // stream | pick | detail | inspect | layers
	pickIdx       int
	detail        *sessRow
	detailCloud   []streamItem
	detailScroll  int
	inspect       *streamItem
	inspectScroll int
	inspectFrom   string
	layersScroll  int

	seen        map[string]bool
	notified    map[string]bool
	openedAt    int64
	lastLocalTS int64
	localSeq    int
	pausedUntil int64
	netFails    int

	sessions   []api.LiveAgent
	sessCounts struct{ active, idle, deactivated int }
	sessRows   []sessRow
	prevStatus map[string]string

	insights       insightsBits
	insightsLoaded bool
	guard          *api.GuardStatus

	alerts []alertBanner
	frozen bool
	help   bool
	tick   int
	start  time.Time

	toastQueue   map[string]*toastItem
	toastOrder   []string
	toastPending bool
	lastNotifyAt int64
}

type toastItem struct {
	count int
	msg   string
}

func newLive(d Deps) *Live {
	in := textinput.New()
	in.Prompt = ""
	in.CharLimit = 200
	return &Live{
		deps:       d,
		tok:        nextPanelToken(),
		filter:     "all",
		signal:     "none",
		mode:       "stream",
		input:      in,
		seen:       map[string]bool{},
		notified:   map[string]bool{},
		prevStatus: map[string]string{},
		toastQueue: map[string]*toastItem{},
	}
}

// ── polling ────────────────────────────────────────────────────────────────

const (
	tickAnim = iota
	tickLocal
	tickFeed
	tickStats
	tickSess
	tickInsights
	tickGuard
	tickToast
)

type liveTick struct {
	gen  int
	tok  int
	kind int
}

func (m liveTick) Generation() int { return m.gen }

func (p *Live) tickCmd(kind int, d time.Duration) tea.Cmd {
	gen, tok := p.gen, p.tok
	return tea.Tick(d, func(time.Time) tea.Msg { return liveTick{gen: gen, tok: tok, kind: kind} })
}

type liveLocalResult struct {
	gen     int
	setting config.LocalLogSetting
	lines   []localLogLine
	ring    *ringStat
}

func (m liveLocalResult) Generation() int { return m.gen }

type liveFeedResult struct {
	gen  int
	list api.AuditList
	ms   int
	err  error
}

func (m liveFeedResult) Generation() int { return m.gen }

type liveStatsResult struct {
	gen   int
	stats api.Stats
	err   error
}

func (m liveStatsResult) Generation() int { return m.gen }

type liveSessResult struct {
	gen    int
	agents api.LiveAgents
	err    error
}

func (m liveSessResult) Generation() int { return m.gen }

type liveInsightsResult struct {
	gen  int
	bits insightsBits
	err  error
}

func (m liveInsightsResult) Generation() int { return m.gen }

type liveGuardResult struct {
	gen    int
	status api.GuardStatus
	err    error
}

func (m liveGuardResult) Generation() int { return m.gen }

type liveDetailResult struct {
	gen   int
	items []streamItem
}

func (m liveDetailResult) Generation() int { return m.gen }

type liveActionResult struct {
	gen      int
	text     string
	level    string
	logText  string
	logLevel string
}

func (m liveActionResult) Generation() int { return m.gen }

func (p *Live) Init(ctx PanelContext) tea.Cmd {
	p.gen = ctx.Gen
	p.openedAt = ctx.Now.UnixMilli()
	p.start = ctx.Now
	// Poll budget, about 40 requests a minute: feed 3s, stats 8s, sessions 8s,
	// insights 20s, guard 60s. The 24h timeseries poll was dropped entirely —
	// TRAFFIC is derived from the buffer — which is what pays for this cadence
	// without risking the API's own rate limit.
	return tea.Batch(
		p.pollLocal(), p.pollFeed(), p.pollStats(), p.pollSessions(), p.pollInsights(), p.pollGuard(),
		p.tickCmd(tickAnim, 500*time.Millisecond),
		p.tickCmd(tickLocal, 2*time.Second),
		p.tickCmd(tickFeed, 3*time.Second),
		p.tickCmd(tickStats, 8*time.Second),
		p.tickCmd(tickSess, 8*time.Second),
		p.tickCmd(tickInsights, 20*time.Second),
		p.tickCmd(tickGuard, 60*time.Second),
	)
}

// paused covers both reasons to stop asking the API: copy mode, and the 30
// second back-off after the API said 429.
func (p *Live) paused() bool { return p.frozen || time.Now().UnixMilli() < p.pausedUntil }

// shouldPoll is whether a cadence may run right now.
//
// Split out of onTick so it can be tested: the alternative is executing a tick
// command to see what it does, and a tick command's whole job is to wait for
// its interval first.
//
// The local plane is disk, not network, so only copy mode stops it — a
// rate-limit back-off is the API asking for room and has nothing to do with
// reading a file this machine wrote.
func (p *Live) shouldPoll(kind int) bool {
	if kind == tickLocal {
		return !p.frozen
	}
	return !p.paused()
}

// The eval ring the guard writes per project. Same directory the hooks use, so
// the dataroom reads what this machine actually produced.
func ringPath() string { return filepath.Join(config.ProjectFlagDir(), ".eval-ring.jsonl") }

func (p *Live) pollLocal() tea.Cmd {
	gen := p.gen
	return func() tea.Msg {
		// on/off is the SETTING, never the presence of output. An enabled log
		// with nothing in it yet (fresh install, folder just changed, account
		// just switched) used to read as off, and the panel then told the user
		// to enable what was already enabled.
		setting := config.LocalLogsSetting()
		res := liveLocalResult{gen: gen, setting: setting}
		// With the setting off the file is not read at all. It still holds
		// whatever was written while it was on, and surfacing that would put LOC
		// rows in the stream of a project that has local storage turned off.
		if setting.Enabled {
			res.lines = parseLocalLines(tailLines(setting.File, defaultTailBytes))
		}
		lines := tailLines(ringPath(), 8192)
		if len(lines) > 30 {
			lines = lines[len(lines)-30:]
		}
		sum, n, session := 0.0, 0, ""
		for _, l := range lines {
			var j struct {
				Ms      *float64 `json:"ms"`
				Session string   `json:"session"`
			}
			if json.Unmarshal([]byte(l), &j) != nil {
				continue
			}
			if j.Ms != nil {
				sum += *j.Ms
				n++
			}
			if j.Session != "" {
				session = j.Session
			}
		}
		if n > 0 {
			res.ring = &ringStat{avgMs: int(sum/float64(n) + 0.5), session: session, count: n}
		}
		return res
	}
}

func (p *Live) pollFeed() tea.Cmd {
	gen, client := p.gen, p.deps.API
	return func() tea.Msg {
		t0 := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		list, err := client.Audit.List(ctx, api.AuditQuery{Limit: 50})
		return liveFeedResult{gen: gen, list: list, ms: int(time.Since(t0).Milliseconds()), err: err}
	}
}

func (p *Live) pollStats() tea.Cmd {
	gen, client := p.gen, p.deps.API
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		s, err := client.Stats.Get(ctx)
		return liveStatsResult{gen: gen, stats: s, err: err}
	}
}

func (p *Live) pollSessions() tea.Cmd {
	gen, client := p.gen, p.deps.API
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		a, err := client.Agents.Live(ctx, 30, true)
		return liveSessResult{gen: gen, agents: a, err: err}
	}
}

func (p *Live) pollInsights() tea.Cmd {
	gen, client := p.gen, p.deps.API
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		raw, err := client.Stats.SecurityInsights(ctx, 7)
		var bits insightsBits
		if err == nil {
			_ = json.Unmarshal(raw, &bits)
		}
		return liveInsightsResult{gen: gen, bits: bits, err: err}
	}
}

func (p *Live) pollGuard() tea.Cmd {
	gen, client := p.gen, p.deps.API
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		s, err := client.Settings.GetGuardStatus(ctx)
		return liveGuardResult{gen: gen, status: s, err: err}
	}
}

// fetchSessionHistory pulls a picked session's full cloud history once, when
// the detail view opens.
func (p *Live) fetchSessionHistory(id string) tea.Cmd {
	gen, client := p.gen, p.deps.API
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		list, err := client.Audit.List(ctx, api.AuditQuery{SessionID: id, Limit: 100})
		if err != nil {
			// A local-only session has no cloud history; the buffer covers it.
			return liveDetailResult{gen: gen}
		}
		items := make([]streamItem, 0, len(list.Entries))
		for _, e := range list.Entries {
			items = append(items, cloudItem(e))
		}
		return liveDetailResult{gen: gen, items: items}
	}
}

// cloudItem converts an audit entry into a stream row.
func cloudItem(e api.AuditEntry) streamItem {
	at, _ := parseMillis(e.CreatedAt)
	detail := ""
	if len(e.ArgumentsSummary) > 0 && string(e.ArgumentsSummary) != "null" {
		detail = string(e.ArgumentsSummary)
	} else if e.Reason != nil {
		detail = *e.Reason
	}
	item := streamItem{
		ID: "c:" + e.ID, At: at, Tool: e.ToolName, Decision: e.Decision,
		Permission: truncate4(e.Permission), Detail: collapseSpace(detail),
		DLP: len(e.DLPMatches) > 0, Burst: e.RateLimitBurst, Source: "cloud",
		EvalMs: e.EvaluationTimeMs,
	}
	if e.SessionID != nil {
		item.Session = *e.SessionID
	}
	if e.AgentName != nil {
		item.Agent = *e.AgentName
	}
	if e.MatchedRuleID != nil {
		item.Rule = *e.MatchedRuleID
	}
	return item
}

func truncate4(s string) string {
	r := []rune(s)
	if len(r) > 4 {
		return string(r[:4])
	}
	return s
}

// collapseSpace is the `.replace(/\s+/g, ' ')` every detail string goes
// through: a row is one line, and an argument containing a newline would
// otherwise push the frame past its budget.
func collapseSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

// ── update ─────────────────────────────────────────────────────────────────

func (p *Live) CapturingKeys() bool { return p.editingSearch }

func (p *Live) Update(msg tea.Msg, ctx PanelContext) (Panel, tea.Cmd) {
	p.gen = ctx.Gen
	now := ctx.Now.UnixMilli()

	switch m := msg.(type) {
	case tea.KeyMsg:
		return p, p.onKey(m, ctx)

	case liveTick:
		return p, p.onTick(m, ctx)

	case liveLocalResult:
		p.localSetting = m.setting
		on := m.setting.Enabled
		p.localOn = &on
		if m.ring != nil {
			p.ring = m.ring
		}
		if len(m.lines) > 0 {
			p.ingestLocal(m.lines)
		}
		return p, p.afterBuffers(ctx)

	case liveFeedResult:
		return p, p.onFeed(m, ctx)

	case liveStatsResult:
		if m.err != nil {
			return p, p.apiError(m.err, now)
		}
		s := m.stats
		p.stats = &s
		return p, nil

	case liveSessResult:
		if m.err != nil {
			return p, p.apiError(m.err, now)
		}
		p.sessions = m.agents.Agents
		p.sessCounts.active = m.agents.Counts.Active
		p.sessCounts.idle = m.agents.Counts.Idle
		p.sessCounts.deactivated = m.agents.Counts.Deactivated
		p.sessRows = p.buildSessions(now)
		return p, nil

	case liveInsightsResult:
		if m.err != nil {
			return p, p.apiError(m.err, now)
		}
		p.insights, p.insightsLoaded = m.bits, true
		return p, nil

	case liveGuardResult:
		if m.err != nil {
			return p, p.apiError(m.err, now)
		}
		g := m.status
		p.guard = &g
		return p, nil

	case liveDetailResult:
		p.detailCloud = m.items
		return p, nil

	case liveActionResult:
		p.action = &flashMsg{text: m.text, level: m.level, until: now + 7000}
		if m.logText != "" {
			p.pushLog(m.logText, m.logLevel, now)
		}
		return p, nil
	}
	return p, nil
}

// onTick re-arms the ticker it came from and issues that cadence's poll. Each
// cadence re-arms itself rather than sharing one timer, so copy mode can skip a
// poll without also stopping the clock.
func (p *Live) onTick(m liveTick, ctx PanelContext) tea.Cmd {
	// A tick armed by a previous mount of this section: let it die here rather
	// than re-arm it beside the chain this instance already started.
	if m.tok != p.tok {
		return nil
	}
	switch m.kind {
	case tickAnim:
		if p.frozen {
			// The animation tick is fully halted in copy mode, so the screen is
			// pixel-static and a terminal mouse selection survives. It is
			// re-armed anyway, or resuming would leave the console frozen.
			return p.tickCmd(tickAnim, 500*time.Millisecond)
		}
		p.tick++
		// The session rows are rebuilt on the tick rather than only when data
		// arrives: active/idle/ended is a function of TIME, and a session that
		// stopped calling has to go idle without anything new coming in — which
		// is exactly the transition the idle banner reports.
		p.sessRows = p.buildSessions(ctx.Now.UnixMilli())
		cmds := []tea.Cmd{p.tickCmd(tickAnim, 500*time.Millisecond)}
		cmds = append(cmds, p.notifyIdleSessions(ctx)...)
		return tea.Batch(cmds...)
	case tickLocal:
		return p.cadence(tickLocal, 2*time.Second, p.pollLocal)
	case tickFeed:
		return p.cadence(tickFeed, 3*time.Second, p.pollFeed)
	case tickStats:
		return p.cadence(tickStats, 8*time.Second, p.pollStats)
	case tickSess:
		return p.cadence(tickSess, 8*time.Second, p.pollSessions)
	case tickInsights:
		return p.cadence(tickInsights, 20*time.Second, p.pollInsights)
	case tickGuard:
		return p.cadence(tickGuard, 60*time.Second, p.pollGuard)
	case tickToast:
		return p.flushToasts(ctx.Now.UnixMilli())
	}
	return nil
}

// cadence re-arms a ticker and, unless the console is frozen or backing off,
// issues that cadence's poll. The ticker is re-armed either way, or resuming
// from copy mode would leave the console with no clock at all.
func (p *Live) cadence(kind int, every time.Duration, poll func() tea.Cmd) tea.Cmd {
	next := p.tickCmd(kind, every)
	if !p.shouldPoll(kind) {
		return next
	}
	return tea.Batch(next, poll())
}

func (p *Live) ingestLocal(lines []localLogLine) {
	var fresh []streamItem
	for _, j := range lines {
		if j.At <= p.lastLocalTS {
			continue
		}
		detail := ""
		if len(j.Arguments) > 0 && string(j.Arguments) != "null" {
			detail = string(j.Arguments)
		} else {
			detail = j.Reason
		}
		tool := j.Tool
		if tool == "" {
			tool = "?"
		}
		decision := j.Decision
		if decision == "" {
			decision = "ALLOW"
		}
		// A rate-limit burst writes many lines in the SAME millisecond for the
		// SAME tool, so timestamp and tool alone collide. The monotonic suffix
		// is what keeps every row's id unique.
		id := "l:" + strconv.FormatInt(j.At, 10) + ":" + j.Tool + ":" + strconv.Itoa(p.localSeq)
		p.localSeq++
		fresh = append(fresh, streamItem{
			ID: id, At: j.At, Tool: tool, Decision: decision,
			Permission: truncate4(j.Permission), Detail: collapseSpace(detail),
			DLP:   len(j.DLP) > 0 && string(j.DLP) != "null" && string(j.DLP) != "false",
			Burst: j.RateLimitBurst, Source: "local", Session: j.SessionID,
			Agent: j.AgentName, EvalMs: j.EvaluationTimeMs, Rule: j.MatchedRuleID,
		})
	}
	if len(fresh) == 0 {
		return
	}
	p.lastLocalTS = fresh[len(fresh)-1].At
	p.local = append(p.local, fresh...)
	if len(p.local) > 400 {
		p.local = p.local[len(p.local)-400:]
	}
	denies := 0
	for _, f := range fresh {
		if f.Decision != "ALLOW" {
			denies++
		}
	}
	if len(fresh) < 10 {
		msg := "local +" + strconv.Itoa(len(fresh)) + " calls"
		level := "warn"
		if denies > 0 {
			msg += " · " + strconv.Itoa(denies) + " DENIED"
			level = "bad"
		}
		p.pushLog(msg, level, time.Now().UnixMilli())
	}
}

func (p *Live) onFeed(m liveFeedResult, ctx PanelContext) tea.Cmd {
	now := ctx.Now.UnixMilli()
	if m.err != nil {
		return p.apiError(m.err, now)
	}
	if p.frozen {
		return nil // dropped: the response landed mid copy-mode
	}
	if p.netFails >= 3 {
		p.pushLog("network recovered", "ok", now)
	}
	p.netFails = 0
	p.lat = append(p.lat, m.ms)
	if len(p.lat) > 240 {
		p.lat = p.lat[len(p.lat)-240:]
	}
	var fresh []streamItem
	denies := 0
	for _, e := range m.list.Entries {
		if p.seen[e.ID] {
			continue
		}
		fresh = append(fresh, cloudItem(e))
		if e.Decision != "ALLOW" {
			denies++
		}
	}
	firstLoad := len(p.seen) == 0 && len(fresh) > 1
	for _, e := range m.list.Entries {
		p.seen[e.ID] = true
	}
	if len(fresh) > 0 {
		sort.SliceStable(fresh, func(i, j int) bool { return fresh[i].At < fresh[j].At })
		p.cloud = append(p.cloud, fresh...)
		if len(p.cloud) > 400 {
			p.cloud = p.cloud[len(p.cloud)-400:]
		}
	}
	switch {
	case firstLoad:
		p.pushLog("cloud link up · api "+strconv.Itoa(m.ms)+"ms · "+strconv.Itoa(len(fresh))+" calls", "ok", now)
	case len(fresh) > 0:
		msg := "api " + strconv.Itoa(m.ms) + "ms · +" + strconv.Itoa(len(fresh)) + " cloud"
		level := "warn"
		if denies > 0 {
			msg += " · " + strconv.Itoa(denies) + " DENIED"
			level = "bad"
		}
		p.pushLog(msg, level, now)
	default:
		p.pushLog("api "+strconv.Itoa(m.ms)+"ms · idle", "ok", now)
	}
	return p.afterBuffers(ctx)
}

// afterBuffers rebuilds the merged view and raises alerts for anything notable
// that arrived. In the Ink version this ran off the animation tick; running it
// where the buffers actually change is the same result with none of the
// re-scanning, and the seen-set makes it idempotent either way.
func (p *Live) afterBuffers(ctx PanelContext) tea.Cmd {
	p.rebuildMerged(ctx.Now.UnixMilli())
	return tea.Batch(p.notifySecurityEvents(ctx)...)
}

func (p *Live) apiError(err error, now int64) tea.Cmd {
	var ae *api.Error
	is429, isNet := false, false
	if e, ok := err.(*api.Error); ok {
		ae = e
		is429 = ae.Status == 429
		isNet = ae.Status == 0
	}
	switch {
	case is429 && now >= p.pausedUntil:
		p.pausedUntil = now + 30_000
		p.pushLog("rate limited by api · backing off 30s", "warn", now)
	case isNet:
		// Transient network blips (an idle socket, a resume) are common and
		// self-heal on the next poll — stay quiet unless it persists.
		p.netFails++
		if p.netFails == 3 {
			p.pushLog("network unreachable · retrying…", "warn", now)
		}
	case !is429:
		p.pushLog("api error · "+truncate(err.Error(), 40), "bad", now)
	}
	return nil
}

func (p *Live) pushLog(msg, level string, now int64) {
	p.events = append(p.events, logLine{ts: now, msg: msg, level: level})
	if len(p.events) > 60 {
		p.events = p.events[len(p.events)-60:]
	}
}

// rebuildMerged dedupes and orders the two planes.
//
// Denials (and some events) are written BOTH to the local file and to the cloud
// with a hashed session id, so the same call would show twice — and the cloud
// copy would read CLD even though it happened on this machine. Cloud entries
// matching a local entry on tool and decision within a minute are dropped; the
// richer local copy wins and is tagged LOC.
func (p *Live) rebuildMerged(now int64) {
	localKeys := map[string]bool{}
	for _, e := range p.local {
		m := int64(float64(e.At)/60_000 + 0.5)
		for _, d := range []int64{-1, 0, 1} {
			localKeys[e.Tool+"|"+e.Decision+"|"+strconv.FormatInt(m+d, 10)] = true
		}
	}
	merged := make([]streamItem, 0, len(p.cloud)+len(p.local))
	for _, e := range p.cloud {
		m := int64(float64(e.At)/60_000 + 0.5)
		if localKeys[e.Tool+"|"+e.Decision+"|"+strconv.FormatInt(m, 10)] {
			continue
		}
		merged = append(merged, e)
	}
	merged = append(merged, p.local...)
	sort.SliceStable(merged, func(i, j int) bool { return merged[i].At < merged[j].At })
	p.merged = merged
	p.sessRows = p.buildSessions(now)
}

func (p *Live) buildSessions(now int64) []sessRow {
	type agg struct {
		agent  string
		calls  int
		denies int
		lastAt int64
	}
	order := []string{}
	byID := map[string]*agg{}
	for _, e := range p.local {
		if e.Session == "" {
			continue
		}
		cur := byID[e.Session]
		if cur == nil {
			cur = &agg{agent: "local agent"}
			byID[e.Session] = cur
			order = append(order, e.Session)
		}
		cur.calls++
		if e.Decision != "ALLOW" {
			cur.denies++
		}
		if e.At > cur.lastAt {
			cur.lastAt = e.At
		}
		if e.Agent != "" {
			cur.agent = e.Agent
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return byID[order[i]].lastAt > byID[order[j]].lastAt })
	rows := make([]sessRow, 0, len(order)+len(p.sessions))
	for _, id := range order {
		v := byID[id]
		rows = append(rows, sessRow{
			source: "local", id: id, agent: v.agent, calls: v.calls, denies: v.denies,
			lastAt: v.lastAt, status: sessStatus(v.lastAt, now),
			isMe: p.ring != nil && p.ring.session == id,
		})
	}
	cloudSess := append([]api.LiveAgent(nil), p.sessions...)
	sort.SliceStable(cloudSess, func(i, j int) bool {
		a, _ := parseMillis(cloudSess[i].LastSeenAt)
		b, _ := parseMillis(cloudSess[j].LastSeenAt)
		return a > b
	})
	for _, a := range cloudSess {
		if _, ok := byID[a.SessionID]; ok {
			continue
		}
		last, _ := parseMillis(a.LastSeenAt)
		name := a.SessionID
		if a.AgentName != nil && *a.AgentName != "" {
			name = *a.AgentName
		}
		trust := a.TrustScore
		rows = append(rows, sessRow{
			source: "cloud", id: a.SessionID, agent: name, calls: a.TotalCalls,
			denies: a.DeniedCalls, lastAt: last, status: sessStatus(last, now), trust: &trust,
		})
	}
	return rows
}

// ── alerts and toasts ──────────────────────────────────────────────────────

// toastRank orders a batched summary by severity.
var toastRank = map[string]int{"DLP hit": 0, "Call denied": 1, "Rate-limit burst": 2}

// fireAlert raises the in-app banner, and queues the desktop toast.
//
// Toasts are BATCHED rather than dropped: a burst delivers many notable calls
// in one poll, and a plain per-event throttle would toast only the FIRST one
// (often a rate-limit burst) while silently swallowing the DLP hits behind it.
// Queue by title, flush 400ms later with at least 3s between flushes: one event
// gets its own detailed toast, several get one summary ordered by severity.
func (p *Live) fireAlert(id, title, msg, level string, desktop bool, ctx PanelContext) tea.Cmd {
	now := ctx.Now.UnixMilli()
	prefix := "⏸ "
	if level == "bad" {
		prefix = "⛔ "
	}
	p.pushLog(prefix+msg, level, now)
	kept := p.alerts[:0]
	for _, a := range p.alerts {
		if a.id != id {
			kept = append(kept, a)
		}
	}
	p.alerts = append(kept, alertBanner{id: id, msg: msg, level: level, until: now + 15_000})
	if len(p.alerts) > 4 {
		p.alerts = p.alerts[len(p.alerts)-4:]
	}
	// The in-app banner still shows with notifications off; only the bell and
	// the desktop toast are skipped.
	if !desktop || !ctx.Cfg.Notifications {
		return nil
	}
	if cur, ok := p.toastQueue[title]; ok {
		cur.count++
	} else {
		p.toastQueue[title] = &toastItem{count: 1, msg: msg}
		p.toastOrder = append(p.toastOrder, title)
	}
	if p.toastPending {
		return nil
	}
	p.toastPending = true
	return p.tickCmd(tickToast, 400*time.Millisecond)
}

func (p *Live) flushToasts(now int64) tea.Cmd {
	p.toastPending = false
	if len(p.toastOrder) == 0 {
		return nil
	}
	if wait := 3000 - (now - p.lastNotifyAt); wait > 0 {
		p.toastPending = true
		return p.tickCmd(tickToast, time.Duration(wait)*time.Millisecond)
	}
	p.lastNotifyAt = now
	titles := append([]string(nil), p.toastOrder...)
	sort.SliceStable(titles, func(i, j int) bool {
		ri, ok := toastRank[titles[i]]
		if !ok {
			ri = 9
		}
		rj, ok := toastRank[titles[j]]
		if !ok {
			rj = 9
		}
		return ri < rj
	})
	items := make([]*toastItem, len(titles))
	total := 0
	for i, t := range titles {
		items[i] = p.toastQueue[t]
		total += items[i].count
	}
	p.toastQueue = map[string]*toastItem{}
	p.toastOrder = nil

	bell()
	if len(titles) == 1 && total == 1 {
		go desktopNotify(titles[0], items[0].msg)
		return nil
	}
	parts := make([]string, len(titles))
	for i, t := range titles {
		parts[i] = strconv.Itoa(items[i].count) + "× " + t
	}
	go desktopNotify("Security alerts", strings.Join(parts, " · "))
	return nil
}

// notifySecurityEvents fires once per notable call that happened AFTER the
// panel opened.
//
// Gating on the call timestamp rather than on a "the first scan seeds the seen
// set" flag is what fixes the backlog spam: that flag armed on the empty first
// tick, before any data had loaded, so the whole historical backlog — arriving
// a tick later — counted as new and dumped a wall of toasts on every open.
func (p *Live) notifySecurityEvents(ctx PanelContext) []tea.Cmd {
	var cmds []tea.Cmd
	for _, e := range p.merged {
		if e.Decision == "ALLOW" && !e.DLP && !e.Burst {
			continue
		}
		if p.notified[e.ID] {
			continue
		}
		p.notified[e.ID] = true
		if e.At <= p.openedAt {
			continue // backlog, or a call from before the panel opened
		}
		who := ""
		if e.Agent != "" {
			who = " · " + truncate(e.Agent, 20)
		}
		switch {
		case e.DLP:
			cmds = append(cmds, p.fireAlert("sec:"+e.ID, "DLP hit",
				"SECRET in "+e.Tool+who+": "+truncate(e.Detail, 60), "bad", true, ctx))
		case e.Decision != "ALLOW":
			what := e.Rule
			if what == "" {
				what = e.Detail
			}
			cmds = append(cmds, p.fireAlert("sec:"+e.ID, "Call denied",
				"DENY "+e.Tool+who+": "+truncate(what, 60), "bad", true, ctx))
		case e.Burst:
			cmds = append(cmds, p.fireAlert("sec:"+e.ID, "Rate-limit burst",
				"BURST "+e.Tool+who, "warn", true, ctx))
		}
	}
	return cmds
}

// notifyIdleSessions raises a banner when a session stops calling. Banner only:
// an idle transition is routine, not a security event, and a bell plus a
// desktop toast here read as a false DLP or rate-limit alarm.
func (p *Live) notifyIdleSessions(ctx PanelContext) []tea.Cmd {
	var cmds []tea.Cmd
	for _, r := range p.sessRows {
		prev := p.prevStatus[r.id]
		if prev == "active" && r.status == "idle" {
			name := r.agent
			if r.isMe {
				name = r.agent + " (this machine)"
			}
			cmds = append(cmds, p.fireAlert("idle:"+r.id, "Agent idle",
				name+" went IDLE, no tool call for 60s", "warn", false, ctx))
		}
		p.prevStatus[r.id] = r.status
	}
	return cmds
}

// ── derived views over the buffer ──────────────────────────────────────────

func (p *Live) matches(e streamItem) bool {
	q := strings.ToLower(strings.TrimSpace(p.search))
	if q == "" {
		return true
	}
	hay := strings.ToLower(e.Tool + " " + e.Agent + " " + e.Decision + " " + e.Permission + " " + e.Rule + " " + e.Detail)
	return strings.Contains(hay, q)
}

func (p *Live) signalOK(e streamItem) bool {
	switch p.signal {
	case "deny":
		return e.Decision != "ALLOW"
	case "dlp":
		return e.DLP
	case "ratelimit":
		return e.Burst
	}
	return true
}

// filtered is the stream after the source, signal and search filters, oldest
// first.
func (p *Live) filtered() []streamItem {
	out := make([]streamItem, 0, len(p.merged))
	for _, e := range p.merged {
		switch p.filter {
		case "local":
			if !e.isLoc() {
				continue
			}
		case "cloud":
			if e.isLoc() {
				continue
			}
		}
		if !p.matches(e) || !p.signalOK(e) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// visibleDesc is every buffered entry that passes the filters, newest first, so
// the row count matches the loc/cld buffer totals in the status bar.
func (p *Live) visibleDesc() []streamItem {
	f := p.filtered()
	out := make([]streamItem, len(f))
	for i := range f {
		out[i] = f[len(f)-1-i]
	}
	return out
}

// detailEntries is a picked session's timeline: its cloud history plus
// everything in the merged buffer that belongs to it, newest first.
func (p *Live) detailEntries() []streamItem {
	if p.detail == nil {
		return nil
	}
	seen := map[string]bool{}
	var all []streamItem
	add := func(e streamItem) {
		key := strconv.FormatInt(e.At, 10) + ":" + e.Tool + ":" + e.Decision
		if seen[key] {
			return
		}
		seen[key] = true
		if p.matches(e) {
			all = append(all, e)
		}
	}
	for _, e := range p.detailCloud {
		add(e)
	}
	for _, e := range p.merged {
		if e.Session == p.detail.id {
			add(e)
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].At > all[j].At })
	return all
}

// ── keys ───────────────────────────────────────────────────────────────────

func (p *Live) onKey(k tea.KeyMsg, ctx PanelContext) tea.Cmd {
	now := ctx.Now.UnixMilli()
	if p.editingSearch {
		return p.editSearch(k)
	}
	str := k.String()

	// Copy mode first; while frozen only space resumes.
	if str == " " {
		p.frozen = !p.frozen
		return nil
	}
	if p.frozen {
		return nil
	}
	// `?` opens the full key reference from ANY mode; any key closes it.
	if p.help {
		p.help = false
		return nil
	}
	if str == "?" {
		p.help = true
		return nil
	}
	if str == "/" && p.mode != "pick" {
		p.editingSearch = true
		p.input.SetValue(p.search)
		p.input.CursorEnd()
		return p.input.Focus()
	}

	switch p.mode {
	case "inspect":
		switch k.Type {
		case tea.KeyLeft:
			p.mode = p.inspectFrom
			p.inspect = nil
		case tea.KeyUp:
			p.inspectScroll = maxInt(0, p.inspectScroll-1)
		case tea.KeyDown:
			p.inspectScroll++ // clamped at render
		case tea.KeyPgUp:
			p.inspectScroll = maxInt(0, p.inspectScroll-10)
		case tea.KeyPgDown:
			p.inspectScroll += 10
		}
		return nil

	case "layers":
		if k.Type == tea.KeyLeft || str == "l" {
			p.mode = "stream"
			return nil
		}
		switch k.Type {
		case tea.KeyUp:
			p.layersScroll = maxInt(0, p.layersScroll-1)
		case tea.KeyDown:
			p.layersScroll++
		case tea.KeyPgUp:
			p.layersScroll = maxInt(0, p.layersScroll-10)
		case tea.KeyPgDown:
			p.layersScroll += 10
		}
		return nil

	case "detail":
		entries := p.detailEntries()
		maxD := maxInt(0, len(entries)-1)
		switch k.Type {
		case tea.KeyLeft:
			p.mode = "stream"
			p.detail = nil
		case tea.KeyUp:
			p.detailScroll = maxInt(0, p.detailScroll-1)
		case tea.KeyDown:
			p.detailScroll = minInt(maxD, p.detailScroll+1)
		case tea.KeyPgUp:
			p.detailScroll = maxInt(0, p.detailScroll-10)
		case tea.KeyPgDown:
			p.detailScroll = minInt(maxD, p.detailScroll+10)
		case tea.KeyEnter:
			if len(entries) > 0 {
				e := entries[minInt(p.detailScroll, maxD)]
				p.inspectFrom = "detail"
				p.inspect = &e
				p.inspectScroll = 0
				p.mode = "inspect"
			}
		}
		return nil

	case "pick":
		pickable := p.pickable(p.colHeight(ctx))
		switch {
		case k.Type == tea.KeyUp:
			p.pickIdx = maxInt(0, p.pickIdx-1)
		case k.Type == tea.KeyDown:
			p.pickIdx = minInt(len(pickable)-1, p.pickIdx+1)
		case k.Type == tea.KeyEnter:
			if p.pickIdx >= 0 && p.pickIdx < len(pickable) {
				row := pickable[p.pickIdx]
				p.detail = &row
				p.detailCloud = nil
				p.detailScroll = 0
				p.mode = "detail"
				return p.fetchSessionHistory(row.id)
			}
		case str == "s" || k.Type == tea.KeyLeft:
			p.mode = "stream"
		}
		return nil
	}

	// stream mode
	visible := p.visibleDesc()
	streamBody := maxInt(3, p.streamRows(ctx)-1)
	toggleSignal := func(s string) {
		if p.signal == s {
			p.signal = "none"
		} else {
			p.signal = s
		}
		p.sel = 0
	}
	switch {
	case str == "f":
		switch p.filter {
		case "all":
			p.filter = "local"
		case "local":
			p.filter = "cloud"
		default:
			p.filter = "all"
		}
		p.sel = 0
	case k.Type == tea.KeyEnter:
		if e, ok := p.selected(visible); ok {
			p.inspectFrom = "stream"
			p.inspect = &e
			p.inspectScroll = 0
			p.mode = "inspect"
		}
	case str == "s":
		p.pickIdx = 0
		p.mode = "pick"
	case str == "l":
		p.layersScroll = 0
		p.mode = "layers"
	case str == "w":
		return p.doAction("whitelist", visible, now)
	case str == "b":
		return p.doAction("block", visible, now)
	case str == "d":
		toggleSignal("deny")
	case str == "x":
		toggleSignal("dlp")
	case str == "r":
		toggleSignal("ratelimit")
	case str == "e":
		p.export(visible, now)
	case k.Type == tea.KeyDown:
		p.sel = minInt(len(visible)-1, p.sel+1)
	case k.Type == tea.KeyUp:
		p.sel = maxInt(0, p.sel-1)
	case k.Type == tea.KeyPgDown:
		p.sel = minInt(len(visible)-1, p.sel+streamBody)
	case k.Type == tea.KeyPgUp:
		p.sel = maxInt(0, p.sel-streamBody)
	}
	return nil
}

// editSearch is the live search bar. `/` and enter both finish; esc cancels the
// editing without discarding the query, which is the one key Ink's text input
// did not answer at all.
func (p *Live) editSearch(k tea.KeyMsg) tea.Cmd {
	switch k.Type {
	case tea.KeyEnter, tea.KeyEsc:
		p.editingSearch = false
		p.input.Blur()
		return nil
	}
	var cmd tea.Cmd
	p.input, cmd = p.input.Update(k)
	v := p.input.Value()
	if strings.HasSuffix(v, "/") {
		p.editingSearch = false
		p.input.SetValue(strings.TrimSuffix(v, "/"))
		p.input.Blur()
		return nil
	}
	if v != p.search {
		p.search = v
		p.sel = 0
		p.detailScroll = 0
	}
	return cmd
}

func (p *Live) selected(visible []streamItem) (streamItem, bool) {
	if len(visible) == 0 {
		return streamItem{}, false
	}
	i := minInt(maxInt(0, p.sel), len(visible)-1)
	return visible[i], true
}

// doAction whitelists the selected DENY or blocks the selected ALLOW.
//
// Cloud entries go through the audit endpoints, which resolve the agent to its
// policy; local entries add a rule to this machine's active policy directly.
func (p *Live) doAction(act string, visible []streamItem, now int64) tea.Cmd {
	e, ok := p.selected(visible)
	if !ok {
		return nil
	}
	valid := e.Decision != "ALLOW"
	if act == "block" {
		valid = e.Decision == "ALLOW"
	}
	if !valid {
		text := "select a DENY to whitelist (w)"
		if act == "block" {
			text = "select an ALLOW to block (b)"
		}
		p.action = &flashMsg{text: text, level: "bad", until: now + 4000}
		return nil
	}
	verb := "ALLOW"
	if act == "block" {
		verb = "DENY"
	}
	p.action = &flashMsg{text: map[string]string{"whitelist": "whitelisting…", "block": "blocking…"}[act],
		level: "ok", until: now + 4000}

	gen, client := p.gen, p.deps.API
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		fail := func(err error) tea.Msg {
			return liveActionResult{gen: gen, text: "✗ " + err.Error(), level: "bad"}
		}
		// Active-policy gate for BOTH sources, mirroring the API: with no policy
		// active nothing is granted — not allow, not deny. Resolved fresh on
		// every action so deactivating in the dashboard applies immediately.
		active, err := client.Policies.Active(ctx, "")
		if err != nil {
			return fail(err)
		}
		if active.Policy == nil || active.Policy.ID == "" {
			return liveActionResult{gen: gen, level: "bad",
				text: "✗ no active policy — rule NOT added. Activate a policy first (Policies section)."}
		}
		var res api.RuleMutation
		if e.Source == "cloud" {
			realID := strings.TrimPrefix(e.ID, "c:")
			if act == "whitelist" {
				res, err = client.Audit.Whitelist(ctx, realID, "")
			} else {
				res, err = client.Audit.Block(ctx, realID, "")
			}
		} else {
			spec := api.RuleSpec{ToolPattern: e.Tool, Kind: "tool", Effect: verb}
			if kind, value, ok := extractTarget(e.Detail); ok {
				spec.Kind, spec.Value = kind, value
			}
			res, err = client.Policies.AddRule(ctx, active.Policy.ID, spec)
		}
		if err != nil {
			return fail(err)
		}
		text := verb + " rule already present"
		if !res.Deduped {
			pid := res.PolicyID
			if pid == "" {
				pid = "?"
			}
			version := ""
			if res.PolicyVersion > 0 {
				version = " v" + strconv.Itoa(res.PolicyVersion)
			}
			text = verb + " rule added → " + pid + version + " · reaches agents in ~30s"
		}
		logText, logLevel := "✓ whitelisted "+e.Tool, "ok"
		if act == "block" {
			logText, logLevel = "⛔ blocked "+e.Tool, "warn"
		}
		return liveActionResult{gen: gen, text: text, level: "ok", logText: logText, logLevel: logLevel}
	}
}

// extractTarget pulls a command, path or url out of a stringified arguments
// summary, so a rule added from a local row is about the thing that was run
// rather than about the tool as a whole.
func extractTarget(detail string) (kind, value string, ok bool) {
	var j map[string]any
	if json.Unmarshal([]byte(detail), &j) != nil {
		return "", "", false
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, found := j[k]; found {
				if s, isStr := v.(string); isStr {
					if s = strings.TrimSpace(s); s != "" {
						return s
					}
				}
			}
		}
		return ""
	}
	if cmd := str("command", "cmd"); cmd != "" {
		return "command", cmd, true
	}
	if fp := str("file_path", "path"); fp != "" {
		base := fp
		if i := strings.LastIndexAny(fp, `/\`); i >= 0 && i+1 < len(fp) {
			base = fp[i+1:]
		}
		return "path", base, true
	}
	if url := str("url"); url != "" {
		return "url", url, true
	}
	return "", "", false
}

func (p *Live) export(visible []streamItem, now int64) {
	dir := config.Dir()
	file := filepath.Join(dir, "live-export.jsonl")
	var b strings.Builder
	for _, e := range visible {
		line, err := json.Marshal(e)
		if err != nil {
			continue
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		p.action = &flashMsg{text: "✗ export failed: " + err.Error(), level: "bad", until: now + 6000}
		return
	}
	if err := os.WriteFile(file, []byte(b.String()), 0o644); err != nil {
		p.action = &flashMsg{text: "✗ export failed: " + err.Error(), level: "bad", until: now + 6000}
		return
	}
	p.action = &flashMsg{
		text:  "✓ exported " + strconv.Itoa(len(visible)) + " lines → " + file,
		level: "ok", until: now + 6000,
	}
}

// ── layout budget ──────────────────────────────────────────────────────────

// The WHOLE frame must fit in ctx.Rows, which the shell already set to one less
// than the terminal's height. At the terminal's full height Ink abandoned
// in-place diffing and did clearTerminal plus a full rewrite on every render —
// a constant flicker that showed up as "glitching" as soon as bright content
// (rate-limit and DLP columns, alert banners) was on screen. The thresholds
// below are the terminal heights from the TypeScript, minus that one row.
func (p *Live) chartHeight(ctx PanelContext) int {
	if ctx.Rows >= 35 {
		return 6
	}
	return 4
}

func (p *Live) colHeight(ctx PanelContext) int {
	if ctx.Rows >= 31 {
		return 7
	}
	return 5
}

func (p *Live) bannerRows(now int64) int {
	n := 0
	if p.activeAlert(now) != nil {
		n++
	}
	if p.activeAction(now) != nil {
		n++
	}
	return n
}

func (p *Live) streamRows(ctx PanelContext) int {
	return maxInt(4, ctx.Rows-5-(1+p.chartHeight(ctx))-p.colHeight(ctx)-p.bannerRows(ctx.Now.UnixMilli()))
}

func (p *Live) activeAlert(now int64) *alertBanner {
	for i := len(p.alerts) - 1; i >= 0; i-- {
		if now < p.alerts[i].until {
			return &p.alerts[i]
		}
	}
	return nil
}

func (p *Live) activeAction(now int64) *flashMsg {
	if p.action != nil && now < p.action.until {
		return p.action
	}
	return nil
}

// pickable is the SESSIONS column: as many rows as fit under its pane title,
// and the same list the picker moves through, so what `s` selects is always
// what is on screen.
func (p *Live) pickable(colH int) []sessRow {
	n := colH - 1
	if n > len(p.sessRows) {
		n = len(p.sessRows)
	}
	if n < 0 {
		n = 0
	}
	return p.sessRows[:n]
}

// ── rendering ──────────────────────────────────────────────────────────────

// Hint is what the boxed layout shows while Live is selected but not opened.
func (p *Live) Hint(ctx PanelContext) string {
	return strings.Join([]string{
		renderRow(ctx.Cols, sgb("▶ REALTIME CONSOLE — THIS MACHINE", theme.AccentBright)),
		renderRow(ctx.Cols, sg("Fullscreen live monitor — streaming tool calls, active charts,", theme.Dim)),
		renderRow(ctx.Cols, sg("counters, DLP hits and denial alerts. Updates every 2s.", theme.Dim)),
		"",
		renderRow(ctx.Cols, plain("press "), sg("enter", theme.Accent), plain(" to go live")),
	}, "\n")
}

func (p *Live) View(ctx PanelContext) string {
	now := ctx.Now.UnixMilli()
	innerW := ctx.Cols - 2
	if innerW < 20 {
		innerW = 20
	}
	spin := spinFrames[p.tick%len(spinFrames)]

	if p.stats == nil && p.localOn == nil {
		return renderRow(ctx.Cols, sg(spin+" connecting…", theme.Dim))
	}

	var lines []string
	switch {
	case p.help:
		lines = p.viewHelp(ctx, innerW, now)
	case p.mode == "inspect" && p.inspect != nil:
		lines = p.viewInspect(ctx, innerW, now)
	case p.mode == "layers":
		lines = p.viewLayers(ctx, innerW, now, spin)
	case p.mode == "detail" && p.detail != nil:
		lines = p.viewDetail(ctx, innerW, now, spin)
	default:
		lines = p.viewMain(ctx, innerW, now, spin)
	}
	for i := range lines {
		lines[i] = " " + lines[i] // paddingX = 1
	}
	// The console clips itself rather than trusting the shell to do it. Two
	// places genuinely round UP: the three lower columns have a 20-column floor
	// each, and the stream has a four-row floor, so on a small terminal the
	// budget cannot be met and something has to go. Losing the footer is what
	// Ink's overflow hidden did; growing the frame is what costs the render
	// path.
	return clampBlock(strings.Join(lines, "\n"), ctx.Cols, ctx.Rows)
}

func (p *Live) titleBar(ctx PanelContext, width int, now int64, spin string) string {
	segs := []seg{
		{text: " SOLONGATE LIVE ", fg: lipgloss.Color("15"), bg: lipgloss.Color(hexTitleBG), bold: true},
		{text: " " + spin + " up " + fmtUp(now-p.start.UnixMilli()) + " · " + hhmmss(now) +
			" · api " + strconv.Itoa(p.latNow()) + "ms ", fg: theme.White, bg: lipgloss.Color(hexPanelBG)},
	}
	lastDeny := p.lastDeny()
	switch {
	case p.frozen:
		segs = append(segs, seg{text: " ⏵ COPY MODE — screen frozen, select & copy freely · space resume ",
			fg: lipgloss.Color(hexOKFG), bg: lipgloss.Color(hexOKBG), bold: true})
	case now < p.pausedUntil:
		segs = append(segs, seg{text: " RATE LIMITED · backing off ",
			fg: lipgloss.Color(hexWarnFG), bg: lipgloss.Color(hexWarnBG), bold: true})
	case lastDeny != nil:
		segs = append(segs, seg{text: " ⚠ " + hhmmss(lastDeny.At) + " " + lastDeny.Tool + " DENIED ",
			fg: lipgloss.Color(hexBadFG), bg: lipgloss.Color(hexBadBG), bold: true})
	default:
		segs = append(segs, seg{text: " ✓ clean ", fg: theme.White, bg: lipgloss.Color(hexPanelBG)})
	}
	return renderRow(width, segs...)
}

func (p *Live) latNow() int {
	if len(p.lat) == 0 {
		return 0
	}
	return p.lat[len(p.lat)-1]
}

func (p *Live) latMedian() int {
	if len(p.lat) == 0 {
		return 0
	}
	s := append([]int(nil), p.lat...)
	sort.Ints(s)
	return s[len(s)/2]
}

func (p *Live) lastDeny() *streamItem {
	for i := len(p.merged) - 1; i >= 0; i-- {
		if p.merged[i].Decision != "ALLOW" {
			return &p.merged[i]
		}
	}
	return nil
}

// searchRow is ALWAYS the first line under a stream or timeline title, never
// hidden, so it is obvious where to type. `/` focuses it; while focused the
// text input takes over, otherwise it shows the query or the hint.
func (p *Live) searchRow(width, matchCount int) string {
	segs := []seg{{text: "⌕ search: ", fg: theme.Dim, bold: p.editingSearch}}
	if p.editingSearch {
		segs[0].fg = theme.Warn
		return renderRow(width, segs...) +
			p.input.View() +
			renderRow(0, sg("  "+strconv.Itoa(matchCount)+" match · enter// done · empty clears", theme.Dim))
	}
	if p.search != "" {
		segs = append(segs,
			sgb(p.search, theme.AccentBright),
			sg("  "+strconv.Itoa(matchCount)+" match · press / to edit · type to clear", theme.Dim))
		return renderRow(width, segs...)
	}
	segs = append(segs, sg("press / to filter the stream by tool, agent, command…", theme.Dim))
	return renderRow(width, segs...)
}

var liveHelp = []helpGroup{
	{"Stream", [][2]string{
		{"↑↓ / PgUp PgDn", "select a row (window follows)"},
		{"enter", "open the FULL entry content"},
		{"w", "whitelist the selected DENY (adds ALLOW rule)"},
		{"b", "block the selected ALLOW (adds DENY rule)"},
		{"d / x / r", "filter: denies / dlp hits / rate-limit bursts"},
		{"f", "source: all → LOC (this machine's local log) → CLD (cloud)"},
		{"/", "live search (tool, agent, command…) · enter done"},
		{"s", "session picker"},
		{"l", "layers detail (rate limit · dlp · ghost · guard)"},
		{"e", "export visible rows → ~/.solongate/live-export.jsonl"},
		{"space", "copy mode: freeze screen for mouse selection"},
		{"esc", "back to menu"},
		{"q", "quit dataroom"},
	}},
	{"Entry (full content)", [][2]string{
		{"↑↓ / PgUp PgDn", "scroll the content"},
		{"space", "copy mode (freeze, then select with mouse)"},
		{"←", "back to where you came from"},
	}},
	{"Sessions", [][2]string{
		{"↑↓ + enter", "pick & open a session (picker)"},
		{"s or ←", "cancel the picker"},
		{"↑↓", "select a timeline row (detail)"},
		{"enter", "full entry content of the selected row"},
		{"/", "search within the timeline"},
		{"←", "back to stream"},
	}},
	{"Anywhere", [][2]string{{"?", "this help"}, {"any key", "close this help"}}},
}

func (p *Live) viewHelp(ctx PanelContext, width int, now int64) []string {
	lines := []string{
		p.titleBar(ctx, width, now, spinFrames[p.tick%len(spinFrames)]),
		renderRow(width, sgb("LIVE — all keys", theme.AccentBright)),
		"",
	}
	lines = append(lines, helpBlock(liveHelp, 20, width)...)
	return append(lines, renderRow(width, sg("press any key to close", theme.Dim)))
}

// viewInspect is the FULL content of one log line.
func (p *Live) viewInspect(ctx PanelContext, width int, now int64) []string {
	e := *p.inspect
	bodyW := maxInt(20, ctx.Cols-4)
	detail := e.Detail
	if strings.TrimSpace(detail) == "" {
		detail = "(no arguments / reason recorded)"
	}
	content := wrapLines(prettyJson(detail), bodyW)
	bodyRows := maxInt(4, ctx.Rows-6) // title + 3 header rows + pane title + footer
	maxScroll := maxInt(0, len(content)-bodyRows)
	off := minInt(p.inspectScroll, maxScroll)

	locLabel, locColor := "CLD", theme.White
	if e.isLoc() {
		locLabel, locColor = "LOC", theme.OK
	}
	head := []seg{
		{text: " ENTRY ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
		sgb("  "+e.Decision, decisionColor(e.Decision)),
		sgb("  "+e.Tool, theme.Accent),
		sg("  "+locLabel, locColor),
	}
	if e.DLP {
		head = append(head, sg("  DLP!", theme.Bad))
	}
	if e.Burst {
		head = append(head, sg("  BURST", theme.Warn))
	}
	head = append(head, sg("  ← back", theme.Dim))

	evalText := "—"
	evalColor := lipgloss.TerminalColor(nil)
	if e.EvalMs != nil {
		evalText = num(*e.EvalMs) + "ms"
		if *e.EvalMs > 500 {
			evalColor = theme.Warn
		}
	}
	perm := e.Permission
	if perm == "" {
		perm = "—"
	}
	agent := e.Agent
	if agent == "" {
		agent = "—"
	}
	session := e.Session
	if session == "" {
		session = "—"
	}
	rule := e.Rule
	ruleColor := lipgloss.TerminalColor(theme.Dim)
	if rule == "" {
		rule = "—"
	} else if e.Decision != "ALLOW" {
		ruleColor = theme.Bad
	}

	scrollNote := ""
	if maxScroll > 0 {
		scrollNote = " · ▼" + strconv.Itoa(maxScroll-off) + " more · ↑↓ scroll"
	}

	lines := []string{
		p.titleBar(ctx, width, now, spinFrames[p.tick%len(spinFrames)]),
		renderRow(width, head...),
		renderRow(width,
			sg("│ when ", theme.Dim), plain(time.UnixMilli(e.At).Format("2006-01-02 15:04:05")),
			sg(" │ perm ", theme.Dim), plain(perm),
			sg(" │ eval ", theme.Dim), seg{text: evalText, fg: evalColor},
			sg(" │ agent ", theme.Dim), plain(agent),
			sg(" │", theme.Dim)),
		renderRow(width,
			sg("│ session ", theme.Dim), sg(session, theme.Dim),
			sg(" │ rule ", theme.Dim), seg{text: rule, fg: ruleColor},
			sg(" │", theme.Dim)),
		paneTitle("FULL CONTENT",
			strconv.Itoa(len(content))+" lines"+scrollNote+" · space copy · ← back", width),
	}
	for i := 0; i < bodyRows; i++ {
		if off+i >= len(content) {
			lines = append(lines, "")
			continue
		}
		lines = append(lines, renderRow(width, plain(content[off+i])))
	}
	return append(lines, renderRow(width,
		seg{text: " ENTRY ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
		seg{text: " " + e.ID + " ", fg: theme.White, bg: lipgloss.Color(hexFooterBG)},
		seg{text: " ↑↓ scroll · space copy · ? all keys · ← back · esc menu ",
			fg: theme.White, bg: lipgloss.Color(hexPanelBG)}))
}

// viewLayers is the full security-layer configuration.
func (p *Live) viewLayers(ctx PanelContext, width int, now int64, spin string) []string {
	rl := p.insights.Layers.RateLimit
	dl := p.insights.Layers.DLP
	gh := p.insights.Layers.Ghost
	barW := maxInt(10, minInt(40, width-30))

	var body []string
	push := func(s string) { body = append(body, s) }
	section := func(label, mode, note string) {
		m := mode
		if m == "" {
			m = "?"
		}
		segs := []seg{sgb("▎"+padEnd(label, 10), theme.AccentBright), sgb(padEnd(m, 8), modeColor(mode))}
		if note != "" {
			segs = append(segs, sg(note, theme.Dim))
		}
		push(renderRow(width, segs...))
	}
	kv := func(k string, value seg) {
		push(renderRow(width, sg(padEnd("  "+k, 16), theme.Dim), value))
	}

	burstsInBuf, dlpInBuf, minuteNow := 0, 0, 0
	for _, e := range p.merged {
		if e.Burst {
			burstsInBuf++
		}
		if e.DLP {
			dlpInBuf++
		}
		if now-e.At < 60_000 {
			minuteNow++
		}
	}

	rlMode, rlNote := "", "no limit enforcement"
	if rl != nil {
		rlMode = rl.Mode
		switch rl.Mode {
		case "block":
			rlNote = "over-limit calls are DENIED"
		case "detect":
			rlNote = "over-limit calls are observed & flagged rl:yes"
		}
	}
	section("RATELIMIT", rlMode, rlNote)
	limits := "none configured"
	if rl != nil && (rl.PerMinute != 0 || rl.PerHour != 0 || rl.PerDay != 0) {
		limits = orDash(rl.PerMinute) + "/min · " + orDash(rl.PerHour) + "/hour · " + orDash(rl.PerDay) + "/day"
	}
	kv("limits", plain(limits))
	kv("load now", plain(strconv.Itoa(minuteNow)+" calls in the last 60s"))
	if rl != nil && rl.PerMinute > 0 {
		color := lipgloss.TerminalColor(theme.Accent)
		if minuteNow > rl.PerMinute {
			color = theme.Bad
		}
		push(hbar("  load/min", minuteNow, rl.PerMinute, barW, color, width))
	}
	burstColor := lipgloss.TerminalColor(theme.Dim)
	if burstsInBuf > 0 {
		burstColor = theme.Warn
	}
	kv("bursts", seg{text: strconv.Itoa(burstsInBuf) + " flagged in the live buffer", fg: burstColor})
	push("")

	dlMode, dlNote := "", "no secret scanning"
	if dl != nil {
		dlMode = dl.Mode
		switch dl.Mode {
		case "block":
			dlNote = "secrets in arguments are DENIED + redacted"
		case "detect":
			dlNote = "secrets observed & flagged dlp:yes, output redacted"
		}
	}
	section("DLP", dlMode, dlNote)
	dlpColor := lipgloss.TerminalColor(theme.Dim)
	if dlpInBuf > 0 {
		dlpColor = theme.Bad
	}
	kv("hits", seg{text: strconv.Itoa(dlpInBuf) + " flagged in the live buffer", fg: dlpColor})
	var builtin []string
	if dl != nil {
		builtin = dl.Patterns
	}
	if len(builtin) > 0 {
		kv("builtin", plain(strconv.Itoa(len(builtin))+" patterns enabled"))
	} else {
		kv("builtin", plain("none enabled"))
	}
	for _, line := range wrapLines(strings.Join(builtin, " · "), maxInt(20, width-18)) {
		if line == "" {
			continue
		}
		push(renderRow(width, sg("                "+line, theme.Dim)))
	}
	customCount := 0
	if dl != nil {
		customCount = len(dl.Custom)
	}
	if customCount > 0 {
		kv("custom", plain(strconv.Itoa(customCount)+" patterns"))
		for _, c := range dl.Custom {
			name := c.Name
			if name == "" {
				name = "custom"
			}
			push(renderRow(width,
				sg("                ", theme.Dim),
				sg(padEnd(truncate(name, 24), 25), theme.Accent),
				sg(truncate(c.Re, maxInt(10, width-44)), theme.Dim)))
		}
	} else {
		kv("custom", plain("none"))
	}
	hits := p.insights.DLPByPattern
	if len(hits) > 0 {
		kv("pattern hits", sg("last 7 days", theme.Dim))
	} else {
		kv("pattern hits", sg("none in the last 7 days", theme.Dim))
	}
	maxHit := 1
	if len(hits) > 0 && hits[0].Count > 0 {
		maxHit = hits[0].Count
	}
	for _, h := range hits {
		push(hbar("  "+truncate(h.Pattern, 10), h.Count, maxHit, barW, theme.Bad, width))
	}
	push("")

	ghMode, ghNote := "", "no hidden paths"
	if gh != nil {
		ghMode = gh.Mode
		if gh.Mode == "on" {
			ghNote = "matching paths are hidden from agents"
		}
	}
	section("GHOST", ghMode, ghNote)
	var ghostPats []string
	if gh != nil {
		ghostPats = gh.Patterns
	}
	if len(ghostPats) > 0 {
		kv("patterns", plain(strconv.Itoa(len(ghostPats))))
	} else {
		kv("patterns", plain("none"))
	}
	for _, line := range wrapLines(strings.Join(ghostPats, " · "), maxInt(20, width-18)) {
		if line == "" {
			continue
		}
		push(renderRow(width, sg("                "+line, theme.Dim)))
	}
	push("")

	guardMode := "?"
	if p.guard != nil {
		guardMode = "stale"
		if p.guard.UpToDate {
			guardMode = "ok"
		}
	}
	section("GUARD", guardMode, "the PreToolUse hook enforcing all of the above")
	if p.guard != nil {
		installed := "?"
		if p.guard.Installed != nil {
			installed = strconv.Itoa(*p.guard.Installed)
		}
		state := " (latest)"
		color := lipgloss.TerminalColor(theme.OK)
		if !p.guard.UpToDate {
			state = " → v" + strconv.Itoa(p.guard.Latest) + " available"
			color = theme.Warn
		}
		devices := " device"
		if p.guard.DeviceCount != 1 {
			devices = " devices"
		}
		kv("hooks", seg{text: "v" + installed + state + " · " + strconv.Itoa(p.guard.DeviceCount) + devices, fg: color})
	} else {
		kv("hooks", sg("loading…", theme.Dim))
	}
	if p.ring != nil {
		kv("local eval", sg("avg "+strconv.Itoa(p.ring.avgMs)+"ms over "+strconv.Itoa(p.ring.count)+" recent calls", theme.OK))
	} else {
		kv("local eval", sg("no local ring in cwd", theme.Dim))
	}

	bodyRows := maxInt(4, ctx.Rows-4)
	maxScroll := maxInt(0, len(body)-bodyRows)
	off := minInt(p.layersScroll, maxScroll)

	extra := ""
	if !p.insightsLoaded {
		extra += spin + " loading · "
	}
	if maxScroll > 0 {
		extra += "▼" + strconv.Itoa(maxScroll-off) + " more · ↑↓ scroll · "
	}
	extra += "l or ← back"

	lines := []string{
		p.titleBar(ctx, width, now, spin),
		renderRow(width,
			seg{text: " LAYERS ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
			sg("  security layers, limits and patterns · insights window: last 7 days", theme.Dim),
			sg("  ← back", theme.Dim)),
		paneTitle("LAYERS", extra, width),
	}
	for i := 0; i < bodyRows; i++ {
		if off+i >= len(body) {
			lines = append(lines, "")
			continue
		}
		lines = append(lines, body[off+i])
	}
	return append(lines, renderRow(width,
		seg{text: " LAYERS ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
		seg{text: " rate limit · dlp · ghost · guard ", fg: theme.White, bg: lipgloss.Color(hexFooterBG)},
		seg{text: " ↑↓ scroll · ? all keys · ← back · esc menu ", fg: theme.White, bg: lipgloss.Color(hexPanelBG)}))
}

func orDash(n int) string {
	if n == 0 {
		return "—"
	}
	return strconv.Itoa(n)
}

// viewDetail is one session, dashboard style: a summary and the full timeline.
func (p *Live) viewDetail(ctx PanelContext, width int, now int64, spin string) []string {
	d := p.detailEntries()
	allow, dlpN := 0, 0
	evalSum, evalN := 0.0, 0
	tools, perms := newCounter(), newCounter()
	for _, e := range d {
		if e.Decision == "ALLOW" {
			allow++
		}
		if e.DLP {
			dlpN++
		}
		if e.EvalMs != nil {
			evalSum += *e.EvalMs
			evalN++
		}
		tools.add(e.Tool)
		if e.Permission != "" {
			perms.add(e.Permission)
		}
	}
	deny := len(d) - allow
	evalAvg := "—"
	if evalN > 0 {
		evalAvg = strconv.Itoa(int(evalSum/float64(evalN)+0.5)) + "ms"
	}
	top := tools.sorted()
	if len(top) > 6 {
		top = top[:6]
	}
	var first, last int64
	if len(d) > 0 {
		first, last = d[len(d)-1].At, d[0].At
	}

	tlRows := maxInt(4, ctx.Rows-9)
	tlBody := maxInt(3, tlRows-1) // a line is reserved for the search bar
	dSel := minInt(p.detailScroll, maxInt(0, len(d)-1))
	maxStart := maxInt(0, len(d)-tlBody)
	start := minInt(maxInt(0, dSel-(tlBody-1)/2), maxStart)

	st := statusStyleOf(sessStatus(p.detail.lastAt, now))
	agentLabel := p.detail.agent
	if p.detail.isMe {
		agentLabel = p.detail.agent + " (this machine)"
	}
	head := []seg{
		{text: " SESSION " + firstN(p.detail.id, 8) + " ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
		sgb("  "+st.dot+" "+st.label, st.color),
	}
	sourceColor := lipgloss.TerminalColor(theme.White)
	if p.detail.source == "local" {
		sourceColor = theme.OK
	}
	head = append(head,
		seg{text: "  " + strings.ToUpper(p.detail.source), fg: sourceColor},
		seg{text: "  " + truncate(agentLabel, 34), bold: true})
	if p.detail.trust != nil {
		head = append(head, sg("  trust "+num(*p.detail.trust)+"/100", theme.Dim))
	}
	head = append(head, sg("  ← back", theme.Dim))

	denyColor := lipgloss.TerminalColor(theme.Dim)
	if deny > 0 {
		denyColor = theme.Bad
	}
	dlpColor := lipgloss.TerminalColor(theme.Dim)
	if dlpN > 0 {
		dlpColor = theme.Bad
	}
	lines := []string{
		p.titleBar(ctx, width, now, spin),
		renderRow(width, head...),
		renderRow(width,
			sg("│ calls ", theme.Dim), seg{text: strconv.Itoa(len(d)), bold: true},
			sg(" │ allow ", theme.Dim), sg(strconv.Itoa(allow), theme.OK),
			sg(" │ deny ", theme.Dim), seg{text: strconv.Itoa(deny), fg: denyColor, bold: deny > 0},
			sg(" │ dlp ", theme.Dim), seg{text: strconv.Itoa(dlpN), fg: dlpColor},
			sg(" │ avg eval ", theme.Dim), plain(evalAvg),
			sg(" │ first ", theme.Dim), sg(stampAgo(first, now), theme.Dim),
			sg(" │ last ", theme.Dim), sg(stampAgo(last, now), theme.Dim),
			sg(" │", theme.Dim)),
		renderRow(width,
			sg("│ tools ", theme.Dim), sg(joinCounts(top, "  "), theme.Accent),
			sg(" │ perms ", theme.Dim), sg(joinCounts(perms.sorted(), " "), theme.Dim),
			sg(" │", theme.Dim)),
		paneTitle("TIMELINE", strconv.Itoa(dSel+1)+"/"+strconv.Itoa(len(d))+
			" · newest first · ↑↓ select · enter full entry · / search · ← back", width),
	}

	tl := []string{p.searchRow(width, len(d))}
	if len(d) == 0 {
		if len(p.detailCloud) == 0 {
			tl = append(tl, renderRow(width, sg(spin+" loading history…", theme.Dim)))
		} else {
			tl = append(tl, renderRow(width, sg("no entries", theme.Dim)))
		}
	}
	for i := 0; i < tlBody && start+i < len(d); i++ {
		e := d[start+i]
		tl = append(tl, streamLine(e.row(), e.isLoc(), start+i == dSel, false, width))
	}
	for i := 0; i < tlRows; i++ {
		if i < len(tl) {
			lines = append(lines, tl[i])
		} else {
			lines = append(lines, "")
		}
	}
	return append(lines, renderRow(width,
		seg{text: " SESSION ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
		seg{text: " " + p.detail.id + " ", fg: theme.White, bg: lipgloss.Color(hexFooterBG)},
		seg{text: " ↑↓ select · enter full entry · ? all keys · ← back · esc menu ",
			fg: theme.White, bg: lipgloss.Color(hexPanelBG)}))
}

func stampAgo(at, now int64) string {
	if at == 0 {
		return "—"
	}
	return hhmmss(at) + " (" + agoAt(at, time.UnixMilli(now)) + " ago)"
}

func (p *Live) viewMain(ctx PanelContext, width int, now int64, spin string) []string {
	chartH := p.chartHeight(ctx)
	colH := p.colHeight(ctx)
	streamRows := p.streamRows(ctx)
	leftW := width * 55 / 100
	rightW := width - leftW - 2
	colW := maxInt(20, (width-4)/3)

	rl := p.insights.Layers.RateLimit
	dl := p.insights.Layers.DLP
	gh := p.insights.Layers.Ghost

	minuteNow := 0
	for _, e := range p.merged {
		if now-e.At < 60_000 {
			minuteNow++
		}
	}

	lines := []string{p.titleBar(ctx, width, now, spin)}

	// counters
	counters := []seg{sg("│ calls ", theme.Dim)}
	if p.stats != nil {
		counters = append(counters,
			seg{text: strconv.Itoa(p.stats.TotalCalls), bold: true},
			sg(" │ allow ", theme.Dim), sg(strconv.Itoa(p.stats.Allowed), theme.OK),
			sg(" │ deny ", theme.Dim), sgb(strconv.Itoa(p.stats.Denied), theme.Bad))
	} else {
		counters = append(counters,
			seg{text: "····", bold: true},
			sg(" │ allow ", theme.Dim), sg("···", theme.OK),
			sg(" │ deny ", theme.Dim), sgb("··", theme.Bad))
	}
	counters = append(counters, sg(" │ local ", theme.Dim))
	if p.localOn != nil && *p.localOn {
		counters = append(counters, sg("✓", theme.OK))
	} else {
		counters = append(counters, sg("off", theme.Dim))
	}
	counters = append(counters,
		sg(" │ rl ", theme.Dim), sg(modeOr(rl.mode()), modeColor(rl.mode())),
		sg(" │ dlp ", theme.Dim), sg(modeOr(dl.mode()), modeColor(dl.mode())),
		sg(" │ ghost ", theme.Dim), sg(modeOr(gh.mode()), modeColor(gh.mode())),
		sg(" │ sess ", theme.Dim),
		sg(strconv.Itoa(len(p.sessRows))+" ("+strconv.Itoa(p.sessCounts.active)+" live)", theme.Accent),
		sg(" │ hooks ", theme.Dim))
	if p.guard != nil {
		installed := "?"
		if p.guard.Installed != nil {
			installed = strconv.Itoa(*p.guard.Installed)
		}
		text := "v" + installed
		color := lipgloss.TerminalColor(theme.OK)
		if !p.guard.UpToDate {
			text += "→v" + strconv.Itoa(p.guard.Latest)
			color = theme.Warn
		}
		text += " " + strconv.Itoa(p.guard.DeviceCount) + "dev"
		counters = append(counters, seg{text: text, fg: color})
	} else {
		counters = append(counters, sg("·", theme.Warn))
	}
	counters = append(counters, sg(" │", theme.Dim))
	lines = append(lines, renderRow(width, counters...))

	if a := p.activeAlert(now); a != nil {
		label, fg, bg := "⏸ IDLE", hexWarnFG, hexWarnBG
		if a.level == "bad" {
			label, fg, bg = "⛔ ALERT", hexBadFG, hexBadBG
		}
		lines = append(lines, renderRow(width, seg{
			text: " " + label + " · " + truncate(a.msg, width-14) + " ",
			fg:   lipgloss.Color(fg), bg: lipgloss.Color(bg), bold: true}))
	}
	if act := p.activeAction(now); act != nil {
		fg, bg := hexOKFG, hexOKBG
		if act.level == "bad" {
			fg, bg = hexBadFG, hexBadBG
		}
		lines = append(lines, renderRow(width, seg{
			text: " " + truncate(act.text, width-4) + " ",
			fg:   lipgloss.Color(fg), bg: lipgloss.Color(bg), bold: true}))
	}

	// TRAFFIC is always the LIVE window: 10-second buckets over the last 10
	// minutes, anchored to wall-clock slots. Bars slide left as real time passes
	// and age out naturally, so an hours-old deny can never paint a giant red
	// column. There is no historical fallback — an idle window is an honest flat
	// floor, not a rescaled 24h chart.
	nowSlot := now / 10_000
	traffic := make([]int, 60)
	trafficHot := make([]bool, 60)
	peak := 0
	for _, e := range p.merged {
		idx := 59 - int(nowSlot-e.At/10_000)
		if idx >= 0 && idx < 60 {
			traffic[idx]++
			if traffic[idx] > peak {
				peak = traffic[idx]
			}
			if e.Decision != "ALLOW" {
				trafficHot[idx] = true
			}
		}
	}
	latHotAt := maxFloat(2000, float64(p.latMedian())*2.5)
	latHot := make([]bool, len(p.lat))
	for i, v := range p.lat {
		latHot[i] = float64(v) > latHotAt
	}
	left := append([]string{paneTitle("TRAFFIC",
		"calls/10s · last 10m · live · peak "+strconv.Itoa(peak)+" · red = denials", leftW)},
		columnChart(traffic, trafficHot, chartH, leftW, theme.Accent, theme.Bad)...)
	right := append([]string{paneTitle("API LATENCY",
		"now "+strconv.Itoa(p.latNow())+"ms · med "+strconv.Itoa(p.latMedian())+
			"ms · amber >"+strconv.Itoa(int(latHotAt+0.5))+"ms", rightW)},
		columnChart(p.lat, latHot, chartH, rightW, theme.White, lipgloss.Color(hexWarnFG))...)
	lines = append(lines, joinColumns([][]string{left, right}, []int{leftW, rightW}, 1+chartH)...)

	// LAYERS · SESSIONS · EVENT LOG
	layersCol := []string{paneTitle("LAYERS", "l = inspect", colW)}
	layersCol = append(layersCol, renderRow(colW,
		sg(padEnd("RATELIMIT ", 10), theme.Dim),
		sg(padEnd(modeOr(rl.mode()), 7), modeColor(rl.mode())),
		sg(rl.summary(minuteNow), theme.Dim)))
	if rl != nil && rl.PerMinute > 0 {
		color := lipgloss.TerminalColor(theme.Accent)
		if minuteNow > rl.PerMinute {
			color = theme.Bad
		}
		layersCol = append(layersCol, hbar("load/min", minuteNow, rl.PerMinute, maxInt(6, colW-16), color, colW))
	}
	builtinN, customN := 0, 0
	if dl != nil {
		builtinN, customN = len(dl.Patterns), len(dl.Custom)
	}
	layersCol = append(layersCol, renderRow(colW,
		sg(padEnd("DLP", 10), theme.Dim),
		sg(padEnd(modeOr(dl.mode()), 7), modeColor(dl.mode())),
		sg(strconv.Itoa(builtinN)+" builtin · "+strconv.Itoa(customN)+" custom", theme.Dim)))
	dlpBars := p.insights.DLPByPattern
	if len(dlpBars) > 2 {
		dlpBars = dlpBars[:2]
	}
	if len(dlpBars) > 0 {
		maxDlpBar := 1
		if dlpBars[0].Count > 0 {
			maxDlpBar = dlpBars[0].Count
		}
		for _, d2 := range dlpBars {
			layersCol = append(layersCol,
				hbar(truncate(d2.Pattern, 10), d2.Count, maxDlpBar, maxInt(6, colW-16), theme.Bad, colW))
		}
	} else {
		// 36 characters against a colW of about 31 at cols=100: without the
		// truncation this wrapped onto a second line and pushed the column past
		// its height.
		layersCol = append(layersCol, renderRow(colW, sg("          no dlp hits in last 7 days", theme.Dim)))
	}
	guardSegs := []seg{sg(padEnd("GUARD", 10), theme.Dim)}
	if p.ring != nil {
		guardSegs = append(guardSegs, sg("local ✓ ", theme.OK),
			sg("eval avg "+strconv.Itoa(p.ring.avgMs)+"ms", theme.Dim))
	} else {
		guardSegs = append(guardSegs, sg("no local ring in cwd", theme.Dim))
	}
	layersCol = append(layersCol, renderRow(colW, guardSegs...))

	pickable := p.pickable(colH)
	sessExtra := strconv.Itoa(len(p.sessRows)) + " · s = inspect"
	if p.mode == "pick" {
		sessExtra = "↑↓ pick · enter open"
	}
	sessCol := []string{paneTitle("SESSIONS", sessExtra, colW)}
	if len(pickable) == 0 {
		sessCol = append(sessCol, renderRow(colW, sg("scanning…", theme.Dim)))
	}
	for i, r := range pickable {
		selected := p.mode == "pick" && i == p.pickIdx
		st := statusStyleOf(r.status)
		cursor, cursorColor := st.dot, st.color
		if selected {
			cursor, cursorColor = "▸", theme.AccentBright
		}
		nameW, padW := 12, 13
		if r.isMe {
			nameW, padW = 9, 10
		}
		segs := []seg{
			sg(cursor+" ", cursorColor),
			sg(padEnd(st.label, 7), st.color),
			// ALWAYS the agent's real name: "this machine" hid it, so the local
			// session gets a dim `me` tag instead and stays bold.
			sg(padEnd(truncate(r.agent, nameW), padW), theme.AccentBright),
		}
		if r.isMe {
			segs = append(segs, sg("me ", theme.OK))
		}
		denyColor := lipgloss.TerminalColor(theme.Dim)
		if r.denies > 0 {
			denyColor = theme.Bad
		}
		trust := ""
		if r.trust != nil {
			trust = "t" + num(*r.trust) + " "
		}
		segs = append(segs,
			plain(padStart(strconv.Itoa(r.calls), 4)+"c "),
			seg{text: padStart(strconv.Itoa(r.denies), 3) + "d ", fg: denyColor},
			sg(trust+agoAt(r.lastAt, time.UnixMilli(now)), theme.Dim))
		bold := selected || r.isMe
		for i := range segs {
			segs[i].bold = segs[i].bold || bold
		}
		if selected {
			segs = onBG(lipgloss.Color(hexSelectBG), segs)
		}
		sessCol = append(sessCol, renderRow(colW, segs...))
	}

	eventCol := []string{paneTitle("EVENT LOG", "system heartbeat", colW)}
	tail := p.events
	if len(tail) > colH-1 {
		tail = tail[len(tail)-(colH-1):]
	}
	for _, l := range tail {
		tickColor := lipgloss.TerminalColor(lipgloss.Color(hexEventTick))
		msgColor := lipgloss.TerminalColor(theme.Dim)
		switch l.level {
		case "bad":
			tickColor, msgColor = theme.Bad, theme.Bad
		case "warn":
			tickColor = theme.Warn
		}
		eventCol = append(eventCol, renderRow(colW,
			sg(hhmmss(l.ts)+" ", theme.Dim),
			seg{text: "▸ ", fg: tickColor},
			seg{text: l.msg, fg: msgColor}))
	}
	lines = append(lines, joinColumns([][]string{layersCol, sessCol, eventCol},
		[]int{colW, colW, colW}, colH)...)

	// TOOL STREAM
	visible := p.visibleDesc()
	sel := minInt(maxInt(0, p.sel), maxInt(0, len(visible)-1))
	streamBody := maxInt(3, streamRows-1)
	maxScroll := maxInt(0, len(visible)-streamBody)
	scroll := minInt(maxInt(0, sel-(streamBody-1)/2), maxScroll)

	extra := strconv.Itoa(sel+1) + "/" + strconv.Itoa(len(visible))
	if p.signal != "none" {
		extra += " · " + p.signal
	}
	if strings.TrimSpace(p.search) != "" {
		extra += " · search"
	}
	if p.filter != "all" {
		extra += " · source:" + p.filter
	}
	extra += " · enter full entry · ? all keys"
	lines = append(lines, paneTitle("TOOL STREAM", extra, width))

	body := []string{p.searchRow(width, len(visible))}
	switch {
	case p.localOn != nil && !*p.localOn:
		body = append(body, renderRow(width,
			sg("local logs off", theme.Warn),
			sg(" — enable: dataroom → Settings (local logs) or dashboard → Settings", theme.Dim)))
	case p.localOn != nil && *p.localOn && !p.localSetting.UsableHere:
		// The folder is a PROJECT setting, so it can name a path that exists on
		// another machine. Saying so beats showing a path nothing writes to.
		body = append(body, renderRow(width,
			sg("local logs on", theme.Warn),
			sg(" — "+p.localSetting.ConfiguredPath+" is not a folder on this device · writing to "+
				p.localSetting.File, theme.Dim)))
	case p.localOn != nil && *p.localOn && len(p.local) == 0:
		body = append(body, renderRow(width,
			sg("local logs on", theme.OK),
			sg(" — no entries yet · hooks write "+p.localSetting.File, theme.Dim)))
	}
	if len(visible) == 0 {
		// With a source filter on, "awaiting traffic" reads as "nothing is
		// happening" when the stream is merely filtered — say which it is.
		if p.filter == "all" {
			body = append(body, renderRow(width, sg(spin+" awaiting traffic…", theme.Dim)))
		} else {
			which := "CLD (cloud)"
			if p.filter == "local" {
				which = "LOC (local log)"
			}
			body = append(body, renderRow(width,
				sg(spin+" no "+which+" calls in the buffer · f switches source", theme.Dim)))
		}
	}
	for i := 0; i < streamBody && scroll+i < len(visible); i++ {
		e := visible[scroll+i]
		body = append(body, streamLine(e.row(), e.isLoc(), scroll+i == sel, false, width))
	}
	for i := 0; i < streamRows; i++ {
		if i < len(body) {
			lines = append(lines, body[i])
		} else {
			lines = append(lines, "")
		}
	}

	// The source filter (f) was only discoverable through the ? overlay, so the
	// stream looked like it merged local and cloud with no way to separate them.
	// The current source is inline and the key is advertised.
	source := "all"
	switch p.filter {
	case "local":
		source = "LOC only"
	case "cloud":
		source = "CLD only"
	}
	localState := "off"
	if p.localOn != nil && *p.localOn {
		localState = "on"
	}
	toolCounts := newCounter()
	for _, e := range p.merged {
		toolCounts.add(e.Tool)
	}
	topTools := toolCounts.sorted()
	if len(topTools) > 3 {
		topTools = topTools[:3]
	}
	top := joinCounts(topTools, " ")
	if top == "" {
		top = "—"
	}
	return append(lines, renderRow(width,
		seg{text: " LIVE ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
		seg{text: " local-log " + localState + " · " + strconv.Itoa(len(p.local)) + " loc/" +
			strconv.Itoa(len(p.cloud)) + " cld · source " + source + " · top " + top + " ",
			fg: theme.White, bg: lipgloss.Color(hexFooterBG)},
		seg{text: " ↑↓ select · enter full entry · f source · / search · space copy · ? all keys · esc menu · q quit ",
			fg: theme.White, bg: lipgloss.Color(hexPanelBG)}))
}

// modeOr is the "?" a layer shows before its configuration has loaded.
func modeOr(m string) string {
	if m == "" {
		return "?"
	}
	return m
}

// ── small renderers ────────────────────────────────────────────────────────

// columnChart draws `height` rows of block columns, newest on the right.
func columnChart(series []int, hot []bool, height, width int, color, hotColor lipgloss.TerminalColor) []string {
	if width < 1 {
		width = 1
	}
	data := make([]int, width)
	hotData := make([]bool, width)
	pad := width - len(series)
	if pad < 0 {
		series = series[len(series)-width:]
		if len(hot) > width {
			hot = hot[len(hot)-width:]
		}
		pad = 0
	}
	for i := range series {
		data[pad+i] = series[i]
		if i < len(hot) {
			hotData[pad+i] = hot[i]
		}
	}
	max := 1
	for _, v := range data {
		if v > max {
			max = v
		}
	}
	lines := make([]string, 0, height)
	for r := height; r >= 1; r-- {
		segs := make([]seg, 0, 8)
		for i, v := range data {
			frac := float64(v) / float64(max)
			ch := " "
			switch {
			case frac >= float64(r)/float64(height):
				ch = "█"
			case frac >= (float64(r)-0.5)/float64(height):
				ch = "▄"
			case r == 1:
				ch = "▁"
			}
			c := color
			if r == 1 && v == 0 {
				c = lipgloss.Color(hexDimFloor)
			} else if hotData[i] {
				c = hotColor
			}
			if n := len(segs); n > 0 && segs[n-1].fg == c {
				segs[n-1].text += ch
			} else {
				segs = append(segs, seg{text: ch, fg: c})
			}
		}
		lines = append(lines, renderRow(width, segs...))
	}
	return lines
}

// hbar is the compact labelled bar used inside the Live columns.
func hbar(label string, value, max, width int, color lipgloss.TerminalColor, maxw int) string {
	filled := 0
	if max > 0 {
		filled = int(float64(value)/float64(max)*float64(width) + 0.5)
	}
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return renderRow(maxw,
		sg(padEnd(label, 10), theme.Dim),
		sg(strings.Repeat("█", filled), color),
		sg(strings.Repeat("░", width-filled), lipgloss.Color(hexDimFloor)),
		sg(" "+strconv.Itoa(value), theme.Dim))
}

// joinColumns lays blocks side by side with a two-column gutter, clipped to
// `height` lines.
//
// The height and the clipping have to happen HERE, on the row, not on the
// individual columns. They used to be split — a fixed height on the row and
// hidden overflow on the columns — which clips nothing: a column with no height
// of its own sizes to its content, so there was no boundary to clip against and
// a column taller than the budget simply grew the whole frame past its limit.
// That is the full repaint the budget exists to avoid, and it is why LAYERS
// made the lower half of the console flicker exactly when it had something to
// show.
func joinColumns(cols [][]string, widths []int, height int) []string {
	out := make([]string, 0, height)
	for r := 0; r < height; r++ {
		parts := make([]string, 0, len(cols))
		for c, block := range cols {
			line := ""
			if r < len(block) {
				line = block[r]
			}
			w := lipgloss.Width(line)
			if w < widths[c] {
				line += strings.Repeat(" ", widths[c]-w)
			}
			parts = append(parts, line)
		}
		out = append(out, strings.Join(parts, "  "))
	}
	return out
}

// ── counters ───────────────────────────────────────────────────────────────

// counter counts by key and remembers the order keys were first seen.
//
// Go map iteration is random where JavaScript's Map is insertion-ordered, so
// without the order slice two tools with the same count would swap places
// between renders and the column would flicker.
type counter struct {
	order []string
	n     map[string]int
}

func newCounter() *counter { return &counter{n: map[string]int{}} }

func (c *counter) add(k string) {
	if _, ok := c.n[k]; !ok {
		c.order = append(c.order, k)
	}
	c.n[k]++
}

type countEntry struct {
	key string
	n   int
}

func (c *counter) sorted() []countEntry {
	out := make([]countEntry, 0, len(c.order))
	for _, k := range c.order {
		out = append(out, countEntry{k, c.n[k]})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].n > out[j].n })
	return out
}

func joinCounts(entries []countEntry, sep string) string {
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		parts = append(parts, e.key+"×"+strconv.Itoa(e.n))
	}
	return strings.Join(parts, sep)
}

func firstN(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
