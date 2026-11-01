// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package live

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/tui"
)

func init() { tui.Register(tui.SectionLive, func(d tui.Deps) tui.Panel { return newLive(d) }) }

var tokens int

func nextToken() int { tokens++; return tokens }

type streamItem struct {
	ID         string `json:"id"`
	At         int64  `json:"at"`
	Tool       string `json:"tool"`
	Decision   string `json:"decision"`
	Permission string `json:"permission"`
	Detail     string `json:"detail"`

	Args json.RawMessage `json:"-"`

	Reason string `json:"reason,omitempty"`
	DLP    bool   `json:"dlp"`

	DLPNames []string `json:"dlpNames,omitempty"`
	Burst    bool     `json:"burst"`
	Source   string   `json:"source"`
	Session  string   `json:"session,omitempty"`
	Agent    string   `json:"agent,omitempty"`
	EvalMs   *float64 `json:"evalMs,omitempty"`
	Rule     string   `json:"rule,omitempty"`
}

func (e streamItem) row() tui.StreamRow {
	return tui.StreamRow{
		At: e.At, Tool: e.Tool, Decision: e.Decision, Permission: e.Permission,
		Detail: e.Detail, DLP: e.DLP, Burst: e.Burst, Agent: e.Agent,
		EvalMs: e.EvalMs, Rule: e.Rule,
	}
}

type logLine struct {
	ts    int64
	msg   string
	level string
}

type ringStat struct {
	avgMs   int
	session string
	count   int
}

type Live struct {
	deps tui.Deps
	gen  int

	tok int

	stats *client.Stats

	eval   []int
	local  []streamItem
	merged []streamItem

	localOn      *bool
	localSetting config.LocalLogSetting
	ring         *ringStat

	events []logLine

	pulse        []int
	pulsePending int
	pulseCalls   int

	signal string

	search        string
	editingSearch bool
	input         textinput.Model

	sel    int
	action *flashMsg

	mode          string
	inspect       *streamItem
	inspectScroll int
	layersScroll  int

	notified    map[string]bool
	openedAt    int64
	lastLocalTS int64
	localSeq    int
	pausedUntil int64
	netFails    int

	insights       insightsBits
	insightsLoaded bool
	guard          *client.GuardStatus

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

func newLive(d tui.Deps) *Live {
	in := textinput.New()
	in.Prompt = ""
	in.CharLimit = 200
	return &Live{
		deps:       d,
		tok:        nextToken(),
		signal:     "none",
		mode:       "stream",
		input:      in,
		notified:   map[string]bool{},
		toastQueue: map[string]*toastItem{},
	}
}

func (p *Live) Init(ctx tui.PanelContext) tea.Cmd {
	p.gen = ctx.Gen
	p.openedAt = ctx.Now.UnixMilli()
	p.start = ctx.Now

	return tea.Batch(
		p.pollLocal(), p.pollStats(), p.pollInsights(), p.pollGuard(),
		p.tickCmd(tickAnim, 500*time.Millisecond),
		p.tickCmd(tickLocal, 2*time.Second),
		p.tickCmd(tickStats, 8*time.Second),
		p.tickCmd(tickInsights, 20*time.Second),
		p.tickCmd(tickGuard, 60*time.Second),
	)
}

func (p *Live) paused() bool { return p.frozen || time.Now().UnixMilli() < p.pausedUntil }

func (p *Live) shouldPoll(kind int) bool {
	if kind == tickLocal {
		return !p.frozen
	}
	return !p.paused()
}

func (p *Live) CapturingKeys() bool { return p.editingSearch }

func (p *Live) Update(msg tea.Msg, ctx tui.PanelContext) (tui.Panel, tea.Cmd) {
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

	case liveStatsResult:
		if m.err != nil {
			return p, p.apiError(m.err, now)
		}
		s := m.stats
		p.stats = &s
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

	case liveActionResult:
		p.action = &flashMsg{text: m.text, level: m.level, until: now + 7000}
		if m.logText != "" {
			p.pushLog(m.logText, m.logLevel, now)
		}
		return p, nil
	}
	return p, nil
}

func (p *Live) chartHeight(ctx tui.PanelContext) int {
	if ctx.Rows >= 35 {
		return 6
	}
	return 4
}

func (p *Live) colHeight(ctx tui.PanelContext) int {
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

func (p *Live) streamRows(ctx tui.PanelContext) int {
	return tui.MaxInt(4, ctx.Rows-5-(1+p.chartHeight(ctx))-p.colHeight(ctx)-p.bannerRows(ctx.Now.UnixMilli()))
}

func (p *Live) Hint(ctx tui.PanelContext) string {
	return strings.Join([]string{
		tui.RenderRow(ctx.Cols, tui.Sgb("▶ REALTIME CONSOLE: THIS MACHINE", tui.Theme.AccentBright)),
		tui.RenderRow(ctx.Cols, tui.Sg("Fullscreen live monitor, streaming tool calls, active charts,", tui.Theme.Dim)),
		tui.RenderRow(ctx.Cols, tui.Sg("counters, DLP hits and denial alerts. Updates every 2s.", tui.Theme.Dim)),
		"",
		tui.RenderRow(ctx.Cols, tui.Plain("press "), tui.Sg("enter", tui.Theme.Accent), tui.Plain(" to go live")),
	}, "\n")
}
