// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
)

// Live, the fullscreen realtime ops console.
//
// Copying: SPACE toggles COPY MODE, the screen freezes completely (polls skip,
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
// wall-clock slots, fast flow with activity, zero movement without.

func init() { Register(SectionLive, func(d Deps) Panel { return newLive(d) }) }

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// streamItem is one row of the merged live buffer. The json tags are the export
// format (`e`), so they are the TypeScript field names rather than Go ones.
type streamItem struct {
	ID         string `json:"id"`
	At         int64  `json:"at"`
	Tool       string `json:"tool"`
	Decision   string `json:"decision"`
	Permission string `json:"permission"`
	Detail     string `json:"detail"`
	// Args is what the guard RECORDED, verbatim, for the w/b keys to build a rule
	// from. Detail is the same JSON collapsed onto one line for display, and it was
	// what the action re-parsed, a display string standing in for data.
	Args json.RawMessage `json:"-"`
	// Reason is the guard's own sentence for the decision, kept SEPARATE from
	// Detail. Detail is the arguments or the reason, whichever exists, so on a
	// call with arguments, which is every real one, the reason was dropped and
	// the inspector had nothing to explain the refusal with.
	Reason string `json:"reason,omitempty"`
	DLP    bool   `json:"dlp"`
	// DLPNames is which patterns fired. The bool above drives the chip and the
	// filter; the names are what tell somebody WHICH secret was found.
	DLPNames []string `json:"dlpNames,omitempty"`
	Burst    bool     `json:"burst"`
	Source   string   `json:"source"` // "local" | "cloud"
	Session  string   `json:"session,omitempty"`
	Agent    string   `json:"agent,omitempty"`
	EvalMs   *float64 `json:"evalMs,omitempty"`
	Rule     string   `json:"rule,omitempty"`
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
// isLoc() lived here: `e.Source == "local"`, which decided whether a row was labelled
// LOC or CLD. There is one source.

type logLine struct {
	ts    int64
	msg   string
	level string // ok | warn | bad
}

type ringStat struct {
	avgMs   int
	session string
	count   int
}

// Live is the panel.
type Live struct {
	deps Deps
	gen  int
	// tok identifies THIS mount of the panel; see nextPanelToken.
	tok int

	stats *client.Stats
	// eval is the guard's own decision time, in milliseconds, one sample per entry
	// read. It was `lat`: the round trip of the audit fetch, which read a file on this
	// machine, see evalNow.
	eval   []int
	local  []streamItem
	merged []streamItem

	localOn      *bool
	localSetting config.LocalLogSetting
	ring         *ringStat

	events []logLine

	// THE HEARTBEAT TRACE, one sample per animation tick.
	//
	// `eval` above holds what each decision COST, one entry per decision, and the chart
	// drawn from it only moved when a decision arrived. On a machine nobody was driving
	// it was a frozen picture under a live console, and a frozen picture is exactly what
	// a hung program looks like, so the pane could not answer the question it existed to
	// answer: is this still running?
	//
	// This advances with the CLOCK. Every tick appends the cost of whatever the guard
	// decided since the last one, or nothing at all, so the trace marches left the way a
	// cardiograph does: flat while idle, a spike per decision. Idle is drawn as a
	// baseline rather than as blank, because an ECG flatline reads as "alive, nothing
	// happening" and an empty column reads as broken.
	//
	// `eval` is still what the numbers in the title are computed from. Padding a median
	// with the zeros between decisions would report a speed nothing ever achieved.
	pulse        []int
	pulsePending int
	pulseCalls   int
	// `filter` (all | local | cloud) stood here, cycled by `f`. Everything is read from
	// one file, so it filtered that file from itself.
	signal string // none | deny | dlp | ratelimit

	search        string
	editingSearch bool
	input         textinput.Model

	sel    int
	action *flashMsg

	mode          string // stream | inspect | layers
	inspect       *streamItem
	inspectScroll int
	layersScroll  int

	// `seen` (audit-entry ids already ingested) stood here, for the second read of the
	// audit file. Fresh local lines are tracked by lastLocalTS instead.
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

func newLive(d Deps) *Live {
	in := textinput.New()
	in.Prompt = ""
	in.CharLimit = 200
	return &Live{
		deps:       d,
		tok:        nextPanelToken(),
		signal:     "none",
		mode:       "stream",
		input:      in,
		notified:   map[string]bool{},
		toastQueue: map[string]*toastItem{},
	}
}

func (p *Live) Init(ctx PanelContext) tea.Cmd {
	p.gen = ctx.Gen
	p.openedAt = ctx.Now.UnixMilli()
	p.start = ctx.Now
	// Poll budget, about 40 requests a minute: feed 3s, stats 8s, sessions 8s,
	// insights 20s, guard 60s. The 24h timeseries poll was dropped entirely,
	// TRAFFIC is derived from the buffer, which is what pays for this cadence
	// without risking the API's own rate limit.
	return tea.Batch(
		p.pollLocal(), p.pollStats(), p.pollInsights(), p.pollGuard(),
		p.tickCmd(tickAnim, 500*time.Millisecond),
		p.tickCmd(tickLocal, 2*time.Second),
		p.tickCmd(tickStats, 8*time.Second),
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
// The local plane is disk, not network, so only copy mode stops it, a
// rate-limit back-off is the API asking for room and has nothing to do with
// reading a file this machine wrote.
func (p *Live) shouldPoll(kind int) bool {
	if kind == tickLocal {
		return !p.frozen
	}
	return !p.paused()
}

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

// ── layout budget ──────────────────────────────────────────────────────────

// The WHOLE frame must fit in ctx.Rows, which the shell already set to one less
// than the terminal's height. At the terminal's full height Ink abandoned
// in-place diffing and did clearTerminal plus a full rewrite on every render,
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

// Hint is what the boxed layout shows while Live is selected but not opened.
func (p *Live) Hint(ctx PanelContext) string {
	return strings.Join([]string{
		renderRow(ctx.Cols, sgb("▶ REALTIME CONSOLE: THIS MACHINE", theme.AccentBright)),
		renderRow(ctx.Cols, sg("Fullscreen live monitor, streaming tool calls, active charts,", theme.Dim)),
		renderRow(ctx.Cols, sg("counters, DLP hits and denial alerts. Updates every 2s.", theme.Dim)),
		"",
		renderRow(ctx.Cols, plain("press "), sg("enter", theme.Accent), plain(" to go live")),
	}, "\n")
}