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
	ID         string `json:"id"`
	At         int64  `json:"at"`
	Tool       string `json:"tool"`
	Decision   string `json:"decision"`
	Permission string `json:"permission"`
	Detail     string `json:"detail"`
	// Args is what the guard RECORDED, verbatim, for the w/b keys to build a rule
	// from. Detail is the same JSON collapsed onto one line for display, and it was
	// what the action re-parsed — a display string standing in for data.
	Args json.RawMessage `json:"-"`
	// Reason is the guard's own sentence for the decision, kept SEPARATE from
	// Detail. Detail is the arguments or the reason, whichever exists, so on a
	// call with arguments — which is every real one — the reason was dropped and
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

	stats *api.Stats
	// eval is the guard's own decision time, in milliseconds, one sample per entry
	// read. It was `lat`: the round trip of the audit fetch, which read a file on this
	// machine — see evalNow.
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
	// it was a frozen picture under a live console — and a frozen picture is exactly what
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
		signal:     "none",
		mode:       "stream",
		input:      in,
		notified:   map[string]bool{},
		toastQueue: map[string]*toastItem{},
	}
}

// ── polling ────────────────────────────────────────────────────────────────

const (
	tickAnim = iota
	tickLocal
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

// liveFeedResult, pollFeed, onFeed and cloudItem lived here, and they were the SECOND
// read of the same audit file.
//
// The panel had two planes: `local`, tailed straight off the log, and `cloud`, fetched
// through the audit API — which on this build reads that same file. So every call was
// ingested twice, rebuildMerged deduped the copies on tool|decision|minute, and the
// survivors were tagged LOC or CLD. A person watching saw rows labelled "cloud" for
// work that had never left their machine, a source filter that filtered one file from
// itself, and a log line saying "cloud link up · api 3ms".
//
// One file, one plane.

type liveStatsResult struct {
	gen   int
	stats api.Stats
	err   error
}

func (m liveStatsResult) Generation() int { return m.gen }

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
		// THE FILE IS ALWAYS READ. This was `if setting.Enabled`, on the reasoning that
		// a project which had turned local storage off should not have old LOC rows
		// appear in its stream. Both writers record unconditionally now, and the
		// setting resolved nothing but "off" for a while — so this panel skipped the
		// one file the guard had been writing to all along.
		res.lines = parseLocalLines(tailLines(setting.File, defaultTailBytes))
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
func (p *Live) pollStats() tea.Cmd {
	gen, client := p.gen, p.deps.API
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		s, err := client.Stats.Get(ctx)
		return liveStatsResult{gen: gen, stats: s, err: err}
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
		// Every tenth tick. The spinner wants 500ms; a heartbeat wants long enough that
		// a line is worth reading when it appears, and short enough that a stalled
		// console is obvious. A beat a second filled the pane faster than anybody could
		// read it and pushed real events off the top in under a minute.
		if p.tick%10 == 0 {
			p.beat(ctx.Now.UnixMilli())
		}
		return p.tickCmd(tickAnim, 500*time.Millisecond)
	case tickLocal:
		return p.cadence(tickLocal, 2*time.Second, p.pollLocal)
	case tickStats:
		return p.cadence(tickStats, 8*time.Second, p.pollStats)
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
		// The structured dlp field is an array of pattern names when it is there
		// at all. When it is not, the reason carries the name — it is written at
		// block time and never redacted — which is what reasonSignals reads.
		var dlpNames []string
		if len(j.DLP) > 0 {
			_ = json.Unmarshal(j.DLP, &dlpNames)
		}
		fromReason, burstFromReason := reasonSignals(j.Reason)
		if len(dlpNames) == 0 {
			dlpNames = fromReason
		}
		fresh = append(fresh, streamItem{
			ID: id, At: j.At, Tool: tool, Decision: decision,
			Permission: truncate4(j.Permission), Detail: collapseSpace(detail),
			Args:     j.Arguments,
			Reason:   j.Reason,
			DLP:      len(j.DLP) > 0 && string(j.DLP) != "null" && string(j.DLP) != "false",
			DLPNames: dlpNames,
			Burst:    j.RateLimitBurst || burstFromReason,
			Source:   "local", Session: j.SessionID,
			Agent: j.AgentName, EvalMs: j.EvaluationTimeMs, Rule: j.MatchedRuleID,
		})
	}
	if len(fresh) == 0 {
		return
	}
	// THE FIRST POLL IS THE WHOLE LOG, not a second's traffic.
	//
	// lastLocalTS starts at zero, so everything on disk comes back as "fresh" the first
	// time. The heartbeat counted it, and every console opened with a line like
	//
	//	00:11:18 • 43ms · 111 calls
	//
	// — the machine's entire recorded history, attributed to the one second somebody
	// happened to start looking. It made the first beat meaningless and the chart open
	// with a spike that never happened.
	backfill := p.lastLocalTS == 0
	p.lastLocalTS = fresh[len(fresh)-1].At
	p.local = append(p.local, fresh...)
	if len(p.local) > 400 {
		p.local = p.local[len(p.local)-400:]
	}
	// WHAT EACH DECISION COST, for the GUARD COST chart. One sample per entry that
	// carries a measurement; an entry without one is skipped rather than counted as
	// zero, because a zero would drag the median toward a speed nothing achieved.
	for _, f := range fresh {
		if f.EvalMs != nil {
			ms := int(*f.EvalMs + 0.5)
			p.eval = append(p.eval, ms)
			// The heartbeat shows the WORST decision in each tick's window rather than
			// the last. A slow one between two fast ones is the sample worth seeing, and
			// at two ticks a second a busy machine puts several in every column.
			if !backfill {
				if ms > p.pulsePending {
					p.pulsePending = ms
				}
				p.pulseCalls++
			}
		}
	}
	if len(p.eval) > 240 {
		p.eval = p.eval[len(p.eval)-240:]
	}
	// A "local +N calls" line stood here, pushed on every poll that saw fewer than ten
	// new rows. The heartbeat now reports the same second with more in it — the cost as
	// well as the count — so this was the same event twice, one line apart:
	//
	//	00:26:15 ▸ local +1 calls
	//	00:26:15 • 30ms · 1 call
	//
	// Denials still raise their own alert, which is a different claim and still worth a
	// line of its own.
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

// beat appends one sample to the heartbeat trace and clears what it consumed.
//
// Called from the animation tick, so the trace keeps moving through a poll that fails or
// a cadence that has gone slow — which is precisely when somebody is looking at this pane
// to find out whether anything is still alive.
// ONE BEAT EVERY FIVE SECONDS. The animation tick runs at 500ms because a spinner needs
// to look like it is spinning; a heartbeat at that rate is a flicker, and it pushed real
// events off the top of the pane in under a minute.
//
// AND THE NUMBERS GO IN THE EVENT LOG, because the chart cannot carry them. A column of
// a certain height says "slower than the others" and nothing more: not how slow, and not
// whether the machine was busy or idle while it happened. Those are the two things worth
// knowing about a beat, so each one writes them down — the cost of the slowest decision
// in that second, and how many calls there were to decide.
func (p *Live) beat(now int64) {
	ms, calls := p.pulsePending, p.pulseCalls
	p.pulse = append(p.pulse, ms)
	p.pulsePending, p.pulseCalls = 0, 0
	if len(p.pulse) > 400 {
		p.pulse = p.pulse[len(p.pulse)-400:]
	}

	msg := "idle"
	if calls > 0 {
		msg = strconv.Itoa(ms) + "ms · " + strconv.Itoa(calls) + " call"
		if calls > 1 {
			msg += "s"
		}
	}
	p.pushLog(msg, "beat", now)
}

func (p *Live) pushLog(msg, level string, now int64) {
	p.events = append(p.events, logLine{ts: now, msg: msg, level: level})
	if len(p.events) > 60 {
		p.events = p.events[len(p.events)-60:]
	}
}

// rebuildMerged orders the stream.
//
// It used to MERGE, and the name is what is left of that: two planes, deduped against
// each other on tool|decision|minute because the same call arrived twice — once tailed
// off the log and once fetched through the audit API, which reads the same file. The
// heuristic was load-bearing and approximate, which is the kind of thing that quietly
// hides a real second call. There is one plane, so there is nothing to reconcile.
//
// The sort stays: entries are appended as they are read, and a file that was written by
// several processes is not strictly ordered by timestamp.
func (p *Live) rebuildMerged(now int64) {
	merged := append(make([]streamItem, 0, len(p.local)), p.local...)
	sort.SliceStable(merged, func(i, j int) bool { return merged[i].At < merged[j].At })
	p.merged = merged
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

// filtered is the stream after the signal and search filters, oldest first.
func (p *Live) filtered() []streamItem {
	out := make([]streamItem, 0, len(p.merged))
	for _, e := range p.merged {
		// A source filter stood here — all → local → cloud. Everything is from one
		// file, so it filtered that file from itself.
		if !p.matches(e) || !p.signalOK(e) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// visibleDesc is every buffered entry that passes the filters, newest first, so the
// row count matches the entry total in the status bar.
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
			p.mode = "stream"
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
	case k.Type == tea.KeyEnter:
		if e, ok := p.selected(visible); ok {
			p.inspect = &e
			p.inspectScroll = 0
			p.mode = "inspect"
		}
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
		// THE SAME RULE THE AUDIT BROWSER WOULD MAKE. This had two branches: an entry
		// from the store went through Audit.Whitelist/Block, which builds the rule from
		// the recorded arguments and REFUSES when there is nothing to narrow on; an
		// entry read off the log got a local extractor that looked for no url and took
		// only the BASENAME of a path — and, when it found nothing, left Kind "tool"
		// and silently allowed every call to that tool forever.
		//
		// The store branch went dead when the second read did, so every `w` was taking
		// the widening path. api.RuleSpecFor is now the one implementation of "what rule
		// would have stopped this call", and it refuses rather than widens.
		spec, specErr := api.RuleSpecFor(e.Tool, e.Args, "exact", verb)
		if specErr != nil {
			return liveActionResult{gen: gen, level: "bad", text: "✗ " + specErr.Error()}
		}
		res, err := client.Policies.AddRule(ctx, active.Policy.ID, spec)
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

// extractTarget lived here: a second reader of a call's target, over the DISPLAY string
// rather than the recorded arguments. It differed from the store's in two ways that
// decided how wide a policy got — no url, and the basename of a path instead of the path
// — so whitelisting one denial from the stream and from the audit browser produced two
// different rules. api.RuleSpecFor is the one answer now.

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
		// `· api <n>ms` stood here, the round trip of the audit fetch. What is worth a
		// place in the title is what ENFORCEMENT costs, which is measured per call and
		// recorded in every entry — see the GUARD COST pane.
		{text: " " + spin + " up " + fmtUp(now-p.start.UnixMilli()) + " · " + hhmmss(now) +
			" · guard " + strconv.Itoa(p.evalNow()) + "ms ", fg: theme.White, bg: lipgloss.Color(hexPanelBG)},
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

// WHAT ENFORCEMENT COSTS, in milliseconds per decision.
//
// These were latNow and latMedian over p.lat, which held the round-trip time of the
// audit fetch — a read of a file on this machine, so the number was a measure of the
// local disk and was labelled "API LATENCY". It charted nothing anybody could act on.
//
// The guard measures its own decision time and writes it into every entry, which is the
// number a person tuning a policy actually wants: a rule set that costs 40ms per tool
// call is a different thing to live with than one that costs 4ms. Same charts, same
// shape, a real subject.
func (p *Live) evalNow() int {
	if len(p.eval) == 0 {
		return 0
	}
	return p.eval[len(p.eval)-1]
}

func (p *Live) evalMedian() int {
	if len(p.eval) == 0 {
		return 0
	}
	s := append([]int(nil), p.eval...)
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
		{"/", "live search (tool, agent, command…) · enter done"},
		{"s", "session picker"},
		{"l", "layers detail (rate limit · dlp · guard)"},
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
	// WHY FIRST, arguments second. On a big call the arguments are a screen of
	// JSON, and the one thing somebody opened this view to find is the sentence
	// explaining why it was refused.
	why := whyBlock(e.Decision, e.Reason, e.Rule, e.DLPNames, e.Burst, bodyW)
	whyN, whyFG := len(why), whyColor(e.Decision, e.Burst, e.DLPNames)
	content := why
	argsText := "(no arguments recorded)"
	if len(e.Args) > 0 && string(e.Args) != "null" {
		argsText = prettyJson(string(e.Args))
	} else if len(content) == 0 && strings.TrimSpace(e.Detail) != "" {
		argsText = e.Detail
	}
	content = append(content, wrapLines(argsText, bodyW)...)
	bodyRows := maxInt(4, ctx.Rows-6) // title + 3 header rows + pane title + footer
	maxScroll := maxInt(0, len(content)-bodyRows)
	off := minInt(p.inspectScroll, maxScroll)

	// A LOC/CLD segment sat at the end of this header. Every entry is from this
	// machine's own log, so the label distinguished nothing.
	head := []seg{
		{text: " ENTRY ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
		sgb("  "+e.Decision, decisionColor(e.Decision)),
		sgb("  "+e.Tool, theme.Accent),
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
		idx := off + i
		if idx >= len(content) {
			lines = append(lines, "")
			continue
		}
		// The why block is coloured; the arguments under it are not. The first of
		// its lines names the layer, so it is the one that carries the weight.
		if idx < whyN {
			lines = append(lines, renderRow(width, seg{text: content[idx], fg: whyFG, bold: idx == 0}))
			continue
		}
		lines = append(lines, renderRow(width, plain(content[idx])))
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
		seg{text: " rate limit · dlp · guard ", fg: theme.White, bg: lipgloss.Color(hexFooterBG)},
		seg{text: " ↑↓ scroll · ? all keys · ← back · esc menu ", fg: theme.White, bg: lipgloss.Color(hexPanelBG)}))
}

func orDash(n int) string {
	if n == 0 {
		return "—"
	}
	return strconv.Itoa(n)
}

// viewDetail is one session, dashboard style: a summary and the full timeline.
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
	colW := maxInt(20, (width-3)/2)

	rl := p.insights.Layers.RateLimit
	dl := p.insights.Layers.DLP

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
		sg(" │ hooks ", theme.Dim))
	if p.guard != nil {
		installed := "?"
		if p.guard.Installed != nil {
			installed = strconv.Itoa(*p.guard.Installed)
		}
		text := "v" + installed
		color := lipgloss.TerminalColor(theme.OK)
		// Only when there is a real newer version to name. Latest is 0 when this build
		// cannot find its own packaged hook to compare against, and rendering that
		// turned "I cannot tell" into "yours is out of date, upgrade to v0".
		if !p.guard.UpToDate && p.guard.Latest > 0 && p.guard.Installed != nil {
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
	// Amber above 2.5x the median, with a floor so a quiet machine whose median is 2ms
	// does not paint every ordinary call hot. The floor was 2000ms for a network round
	// trip; for a local policy decision 50ms is already slow.
	evalHotAt := maxFloat(50, float64(p.evalMedian())*2.5)
	// A BASELINE UNDER THE IDLE SAMPLES. A zero column draws nothing, and a trace of
	// nothing is the frozen picture this pane was replaced for. One unit is below the
	// chart's floor of 50, so it moves the scale by nothing and reads as a flatline.
	trace := make([]int, len(p.pulse))
	evalHot := make([]bool, len(p.pulse))
	for i, v := range p.pulse {
		trace[i] = maxInt(1, v)
		evalHot[i] = float64(v) > evalHotAt
	}
	left := append([]string{paneTitle("TRAFFIC",
		"calls/10s · last 10m · live · peak "+strconv.Itoa(peak)+" · red = denials", leftW)},
		// Ten calls in ten seconds is a busy machine; below that the bars stay short.
		columnChart(traffic, trafficHot, chartH, leftW, 10, theme.Accent, theme.Bad)...)
	right := append([]string{paneTitle("HEARTBEAT",
		"live · ms per decision · now "+strconv.Itoa(p.evalNow())+" · med "+strconv.Itoa(p.evalMedian())+
			" · amber >"+strconv.Itoa(int(evalHotAt+0.5)), rightW)},
		// The amber threshold is the top of the scale: an ordinary decision sits well
		// under it, and a bar that reaches up there is one worth looking at.
		columnChart(trace, evalHot, chartH, rightW, int(evalHotAt+0.5), theme.White, lipgloss.Color(hexWarnFG))...)
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

	eventCol := []string{paneTitle("EVENT LOG", "system heartbeat", colW)}
	tail := p.events
	if len(tail) > colH-1 {
		tail = tail[len(tail)-(colH-1):]
	}
	for _, l := range tail {
		tickColor := lipgloss.TerminalColor(lipgloss.Color(hexEventTick))
		msgColor := lipgloss.TerminalColor(theme.Dim)
		mark := "▸ "
		switch l.level {
		case "bad":
			tickColor, msgColor = theme.Bad, theme.Bad
		case "warn":
			tickColor = theme.Warn
		case "beat":
			// A beat is a different KIND of line from an event: it says the console is
			// alive, not that something happened. Marked and dimmed so a denial still
			// stands out in a column that now has one of these every second.
			mark, tickColor = "• ", theme.OK
		}
		eventCol = append(eventCol, renderRow(colW,
			sg(hhmmss(l.ts)+" ", theme.Dim),
			seg{text: mark, fg: tickColor},
			seg{text: l.msg, fg: msgColor}))
	}
	lines = append(lines, joinColumns([][]string{layersCol, eventCol},
		[]int{colW, colW}, colH)...)

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
	extra += " · enter full entry · ? all keys"
	lines = append(lines, paneTitle("TOOL STREAM", extra, width))

	body := []string{p.searchRow(width, len(visible))}
	switch {
	// A "local logs off — enable: dataroom → Settings or dashboard → Settings" row stood
	// first here. Recording is unconditional: the setting chooses the folder and nothing
	// else, so `off` is a state the writers cannot be in and the row could not appear.
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
		// A source filter used to make this ambiguous — "awaiting traffic" reads as
		// "nothing is happening" when the stream is merely filtered — so it said which
		// source was selected. There is one source. The signal and search filters can
		// still empty the view, and they are visible in the status bar.
		body = append(body, renderRow(width, sg(spin+" awaiting traffic…", theme.Dim)))
	}
	for i := 0; i < streamBody && scroll+i < len(visible); i++ {
		e := visible[scroll+i]
		body = append(body, streamLine(e.row(), scroll+i == sel, false, width))
	}
	for i := 0; i < streamRows; i++ {
		if i < len(body) {
			lines = append(lines, body[i])
		} else {
			lines = append(lines, "")
		}
	}

	// A source indicator stood here, with the `f` key that cycled it, because the
	// filter was otherwise discoverable only through the ? overlay — the stream looked
	// like it merged local and cloud with no way to separate them. It merged one file
	// with itself.
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
		seg{text: " local-log " + localState + " · " + strconv.Itoa(len(p.local)) +
			" entries · top " + top + " ",
			fg: theme.White, bg: lipgloss.Color(hexFooterBG)},
		seg{text: " ↑↓ select · enter full entry · / search · space copy · ? all keys · esc menu · q quit ",
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
func columnChart(series []int, hot []bool, height, width, floor int, color, hotColor lipgloss.TerminalColor) []string {
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
	// A FLOOR UNDER THE SCALE, so a quiet machine looks quiet.
	//
	// The top of the chart was whatever the tallest sample happened to be, so on an idle
	// console ONE call drew a full-height bar. Technically a 100% increase over nothing,
	// and useless: every reading looked like a spike, and a real spike looked the same.
	//
	// The floor is what the caller considers a normal maximum — the amber threshold for
	// decision cost, a busy second's traffic for call counts — so a bar only approaches
	// the top when it is genuinely near that. Above the floor the scale still grows, so
	// nothing is ever clipped.
	max := floor
	if max < 1 {
		max = 1
	}
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
