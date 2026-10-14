// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
)

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
// through the audit API, which on this build reads that same file. So every call was
// ingested twice, rebuildMerged deduped the copies on tool|decision|minute, and the
// survivors were tagged LOC or CLD. A person watching saw rows labelled "cloud" for
// work that had never left their machine, a source filter that filtered one file from
// itself, and a log line saying "cloud link up · api 3ms".
//
// One file, one plane.

type liveStatsResult struct {
	gen   int
	stats client.Stats
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
	status client.GuardStatus
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

// The eval ring the guard writes per project. Same directory the hooks use, so
// the TUI reads what this machine actually produced.
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
		// setting resolved nothing but "off" for a while, so this panel skipped the
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
	gen, client := p.gen, p.deps.Client
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		s, err := client.Stats.Get(ctx)
		return liveStatsResult{gen: gen, stats: s, err: err}
	}
}

func (p *Live) pollInsights() tea.Cmd {
	gen, client := p.gen, p.deps.Client
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
	gen, client := p.gen, p.deps.Client
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
		// at all. When it is not, the reason carries the name, it is written at
		// block time and never redacted, which is what reasonSignals reads.
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
	//, the machine's entire recorded history, attributed to the one second somebody
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
	// new rows. The heartbeat now reports the same second with more in it, the cost as
	// well as the count, so this was the same event twice, one line apart:
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
	var ae *client.Error
	is429, isNet := false, false
	if e, ok := err.(*client.Error); ok {
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
		// self-heal on the next poll, stay quiet unless it persists.
		p.netFails++
		if p.netFails == 3 {
			p.pushLog("network unreachable · retrying…", "warn", now)
		}
	case !is429:
		p.pushLog("api error · "+truncate(err.Error(), 40), "bad", now)
	}
	return nil
}