// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package live

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strconv"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/tui"
)

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
	lines   []tui.LocalLogLine
	ring    *ringStat
}

func (m liveLocalResult) Generation() int { return m.gen }

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

func ringPath() string { return filepath.Join(config.ProjectFlagDir(), ".eval-ring.jsonl") }

func (p *Live) pollLocal() tea.Cmd {
	gen := p.gen
	return func() tea.Msg {

		setting := config.LocalLogsSetting()
		res := liveLocalResult{gen: gen, setting: setting}

		res.lines = tui.ParseLocalLines(tui.TailLines(setting.File, tui.DefaultTailBytes))
		lines := tui.TailLines(ringPath(), 8192)
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

func (p *Live) onTick(m liveTick, ctx tui.PanelContext) tea.Cmd {

	if m.tok != p.tok {
		return nil
	}
	switch m.kind {
	case tickAnim:
		if p.frozen {

			return p.tickCmd(tickAnim, 500*time.Millisecond)
		}
		p.tick++

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

func (p *Live) cadence(kind int, every time.Duration, poll func() tea.Cmd) tea.Cmd {
	next := p.tickCmd(kind, every)
	if !p.shouldPoll(kind) {
		return next
	}
	return tea.Batch(next, poll())
}

func (p *Live) ingestLocal(lines []tui.LocalLogLine) {
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

		id := "l:" + strconv.FormatInt(j.At, 10) + ":" + j.Tool + ":" + strconv.Itoa(p.localSeq)
		p.localSeq++

		var dlpNames []string
		if len(j.DLP) > 0 {
			_ = json.Unmarshal(j.DLP, &dlpNames)
		}
		fromReason, burstFromReason := tui.ReasonSignals(j.Reason)
		if len(dlpNames) == 0 {
			dlpNames = fromReason
		}
		fresh = append(fresh, streamItem{
			ID: id, At: j.At, Tool: tool, Decision: decision,
			Permission: tui.Truncate4(j.Permission), Detail: tui.CollapseSpace(detail),
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

	backfill := p.lastLocalTS == 0
	p.lastLocalTS = fresh[len(fresh)-1].At
	p.local = append(p.local, fresh...)
	if len(p.local) > 400 {
		p.local = p.local[len(p.local)-400:]
	}

	for _, f := range fresh {
		if f.EvalMs != nil {
			ms := int(*f.EvalMs + 0.5)
			p.eval = append(p.eval, ms)

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

}

func (p *Live) afterBuffers(ctx tui.PanelContext) tea.Cmd {
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

		p.netFails++
		if p.netFails == 3 {
			p.pushLog("network unreachable · retrying…", "warn", now)
		}
	case !is429:
		p.pushLog("api error · "+tui.Truncate(err.Error(), 40), "bad", now)
	}
	return nil
}