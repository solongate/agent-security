// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package live

import (
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/tui"
)

type alertBanner struct {
	id    string
	msg   string
	level string
	until int64
}

type flashMsg struct {
	text  string
	level string
	until int64
}

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

func (r *insightsRateLimit) summary(minuteNow int) string {
	if r == nil || r.PerMinute == 0 {
		return "no limits set"
	}
	return strconv.Itoa(minuteNow) + "/" + strconv.Itoa(r.PerMinute) + "m " +
		orDash(r.PerHour) + "h " + orDash(r.PerDay) + "d"
}

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

func (p *Live) rebuildMerged(now int64) {
	merged := append(make([]streamItem, 0, len(p.local)), p.local...)
	sort.SliceStable(merged, func(i, j int) bool { return merged[i].At < merged[j].At })
	p.merged = merged

	// p.notified is a dedup set, but nothing evicted from it: on a long-lived
	// Live panel it grew one entry per event ID forever. Events arrive sorted
	// oldest-first here, so drop the oldest keys past a generous bound — an ID
	// older than that can never merge again (merged only holds the newest
	// window).
	for id := range p.notified {
		seen := false
		for _, e := range merged {
			if e.ID == id {
				seen = true
				break
			}
		}
		if !seen {
			delete(p.notified, id)
		}
	}
	// Defensive cap: the eviction above already keeps p.notified within the
	// merged window, so this is normally a no-op. If it ever does trip, trim
	// to the newest 400 IDs like every other bound in this file, rather than
	// wiping the set and re-toasting everything still in that window.
	if len(p.notified) > 400 {
		start := 0
		if len(merged) > 400 {
			start = len(merged) - 400
		}
		kept := make(map[string]bool, 400)
		for _, e := range merged[start:] {
			if p.notified[e.ID] {
				kept[e.ID] = true
			}
		}
		p.notified = kept
	}
}

var toastRank = map[string]int{"DLP hit": 0, "Call denied": 1, "Rate-limit burst": 2}

func (p *Live) fireAlert(id, title, msg, level string, desktop bool, ctx tui.PanelContext) tea.Cmd {
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

func (p *Live) notifySecurityEvents(ctx tui.PanelContext) []tea.Cmd {
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
			continue
		}
		who := ""
		if e.Agent != "" {
			who = " · " + tui.Truncate(e.Agent, 20)
		}
		switch {
		case e.DLP:
			cmds = append(cmds, p.fireAlert("sec:"+e.ID, "DLP hit",
				"SECRET in "+e.Tool+who+": "+tui.Truncate(e.Detail, 60), "bad", true, ctx))
		case e.Decision != "ALLOW":
			what := e.Rule
			if what == "" {
				what = e.Detail
			}
			cmds = append(cmds, p.fireAlert("sec:"+e.ID, "Call denied",
				"DENY "+e.Tool+who+": "+tui.Truncate(what, 60), "bad", true, ctx))
		case e.Burst:
			cmds = append(cmds, p.fireAlert("sec:"+e.ID, "Rate-limit burst",
				"BURST "+e.Tool+who, "warn", true, ctx))
		}
	}
	return cmds
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