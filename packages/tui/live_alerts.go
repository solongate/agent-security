// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

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

// beat appends one sample to the heartbeat trace and clears what it consumed.
//
// Called from the animation tick, so the trace keeps moving through a poll that fails or
// a cadence that has gone slow, which is precisely when somebody is looking at this pane
// to find out whether anything is still alive.
// ONE BEAT EVERY FIVE SECONDS. The animation tick runs at 500ms because a spinner needs
// to look like it is spinning; a heartbeat at that rate is a flicker, and it pushed real
// events off the top of the pane in under a minute.
//
// AND THE NUMBERS GO IN THE EVENT LOG, because the chart cannot carry them. A column of
// a certain height says "slower than the others" and nothing more: not how slow, and not
// whether the machine was busy or idle while it happened. Those are the two things worth
// knowing about a beat, so each one writes them down, the cost of the slowest decision
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
// each other on tool|decision|minute because the same call arrived twice, once tailed
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
// tick, before any data had loaded, so the whole historical backlog, arriving
// a tick later, counted as new and dumped a wall of toasts on every open.
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