// SPDX-License-Identifier: Apache-2.0

package panels

import (
	"strconv"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

// Split from ratelimit.go: the panel's render and its small format helpers.

func (p *RateLimit) View(ctx tui.PanelContext) string {
	p.apply(ctx)
	body := func() string {
		if !p.hasDraft {
			return ""
		}
		rl := p.draft.RateLimit
		anomalies := p.sortedAnomalies()
		budget := p.burstBudget()
		maxOff := max(0, len(anomalies)-budget)
		bcur := p.burstCursor()
		off := 0
		if bcur >= 0 {
			off = min(max(0, bcur-budget/2), maxOff)
		}

		var out []string
		hint := "press → to edit"
		if p.focused {
			tail := "s save · ^R refresh"
			if p.bound {
				tail = "s save · ← back"
			}
			hint = "↑↓ move (fields + bursts) · ←→ ±1 · shift+←→ ±10 · " + tail
		}
		out = append(out, stDim.Render(hint))

		fi := p.fieldIndex()
		modeDesc := "  DENY calls over the limit"
		switch rl.Mode {
		case client.LayerOff:
			modeDesc = "  no limit"
		case client.LayerDetect:
			modeDesc = "  flag bursts, never block"
		}
		out = append(out, p.fieldRow(0, fi, "Mode",
			modeStyle(string(rl.Mode)).Bold(true).Render(string(rl.Mode))+stDim.Render(modeDesc)))
		out = append(out, p.fieldRow(1, fi, "Per minute", stBold.Render(offOr(rl.PerMinute))))
		out = append(out, p.fieldRow(2, fi, "Per hour", stBold.Render(offOr(rl.PerHour))))
		out = append(out, p.fieldRow(3, fi, "Per day", stBold.Render(offOr(rl.PerDay))))

		lim := rl.PerMinute
		now := 0
		if n := len(p.insights.Activity.Minute); n > 0 {
			now = p.insights.Activity.Minute[n-1].Count
		}
		last24h := 0
		for _, b := range p.insights.Activity.Hour {
			last24h += b.Count
		}

		if p.showExtras() {
			// Bursts are the point of this panel, so this secondary block only
			// renders when the panel is tall: on a short terminal it ate the
			// height and left room for a single burst.
			if lim > 0 {
				filled := min(18, int(float64(now)/float64(lim)*18+0.5))
				pctv := min(100, int(float64(now)/float64(lim)*100+0.5))
				barStyle := stOK
				if pctv >= 100 {
					barStyle = stBad
				} else if pctv >= 80 {
					barStyle = stWarn
				}
				l := newLine(false)
				l.put(pad("load now", 13), stDim)
				l.put(strings.Repeat("█", max(0, filled)), barStyle)
				l.put(strings.Repeat("░", max(0, 18-filled)), stDim)
				l.put("  "+itoa(now)+"/"+itoa(lim)+" this minute ("+itoa(pctv)+"%)", stDim)
				out = append(out, l.String())
			}
			out = append(out, stAccentB.Render("Busiest 7d")+stDim.Render("   most calls in one window vs your limit"))
			out = append(out, busiestRow("minute", p.insights.Peaks.Minute, rl.PerMinute))
			out = append(out, busiestRow("hour", p.insights.Peaks.Hour, rl.PerHour))
			out = append(out, busiestRow("day", p.insights.Peaks.Day, rl.PerDay))
			out = append(out, stDim.Render(pad("activity", 11)+
				"   last 24h · "+itoa(last24h)+" calls · busiest hour "+itoa(p.insights.Peaks.Hour)+"/hr"))
		}

		head := "Recent bursts 7d"
		if len(anomalies) > 0 {
			head += " (" + itoa(len(anomalies)) + ")"
		}
		hl := newLine(false)
		hl.put(head, stAccentB)
		if maxOff > 0 {
			hl.put("  "+itoa(off+1)+"-"+itoa(min(off+budget, len(anomalies)))+"/"+itoa(len(anomalies)), stWarn)
		}
		hl.put("   over the per-minute limit · Bypassed = detect (not blocked)", stDim)
		out = append(out, hl.String())

		bw := max(10, p.cols-30)
		agentW := max(8, bw-31)
		if len(anomalies) == 0 {
			switch {
			case p.insLoad:
				out = append(out, stDim.Render("  loading…"))
			case p.insErr != nil:
				out = append(out, stDim.Render("  couldn't load bursts: "+truncate(errText(p.insErr), 60)))
			default:
				out = append(out, stDim.Render("  no bursts in the last 7 days"))
			}
		} else {
			out = append(out, stDim.Render(fit("WHEN", 15)+"  "+fit("RESULT", 9)+"  "+fit("CALLS", 7)+"  "+fit("AGENT", agentW)+"  "))
			end := min(len(anomalies), off+budget)
			for i := off; i < end; i++ {
				a := anomalies[i]
				isSel := i == bcur
				cursor := "  "
				whenStyle := stDim
				agentStyle := stDim
				if isSel {
					cursor = "▸ "
					whenStyle = stAccent
					agentStyle = stPlain
				}
				resStyle, res := stWarn, "Bypassed"
				if a.Blocked {
					resStyle, res = stBad, "Blocked"
				}
				l := newLine(false)
				l.put(fit(cursor+whenLabel(a.Minute), 15)+"  ", whenStyle)
				l.put(fit(res, 9)+"  ", resStyle)
				l.put(fit(itoa(a.Count)+"/"+itoa(a.Limit), 7)+"  ", stWarn)
				l.put(fit(truncate(a.Agent, agentW), agentW)+"  ", agentStyle)
				out = append(out, l.String())
			}
		}

		if p.showExtras() {
			out = append(out, "")
		}

		f := newLine(false)
		f.put("limit now  ", stDim)
		if lim > 0 {
			f.put(itoa(lim)+"/min", stPlain)
		} else {
			f.put("no per-minute limit", stPlain)
		}
		if len(p.history) > 0 {
			last := p.history[0]
			for _, h := range p.history {
				if h.TS > last.TS {
					last = h
				}
			}
			f.put("  · changed "+time.UnixMilli(last.TS).Format("Jan 2 15:04"), stDim)
		}
		if p.dirty {
			f.put("   ● unsaved (s save · x discard)", stWarn)
		}
		if p.status != "" {
			st := stOK
			if strings.HasPrefix(p.status, "✗") {
				st = stBad
			}
			f.put("   "+p.status, st)
		}
		out = append(out, f.String())
		return joinLines(out)
	}()

	return clip(dataView(p.loading && !p.hasDraft, p.loadErr, false, "", body), p.cols, p.rows)
}

func (p *RateLimit) fieldRow(idx, cursor int, label, value string) string {
	active := p.focused && idx == cursor
	prefix, st := "  ", stPlain
	if active {
		prefix, st = "▸ ", stAccent
	}
	return st.Render(prefix+pad(label, 11)) + value
}

// busiestRow is the dashboard's "busiest window" card, TUI edition: the peak in
// one window over 7 days, red when it went OVER the configured limit.
func busiestRow(label string, peak, limit int) string {
	ctx := "no limit set"
	if limit > 0 {
		switch {
		case peak > limit:
			ctx = "over " + itoa(limit)
		case peak == limit:
			ctx = "at limit " + itoa(limit)
		default:
			ctx = "limit " + itoa(limit)
		}
	}
	hot := limit > 0 && peak > limit
	l := newLine(false)
	l.put(pad("  "+label, 11), stDim)
	peakStyle := stPlain
	ctxStyle := stDim
	if hot {
		peakStyle = stBadB
		ctxStyle = stBad
	}
	l.put(padLeft(itoa(peak), 4)+" calls", peakStyle)
	l.put("  · "+ctx, ctxStyle)
	return l.String()
}

func offOr(n int) string {
	if n == 0 {
		return "off"
	}
	return itoa(n)
}

// parseWhen reads the timestamps the insights endpoint sends. It accepts the
// three shapes seen in the wild rather than one: a bucket that will not parse
// renders as ", " instead of as 1970.
func parseWhen(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02T15:04"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil && ms > 0 {
		return time.UnixMilli(ms)
	}
	return time.Time{}
}

func whenLabel(s string) string {
	t := parseWhen(s)
	if t.IsZero() {
		return ", "
	}
	return t.Local().Format("Jan 2 15:04")
}