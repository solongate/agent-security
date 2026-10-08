// SPDX-License-Identifier: Apache-2.0

package panels

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/proxy-go/internal/api"
	"github.com/solongate/agent-security/packages/proxy-go/internal/tui"
)

// No init(): the rate limit is not a section any more.
//
// A policy carries its own, per variant, which is what the guard reads and what
// the dashboard edits. A section beside Policies described a layer that applied
// to a project rather than to a policy — enforcement that no longer exists.
// NewRateLimit stays because the Policies panel mounts it on a variant.

// The Rate Limit panel: the layer's own settings plus the dashboard's
// busiest-window and burst view, ported from tui/panels/RateLimit.tsx.
//
// Edits are draft-only: `s` writes and `x` throws the draft away. `x` is not a
// convenience. ←→ is how a number is changed here, so ← cannot also mean back
// while the cursor is on a field — and with no bursts recorded the cursor can
// only ever BE on a field, which left a dirty panel with no key that both
// stopped editing and did not write. `x` is that key; esc is the one that leaves.
//
// The ↑↓ cursor is UNIFIED — indexes 0-3 are the editable fields and everything
// after them is a burst row — so the list scrolls out of the fields rather than
// needing a second cursor.

var rlModes = []api.LayerMode{api.LayerOff, api.LayerDetect, api.LayerBlock}

// rlAnomaly is one burst over the per-minute limit.
type rlAnomaly struct {
	Agent   string `json:"agent"`
	Minute  string `json:"minute"`
	Count   int    `json:"count"`
	Limit   int    `json:"limit"`
	Blocked bool   `json:"blocked"`
}

// securityInsights is the slice of /stats/security-insights this panel reads.
// The endpoint's payload is still moving, so only these three keys are pinned
// and the rest is ignored rather than failing the decode.
type securityInsights struct {
	Peaks struct {
		Minute int `json:"minute"`
		Hour   int `json:"hour"`
		Day    int `json:"day"`
	} `json:"peaks"`
	Anomalies []rlAnomaly `json:"anomalies"`
	Activity  struct {
		Minute []struct {
			Count int `json:"count"`
		} `json:"minute"`
		Hour []struct {
			Count int `json:"count"`
		} `json:"hour"`
	} `json:"activity"`
}

type (
	rlLayersMsg struct {
		genTag
		data api.SecurityLayersResponse
		err  error
	}
	rlHistoryMsg struct {
		genTag
		data []api.RateLimitChange
		err  error
	}
	rlInsightsMsg struct {
		genTag
		data securityInsights
		err  error
	}
	rlSavedMsg struct {
		genTag
		layers api.SecurityLayers
		err    error
	}
	rlFastTickMsg struct{ genTag }
	rlSlowTickMsg struct{ genTag }
)

// RateLimit is the panel.
type RateLimit struct {
	deps tui.Deps

	cols, rows int
	focused    bool
	gen, tok   int

	server   api.SecurityLayersResponse
	haveSrv  bool
	loadErr  error
	loading  bool
	history  []api.RateLimitChange
	insights securityInsights
	insErr   error
	insLoad  bool

	// bound is set when the panel is not a section of its own but the rate-limit
	// fold of one policy VARIANT, which is where the limit actually lives. The
	// owner hands the draft in before every key and reads it back after, so
	// there is one copy of it and it is the policy's. The bursts and the
	// busiest-window figures still load: they are observations of this
	// project's traffic and are what the number being typed should be judged
	// against.
	bound bool

	draft    api.SecurityLayers
	hasDraft bool
	dirty    bool
	sel      int
	status   string
}

func NewRateLimit(d tui.Deps) *RateLimit {
	return &RateLimit{deps: d, cols: 60, rows: 12, loading: true, insLoad: true, tok: nextToken()}
}

var _ tui.Panel = (*RateLimit)(nil)

// SetBound points the panel at a limit somebody else owns. See the note on
// DLP.SetBound: it is called before every key and every render.
func (p *RateLimit) SetBound(sec api.SecurityLayers, dirty bool) {
	p.bound = true
	p.loading = false
	p.draft, p.hasDraft = sec, true
	p.dirty = dirty
}

func (p *RateLimit) Bound() api.SecurityLayers { return p.draft }

// WantsLeft is whether ← means something here right now.
//
// It does on the four editable fields, where ←→ is how a number is changed, and
// does not on a burst row. The owner asks before it treats ← as "back", so this
// panel keeps its editing keys and there is still one key that leaves it.
func (p *RateLimit) WantsLeft() bool { return p.fieldIndex() >= 0 }

// CapturingKeys is always false here: the panel has no text field. Every value
// it edits is a number or an enum, adjusted with ←→.
func (p *RateLimit) CapturingKeys() bool { return false }

func (p *RateLimit) apply(ctx tui.PanelContext) {
	p.cols, p.rows, p.focused, p.gen = ctx.Cols, ctx.Rows, ctx.Focused, ctx.Gen
}

func (p *RateLimit) tag() genTag { return genTag{gen: p.gen, tok: p.tok} }

func (p *RateLimit) Init(ctx tui.PanelContext) tea.Cmd {
	p.apply(ctx)
	t := p.tag()
	// Config is light, so it polls fast (3s) and a change made on the dashboard
	// shows up quickly. The heavier history and insights scan polls at 10s.
	if p.bound {
		// No layer poll and no fast tick: the owner reloads the policy, and a
		// second clock here would only fight it.
		return tea.Batch(
			p.loadHistory(), p.loadInsights(),
			tea.Tick(10*time.Second, func(time.Time) tea.Msg { return rlSlowTickMsg{t} }),
		)
	}
	return tea.Batch(
		p.loadLayers(), p.loadHistory(), p.loadInsights(),
		tea.Tick(3*time.Second, func(time.Time) tea.Msg { return rlFastTickMsg{t} }),
		tea.Tick(10*time.Second, func(time.Time) tea.Msg { return rlSlowTickMsg{t} }),
	)
}

func (p *RateLimit) loadLayers() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		r, err := p.deps.API.Settings.GetSecurityLayers(bg())
		return rlLayersMsg{genTag: t, data: r, err: err}
	}
}

func (p *RateLimit) loadHistory() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		h, err := p.deps.API.Settings.GetRateLimitHistory(bg())
		return rlHistoryMsg{genTag: t, data: h, err: err}
	}
}

func (p *RateLimit) loadInsights() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		raw, err := p.deps.API.Stats.SecurityInsights(bg(), 7)
		if err != nil {
			return rlInsightsMsg{genTag: t, err: err}
		}
		var out securityInsights
		if len(raw) > 0 {
			// A payload this version cannot read is not an error worth taking the
			// panel over: the fields it does understand still render.
			_ = json.Unmarshal(raw, &out)
		}
		return rlInsightsMsg{genTag: t, data: out}
	}
}

func (p *RateLimit) Update(msg tea.Msg, ctx tui.PanelContext) (tui.Panel, tea.Cmd) {
	p.apply(ctx)
	switch m := msg.(type) {
	case rlLayersMsg:
		p.loading = false
		p.loadErr = m.err
		if m.err == nil {
			p.server, p.haveSrv = m.data, true
			// Sync the draft from the server ONLY when there is nothing unsaved.
			// Re-syncing unconditionally is what made a save revert: the reply
			// landed, dirty cleared, and the next poll wrote the pre-save values
			// back over the ones that had just been saved.
			if !p.dirty {
				p.draft, p.hasDraft = m.data.Layers, true
			}
		}
		return p, nil

	case rlHistoryMsg:
		if m.err == nil {
			p.history = m.data
		}
		return p, nil

	case rlInsightsMsg:
		p.insLoad = false
		p.insErr = m.err
		if m.err == nil {
			p.insights = m.data
		}
		return p, nil

	case rlSavedMsg:
		if m.err != nil {
			p.status = "✗ " + errText(m.err)
			return p, nil
		}
		p.draft, p.hasDraft = m.layers, true
		p.dirty = false
		p.status = "✓ Saved"
		return p, tea.Batch(p.loadLayers(), p.loadHistory(), p.loadInsights())

	case rlFastTickMsg:
		if m.tok != p.tok {
			return p, nil // a previous mount's clock: let the chain end here
		}
		t := p.tag()
		cmd := tea.Tick(3*time.Second, func(time.Time) tea.Msg { return rlFastTickMsg{t} })
		// Paused mid-edit so a background refresh cannot overwrite the draft.
		if !p.dirty {
			return p, tea.Batch(cmd, p.loadLayers())
		}
		return p, cmd

	case rlSlowTickMsg:
		if m.tok != p.tok {
			return p, nil
		}
		t := p.tag()
		return p, tea.Batch(
			tea.Tick(10*time.Second, func(time.Time) tea.Msg { return rlSlowTickMsg{t} }),
			p.loadHistory(), p.loadInsights(),
		)

	case tea.KeyMsg:
		if !p.focused {
			return p, nil
		}
		return p, p.key(m)
	}
	return p, nil
}

func (p *RateLimit) key(k tea.KeyMsg) tea.Cmd {
	total, burstBudget := p.cursorTotal(), p.burstBudget()
	switch k.String() {
	case "ctrl+r":
		p.status = "⟳ refreshed " + time.Now().Format("15:04:05")
		if p.bound {
			return tea.Batch(p.loadHistory(), p.loadInsights())
		}
		return tea.Batch(p.loadLayers(), p.loadHistory(), p.loadInsights())
	case "up":
		p.sel = max(0, p.selClamped()-1)
	case "down":
		p.sel = min(total-1, p.selClamped()+1)
	case "pgdown":
		p.sel = min(total-1, p.selClamped()+burstBudget)
	case "pgup":
		p.sel = max(0, p.selClamped()-burstBudget)
	case "left":
		p.adjust(-1, 1)
	case "right":
		p.adjust(1, 1)
	case "shift+left":
		p.adjust(-1, 10)
	case "shift+right":
		p.adjust(1, 10)
	case "s":
		if p.bound {
			// The owner saves. See DLP.
			return nil
		}
		return p.save()
	case "x":
		if p.bound {
			// The owner discards, for the same reason it saves: the draft is the
			// policy's, and throwing away only this half would leave the two
			// disagreeing about what is unsaved.
			return nil
		}
		p.discard()
	}
	return nil
}

// discard drops the draft and takes the server's answer back.
func (p *RateLimit) discard() {
	if !p.haveSrv {
		return
	}
	p.draft, p.hasDraft = p.server.Layers, true
	p.dirty = false
	p.status = "discarded"
}

// adjust moves the field under the cursor. A cursor sitting on a burst row is
// not a field and must not silently edit the one above it.
func (p *RateLimit) adjust(dir, step int) {
	if !p.hasDraft {
		return
	}
	fi := p.fieldIndex()
	if fi < 0 {
		return
	}
	rl := &p.draft.RateLimit
	switch fi {
	case 0:
		i := 0
		for j, m := range rlModes {
			if m == rl.Mode {
				i = j
			}
		}
		rl.Mode = rlModes[(i+dir+len(rlModes))%len(rlModes)]
	case 1:
		rl.PerMinute = max(0, rl.PerMinute+dir*step)
	case 2:
		rl.PerHour = max(0, rl.PerHour+dir*step)
	case 3:
		rl.PerDay = max(0, rl.PerDay+dir*step)
	}
	p.dirty = true
	p.status = ""
}

func (p *RateLimit) save() tea.Cmd {
	if !p.hasDraft || !p.haveSrv {
		return nil
	}
	p.status = "Saving…"
	next := p.server.Layers
	next.RateLimit = p.draft.RateLimit
	t := p.tag()
	return func() tea.Msg {
		got, err := p.deps.API.Settings.SetSecurityLayers(bg(), next)
		return rlSavedMsg{genTag: t, layers: got, err: err}
	}
}

// ── layout arithmetic, shared by the key handler and the render ────────────

func (p *RateLimit) sortedAnomalies() []rlAnomaly {
	out := append(p.insights.Anomalies[:0:0], p.insights.Anomalies...)
	// Biggest bursts first, then newest, matching the dashboard's ordering.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return parseWhen(out[i].Minute).After(parseWhen(out[j].Minute))
	})
	return out
}

func (p *RateLimit) showExtras() bool { return p.rows >= 20 }

func (p *RateLimit) burstBudget() int {
	hasLoad := p.hasDraft && p.draft.RateLimit.PerMinute > 0
	spacer := 0
	if p.showExtras() {
		spacer = 1
	}
	extras := 0
	if p.showExtras() {
		extras = 5
		if hasLoad {
			extras++
		}
	}
	// hint + fields + extras + bursts header + column header + spacer + the
	// "limit now" footer + one line kept back. Budgeting a list to fill the
	// panel EXACTLY is what broke scrolling in the Ink version: the footer had
	// nowhere to go, so it pushed rows past the clip and the selection moved
	// into space that is never drawn.
	fixed := 1 + 4 + extras + 1 + 1 + spacer + 1 + 1
	return max(1, p.rows-fixed)
}

func (p *RateLimit) cursorTotal() int { return 4 + len(p.insights.Anomalies) }

func (p *RateLimit) selClamped() int { return min(p.sel, max(0, p.cursorTotal()-1)) }

func (p *RateLimit) fieldIndex() int {
	if p.selClamped() < 4 {
		return p.selClamped()
	}
	return -1
}

func (p *RateLimit) burstCursor() int {
	if p.fieldIndex() >= 0 {
		return -1
	}
	return p.selClamped() - 4
}

// ── render ─────────────────────────────────────────────────────────────────

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
		case api.LayerOff:
			modeDesc = "  no limit"
		case api.LayerDetect:
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
// renders as "—" instead of as 1970.
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
		return "—"
	}
	return t.Local().Format("Jan 2 15:04")
}
