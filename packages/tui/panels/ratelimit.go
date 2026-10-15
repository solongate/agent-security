// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"encoding/json"
	"sort"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

// No init(): the rate limit is not a section any more.
//
// A policy carries its own, per variant, which is what the guard reads and what
// the dashboard edits. A section beside Policies described a layer that applied
// to a project rather than to a policy, enforcement that no longer exists.
// NewRateLimit stays because the Policies panel mounts it on a variant.

// The Rate Limit panel: the layer's own settings plus the dashboard's
// busiest-window and burst view, ported from tui/panels/RateLimit.tsx.
//
// Edits are draft-only: `s` writes and `x` throws the draft away. `x` is not a
// convenience. ←→ is how a number is changed here, so ← cannot also mean back
// while the cursor is on a field, and with no bursts recorded the cursor can
// only ever BE on a field, which left a dirty panel with no key that both
// stopped editing and did not write. `x` is that key; esc is the one that leaves.
//
// The ↑↓ cursor is UNIFIED, indexes 0-3 are the editable fields and everything
// after them is a burst row, so the list scrolls out of the fields rather than
// needing a second cursor.

var rlModes = []client.LayerMode{client.LayerOff, client.LayerDetect, client.LayerBlock}

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
		data client.SecurityLayersResponse
		err  error
	}
	rlHistoryMsg struct {
		genTag
		data []client.RateLimitChange
		err  error
	}
	rlInsightsMsg struct {
		genTag
		data securityInsights
		err  error
	}
	rlSavedMsg struct {
		genTag
		layers client.SecurityLayers
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

	server   client.SecurityLayersResponse
	haveSrv  bool
	loadErr  error
	loading  bool
	history  []client.RateLimitChange
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

	draft    client.SecurityLayers
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
func (p *RateLimit) SetBound(sec client.SecurityLayers, dirty bool) {
	p.bound = true
	p.loading = false
	p.draft, p.hasDraft = sec, true
	p.dirty = dirty
}

func (p *RateLimit) Bound() client.SecurityLayers { return p.draft }

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
		r, err := p.deps.Client.Settings.GetSecurityLayers(bg())
		return rlLayersMsg{genTag: t, data: r, err: err}
	}
}

func (p *RateLimit) loadHistory() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		h, err := p.deps.Client.Settings.GetRateLimitHistory(bg())
		return rlHistoryMsg{genTag: t, data: h, err: err}
	}
}

func (p *RateLimit) loadInsights() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		raw, err := p.deps.Client.Stats.SecurityInsights(bg(), 7)
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