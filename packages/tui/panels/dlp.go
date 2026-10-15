// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

// No init(): DLP is not a section any more. See the note on NewRateLimit, a
// policy carries its own, per variant, and NewDLP is mounted there.

// The DLP panel, ported from tui/panels/Dlp.tsx. Draft-only edits, saved with
// `s`, never auto-saved.
//
// ONE scrollable cursor runs over two sections so nothing is ever clipped: the
// built-in secret patterns (space toggles each) and the custom patterns
// (a add · d remove).
//
// Custom patterns take the SAME GLOB syntax as the built-in
// patterns, `*` matches any run of characters, not regular expressions. The
// field is named `re` on the wire, which is exactly why the prompts say glob
// every time they are shown.
//
// The built-ins tile FOUR TO A ROW. There are seventy of them, and one per line
// put the custom section four screens below the fold, nobody scrolled that far,
// so nobody found it. The names are 23 characters at the longest, which fits
// four across any terminal this TUI already asks for. The row is also the ↑↓
// step; ←→ moves one cell, and ← from the leftmost column means back, because a
// cursor already at the edge has nowhere else for that key to take it.
//
// `A` turns every built-in on and `U` turns every one off. Seventy space presses
// was the only way to say "all of them", which is the common answer.
//
// The add editor is pinned at the TOP so what is being typed is always visible.
// Self-protection lives in Settings, not here.

// The three things a scan can do, plus off. They are separate modes because
// they are separate outcomes: detect leaves the call exactly as it was, redact
// changes what the model sees, block stops the call. Two of these used to share
// one name, "detect" masked everything it found, so choosing the weakest mode
// quietly applied the middle one.
var dlpModes = []client.LayerMode{client.LayerOff, client.LayerDetect, client.LayerRedact, client.LayerBlock}

// dlpCols is how many built-ins share a row. Fixed, not derived from the width:
// the row is the ↑↓ stride, and a stride that changed with the terminal would
// land the cursor somewhere different after every resize.
const dlpCols = 4

// dlpEntryKind discriminates the flattened cursor's rows.
type dlpEntryKind int

const (
	dlpBuiltin dlpEntryKind = iota
	dlpCustom
)

type dlpEntry struct {
	kind dlpEntryKind
	name string // built-in pattern name
	i    int    // index into custom
}

// dlpAdding is which text prompt is open, if any.
type dlpAdding string

const (
	dlpAddNone dlpAdding = ""
	dlpAddName dlpAdding = "name"
	dlpAddRe   dlpAdding = "re"
)

type (
	dlpLoadedMsg struct {
		genTag
		data client.SecurityLayersResponse
		err  error
	}
	dlpSavedMsg struct {
		genTag
		layers client.SecurityLayers
		err    error
	}
	dlpTickMsg struct{ genTag }
)

// DLP is the panel.
type DLP struct {
	deps tui.Deps

	cols, rows int
	focused    bool
	gen, tok   int

	server  client.SecurityLayersResponse
	haveSrv bool
	loading bool
	loadErr error

	dlp       client.SecurityLayers // the draft; only the dlp part is edited
	hasDraft  bool
	available []string

	sel    int
	dirty  bool
	status string

	// bound is set when the panel is not a section of its own but the DLP fold
	// of one policy VARIANT, which is where these settings actually live. The
	// owner hands the draft in before every key and reads it back after, so
	// there is one copy of it and it is the policy's; loading, saving and the
	// poll all belong to the owner and are skipped here.
	bound bool

	adding  dlpAdding
	newName string
	editIdx int // index being edited in place, -1 when adding a new entry
	input   textinput.Model
}

func NewDLP(d tui.Deps) *DLP {
	ti := textinput.New()
	ti.Prompt = ""
	return &DLP{deps: d, cols: 60, rows: 12, loading: true, editIdx: -1, input: ti, tok: nextToken()}
}

var _ tui.Panel = (*DLP)(nil)

// SetBound points the panel at layers somebody else owns.
//
// It is called before every key and every render rather than once, so a poll
// that reloaded the policy underneath cannot leave this editor showing the
// draft it had a second ago. The prompt state is deliberately not touched: a
// half-typed pattern belongs to the keyboard, not to the document.
func (p *DLP) SetBound(sec client.SecurityLayers, available []string, dirty bool) {
	p.bound = true
	p.loading = false
	p.available = available
	p.dirty = dirty
	p.adoptServer(sec)
}

// Bound reads the draft back out.
func (p *DLP) Bound() client.SecurityLayers { return p.dlp }

// CapturingKeys is true while the add/edit prompt is open, so the shell leaves
// every key, including q and esc, to the prompt.
func (p *DLP) CapturingKeys() bool { return p.adding != dlpAddNone }

// WantsLeft is whether ← means something here right now.
//
// It does inside the built-in grid, where ← steps one cell to the left, and it
// does not in the leftmost column or anywhere in the custom list. The owner asks
// before it treats ← as "back", so the grid keeps its key and the panel still
// has one that leaves it.
func (p *DLP) WantsLeft() bool {
	selC := p.selClamped()
	return selC < len(p.available) && selC%dlpCols != 0
}

func (p *DLP) apply(ctx tui.PanelContext) {
	p.cols, p.rows, p.focused, p.gen = ctx.Cols, ctx.Rows, ctx.Focused, ctx.Gen
}

func (p *DLP) tag() genTag { return genTag{gen: p.gen, tok: p.tok} }

func (p *DLP) Init(ctx tui.PanelContext) tea.Cmd {
	p.apply(ctx)
	if p.bound {
		return nil
	}
	t := p.tag()
	return tea.Batch(p.load(), tea.Tick(3*time.Second, func(time.Time) tea.Msg { return dlpTickMsg{t} }))
}

func (p *DLP) load() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		r, err := p.deps.Client.Settings.GetSecurityLayers(bg())
		return dlpLoadedMsg{genTag: t, data: r, err: err}
	}
}

func (p *DLP) Update(msg tea.Msg, ctx tui.PanelContext) (tui.Panel, tea.Cmd) {
	p.apply(ctx)
	switch m := msg.(type) {
	case dlpLoadedMsg:
		p.loading = false
		p.loadErr = m.err
		if m.err == nil {
			p.server, p.haveSrv = m.data, true
			p.available = m.data.AvailablePatterns
			if !p.dirty {
				p.adoptServer(m.data.Layers)
			}
		}
		return p, nil

	case dlpSavedMsg:
		if m.err != nil {
			p.status = "✗ " + errText(m.err)
			return p, nil
		}
		p.adoptServer(m.layers)
		p.dirty = false
		p.status = "✓ Saved"
		return p, p.load()

	case dlpTickMsg:
		if m.tok != p.tok {
			return p, nil // a previous mount's clock: let the chain end here
		}
		t := p.tag()
		cmd := tea.Tick(3*time.Second, func(time.Time) tea.Msg { return dlpTickMsg{t} })
		// Paused mid-edit and while typing, so a refresh cannot overwrite the
		// draft or the prompt under the cursor.
		if !p.dirty && p.adding == dlpAddNone {
			return p, tea.Batch(cmd, p.load())
		}
		return p, cmd

	case tea.KeyMsg:
		if !p.focused {
			return p, nil
		}
		if p.adding != dlpAddNone {
			return p, p.editKey(m)
		}
		return p, p.key(m)
	}
	return p, nil
}

// adoptServer copies the server's answer into the draft. The slices are copied
// rather than aliased: an edit to the draft must not mutate what the panel
// compares against when discarding.
func (p *DLP) adoptServer(l client.SecurityLayers) {
	p.dlp = l
	p.dlp.DLP.Patterns = append([]string(nil), l.DLP.Patterns...)
	p.dlp.DLP.Custom = append([]client.CustomPattern(nil), l.DLP.Custom...)
	p.hasDraft = true
}

func (p *DLP) entries() []dlpEntry {
	out := make([]dlpEntry, 0, len(p.available)+len(p.dlp.DLP.Custom))
	for _, name := range p.available {
		out = append(out, dlpEntry{kind: dlpBuiltin, name: name})
	}
	for i := range p.dlp.DLP.Custom {
		out = append(out, dlpEntry{kind: dlpCustom, i: i})
	}
	return out
}

func (p *DLP) selClamped() int {
	return min(p.sel, max(0, len(p.entries())-1))
}

func (p *DLP) current() (dlpEntry, bool) {
	e := p.entries()
	if len(e) == 0 {
		return dlpEntry{}, false
	}
	return e[p.selClamped()], true
}

// ── small slice helpers ────────────────────────────────────────────────────

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}