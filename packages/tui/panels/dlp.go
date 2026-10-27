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

var dlpModes = []client.LayerMode{client.LayerOff, client.LayerDetect, client.LayerRedact, client.LayerBlock}

const dlpCols = 4

type dlpEntryKind int

const (
	dlpBuiltin dlpEntryKind = iota
	dlpCustom
)

type dlpEntry struct {
	kind dlpEntryKind
	name string
	i    int
}

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

type DLP struct {
	deps tui.Deps

	cols, rows int
	focused    bool
	gen, tok   int

	server  client.SecurityLayersResponse
	haveSrv bool
	loading bool
	loadErr error

	dlp       client.SecurityLayers
	hasDraft  bool
	available []string

	sel    int
	dirty  bool
	status string

	bound bool

	adding  dlpAdding
	newName string
	editIdx int
	input   textinput.Model
}

func NewDLP(d tui.Deps) *DLP {
	ti := textinput.New()
	ti.Prompt = ""
	return &DLP{deps: d, cols: 60, rows: 12, loading: true, editIdx: -1, input: ti, tok: nextToken()}
}

var _ tui.Panel = (*DLP)(nil)

func (p *DLP) SetBound(sec client.SecurityLayers, available []string, dirty bool) {
	p.bound = true
	p.loading = false
	p.available = available
	p.dirty = dirty
	p.adoptServer(sec)
}

func (p *DLP) Bound() client.SecurityLayers { return p.dlp }

func (p *DLP) CapturingKeys() bool { return p.adding != dlpAddNone }

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
			return p, nil
		}
		t := p.tag()
		cmd := tea.Tick(3*time.Second, func(time.Time) tea.Msg { return dlpTickMsg{t} })

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
	// "down" on an empty list can arm a negative selection; clamp both ends
	// so a stale negative value never indexes entries() out of range.
	return max(0, min(p.sel, len(p.entries())-1))
}

func (p *DLP) current() (dlpEntry, bool) {
	e := p.entries()
	if len(e) == 0 {
		return dlpEntry{}, false
	}
	return e[p.selClamped()], true
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}