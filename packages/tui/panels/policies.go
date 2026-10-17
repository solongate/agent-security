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

func init() { tui.Register(tui.SectionPolicies, func(d tui.Deps) tui.Panel { return NewPolicies(d) }) }

type polView int

const (
	viewList polView = iota
	viewPolicy
	viewRules
	viewRule
	viewMatch
	viewDLP
	viewRate
)

const (
	layerRules = iota
	layerDLP
	layerRate
	layerCount
)

type polField struct {
	label string
	kind  string
}

var polFields = []polField{
	{"Effect", "effect"},
	{"Constraint", "ctype"},
	{"Permissions", "perms"},
	{"Priority", "priority"},
	{"Description", "text"},
	{"Match", "match"},
}

func fieldsFor(r client.PolicyRule) []polField {
	switch currentCType(r) {
	case cPath, cFilename:
		return polFields
	}
	out := make([]polField, 0, len(polFields)-1)
	for _, f := range polFields {
		if f.kind == "perms" {
			continue
		}
		out = append(out, f)
	}
	return out
}

type (
	polListMsg struct {
		genTag
		data []client.PolicyListEntry
		err  error
	}
	polActiveMsg struct {
		genTag
		data client.ActivePolicy
		err  error
	}
	polDetailMsg struct {
		genTag
		id   string
		data client.PolicyDetail
		err  error
	}
	polSavedMsg struct {
		genTag
		rules client.Rules
		err   error
	}

	polActionMsg struct {
		genTag
		status        string
		refreshList   bool
		refreshActive bool
		resetCursor   bool
	}

	polLayersMsg struct {
		genTag
		data client.SecurityLayersResponse
		err  error
	}
	polTickMsg struct{ genTag }
)

type Policies struct {
	deps tui.Deps

	cols, rows int
	focused    bool
	gen, tok   int

	policies    []client.PolicyListEntry
	listErr     error
	listLoading bool

	activeID   string
	activeBy   string
	activeLoad bool

	detailID      string
	detailLoading bool
	detailErr     error
	detail        client.PolicyDetail
	haveDetail    bool
	unreadable    int

	view       polView
	pi, ri, fi int
	permCursor int
	matchSel   int
	li         int

	variants []variantDraft
	vi       int

	rules []ruleDoc
	sec   client.SecurityLayers
	mode  client.PolicyMode
	dirty bool

	available    []string
	fallback     client.SecurityLayers
	layersLoaded bool

	dlpPanel  *DLP
	ratePanel *RateLimit

	rateStarted bool

	status     string
	pendingDel string

	creating   bool
	busyCreate bool
	editing    bool
	input      textinput.Model
}

type variantDraft struct {
	id, name   string
	rules      []ruleDoc
	unreadable int
	sec        client.SecurityLayers
}

func NewPolicies(d tui.Deps) *Policies {
	ti := textinput.New()
	ti.Prompt = ""
	return &Policies{
		deps: d, cols: 60, rows: 12,
		listLoading: true, activeLoad: true,
		mode: client.ModeDenylist, input: ti, tok: nextToken(),
		dlpPanel: NewDLP(d), ratePanel: NewRateLimit(d),
	}
}

var _ tui.Panel = (*Policies)(nil)

func (p *Policies) CapturingKeys() bool {
	if p.editing || p.creating {
		return true
	}
	switch p.view {
	case viewDLP:
		return p.dlpPanel.CapturingKeys()
	case viewRate:
		return p.ratePanel.CapturingKeys()
	}
	return false
}

func (p *Policies) apply(ctx tui.PanelContext) {
	p.cols, p.rows, p.focused, p.gen = ctx.Cols, ctx.Rows, ctx.Focused, ctx.Gen
}

func (p *Policies) tag() genTag { return genTag{gen: p.gen, tok: p.tok} }

func (p *Policies) Init(ctx tui.PanelContext) tea.Cmd {
	p.apply(ctx)
	t := p.tag()
	return tea.Batch(p.loadList(), p.loadActive(), p.loadLayers(),
		tea.Tick(3*time.Second, func(time.Time) tea.Msg { return polTickMsg{t} }))
}

func (p *Policies) loadList() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		l, err := p.deps.Client.Policies.List(bg())
		return polListMsg{genTag: t, data: l, err: err}
	}
}

func (p *Policies) loadActive() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		a, err := p.deps.Client.Policies.Active(bg(), "")
		return polActiveMsg{genTag: t, data: a, err: err}
	}
}

func (p *Policies) loadLayers() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		r, err := p.deps.Client.Settings.GetSecurityLayers(bg())
		return polLayersMsg{genTag: t, data: r, err: err}
	}
}

func (p *Policies) loadDetail(id string) tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		d, err := p.deps.Client.Policies.Get(bg(), id, 0)
		return polDetailMsg{genTag: t, id: id, data: d, err: err}
	}
}

func (p *Policies) selected() (client.PolicyListEntry, bool) {
	if len(p.policies) == 0 {
		return client.PolicyListEntry{}, false
	}
	return p.policies[min(p.pi, len(p.policies)-1)], true
}

func (p *Policies) ensureDetail() tea.Cmd {
	sel, ok := p.selected()
	if !ok || sel.ID == p.detailID {
		return nil
	}
	p.detailID = sel.ID
	p.detailLoading = true
	p.detailErr = nil
	p.haveDetail = false
	return p.loadDetail(sel.ID)
}

func (p *Policies) Update(msg tea.Msg, ctx tui.PanelContext) (tui.Panel, tea.Cmd) {
	p.apply(ctx)
	switch m := msg.(type) {
	case polListMsg:
		p.listLoading = false
		p.listErr = m.err
		if m.err == nil {
			p.policies = m.data
			if p.busyCreate && len(p.policies) > 0 {
				p.busyCreate = false
			}
			return p, p.ensureDetail()
		}
		return p, nil

	case polActiveMsg:
		p.activeLoad = false
		if m.err == nil {
			p.activeID = ""
			if m.data.Policy != nil {
				p.activeID = m.data.Policy.ID
			}
			p.activeBy = m.data.MatchedBy
		}
		return p, nil

	case polDetailMsg:

		if m.id != p.detailID {
			return p, nil
		}
		p.detailLoading = false
		p.detailErr = m.err
		if m.err != nil {
			return p, nil
		}
		p.detail = m.data
		p.haveDetail = true
		p.adoptPolicy(m.data.PolicySet)
		p.dirty = false
		p.ri = 0
		return p, nil

	case polLayersMsg:
		if m.err == nil {
			p.available = m.data.AvailablePatterns
			p.fallback = m.data.Layers
			p.layersLoaded = true

			if p.haveDetail && !p.dirty {
				p.adoptPolicy(p.detail.PolicySet)
			}
		}
		return p, nil

	case polSavedMsg:
		if m.err != nil {
			p.status = "✗ " + errText(m.err)
			return p, nil
		}
		p.dirty = false
		p.status = "✓ Saved"

		var cmds []tea.Cmd
		cmds = append(cmds, p.loadList())
		if p.detailID != "" {
			cmds = append(cmds, p.loadDetail(p.detailID))
		}
		return p, tea.Batch(cmds...)

	case polActionMsg:
		p.status = m.status
		var cmds []tea.Cmd
		if m.resetCursor {
			p.pi = 0
			p.detailID = ""
		}
		if m.refreshList {
			cmds = append(cmds, p.loadList())
		}
		if m.refreshActive {
			cmds = append(cmds, p.loadActive())
		}
		return p, tea.Batch(cmds...)

	case polTickMsg:
		if m.tok != p.tok {
			return p, nil
		}
		t := p.tag()
		cmd := tea.Tick(3*time.Second, func(time.Time) tea.Msg { return polTickMsg{t} })

		if !p.creating && !p.editing {
			return p, tea.Batch(cmd, p.loadList(), p.loadActive())
		}
		return p, cmd

	case tea.KeyMsg:
		if !p.focused {
			return p, nil
		}
		if p.creating {
			return p, p.creatingKey(m)
		}
		if p.editing {
			return p, p.editingKey(m)
		}
		return p, p.key(m)
	}

	return p, p.forwardToLayers(msg)
}

func (p *Policies) mutate() {
	p.dirty = true
	p.status = ""
}