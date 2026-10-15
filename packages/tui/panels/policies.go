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

// The Policies panel. It is the dashboard's /policies, level by level, and
// every edit is DRAFT-only until `s`:
//
//	list   : browse policies (↑↓), open one (→/enter), activate (a), deactivate
//	         (x), create (n), delete (d, twice)
//	policy : ONE policy: its variants along the top and its three layers under
//	         them. tab switches variant · v new variant · V delete · m mode
//	rules  : a variant's rules. space on/off · e effect · d delete · n new ·
//	         enter opens the rule · s save · x discard
//	rule   : the rule editor, mirroring the dashboard. Effect, one Constraint
//	         type, Permissions, Priority, Description, Match
//	match  : the constraint's value list, with [ ] wildcard toggles
//	dlp    : that variant's secret detectors
//	rate   : that variant's rate limit, beside this project's real bursts
//
// A POLICY IS NOT ONE SET OF RULES, and this is the part worth reading before
// changing anything here. It is a set of interchangeable variants, each with
// its own rules and its own layers, and a machine enforces exactly one of them
//, which one is the host's choice, made on Fleet. The dashboard has said so
// since the editor grew tabs; a terminal that showed only `$.rules` would be
// showing the default variant and calling it the policy.
//
// The draft is held as `variants`, and the level the user is looking at is
// FOLDED OUT of the active one into p.rules / p.sec / p.mode and folded back on
// every switch. Every key handler below therefore edits the visible variant
// without knowing which one it is, and only fold/unfold know where it lives.
//
// The DLP and rate-limit editors are the two panels next door, mounted BOUND:
// they were sections of their own while those settings were a project's, and
// they are folds of a variant now that the settings are a policy's. Nothing
// reaches the cloud without an explicit save (PUT /policies/:id).

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

// The three layers of a variant, in the dashboard's order. Rules first because
// it is the one every policy has.
const (
	layerRules = iota
	layerDLP
	layerRate
	layerCount
)

// The rule editor's fields, in the dashboard's order. Enabled is not among them:
// it is toggled with space on the rules list, the way the dashboard toggles it
// on the rule card.
type polField struct {
	label string
	kind  string // effect · ctype · perms · priority · text · match
}

var polFields = []polField{
	{"Effect", "effect"},
	{"Constraint", "ctype"},
	{"Permissions", "perms"},
	{"Priority", "priority"},
	{"Description", "text"},
	{"Match", "match"},
}

// PERMISSIONS ARE ONLY A QUESTION FOR A RULE ABOUT FILES.
//
// READ, WRITE, EXECUTE and NETWORK come from the TOOL a call was made with, so narrowing
// by them says WHICH KIND of tool a rule covers. For a path or a filename that is a real
// choice, block reading a directory but not writing to it, or the reverse. For the other
// two kinds it is noise at best and a trap at worst: a rule about a command already only
// matches a command, a rule about a URL already only matches a fetch, and the row sat
// there showing all four lit as though somebody had chosen them.
//
// Worse, it is one of the three rows ←→ edits rather than navigates, so the way out of
// the editor on that row is not the way out on the next one.
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
	// polActionMsg is the answer to anything that changes cloud state from the
	// list view: activate, deactivate, delete, create.
	polActionMsg struct {
		genTag
		status        string
		refreshList   bool
		refreshActive bool
		resetCursor   bool
	}
	// polLayersMsg is the detector catalogue and the project-wide fallback.
	polLayersMsg struct {
		genTag
		data client.SecurityLayersResponse
		err  error
	}
	polTickMsg struct{ genTag }
)

// Policies is the panel.
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

	detailID      string // policy the draft belongs to
	detailLoading bool
	detailErr     error
	detail        client.PolicyDetail
	haveDetail    bool
	unreadable    int

	view       polView
	pi, ri, fi int
	permCursor int
	matchSel   int
	li         int // which of the three layers the cursor is on

	// The draft, and the window onto it. variants is the whole policy; rules,
	// sec and unreadable are variant vi folded out for editing. See the package
	// note above: everything below edits the window and only fold/unfold know
	// it is a window.
	variants []variantDraft
	vi       int

	rules []ruleDoc
	sec   client.SecurityLayers
	mode  client.PolicyMode
	dirty bool

	// available is the built-in detector list and fallback is the project-wide
	// block a policy written before variants existed inherits. Both are read
	// once, from the settings endpoint the old DLP and Rate Limit sections used
	// to own, every project that ever used those pages still has that row, and
	// it is what their machines are enforcing today, so an old policy opens
	// showing what is in force rather than a screen of defaults that would
	// quietly turn DLP off on the first save.
	available    []string
	fallback     client.SecurityLayers
	layersLoaded bool

	dlpPanel  *DLP
	ratePanel *RateLimit
	// rateStarted is whether the burst scan has been started. See the note
	// where it is set.
	rateStarted bool

	status     string
	pendingDel string

	creating   bool
	busyCreate bool
	editing    bool
	input      textinput.Model
}

// variantDraft is one variant being edited: its rules with their original bytes
// beside them, and its own layers.
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

// CapturingKeys is true while a policy is being named or a field typed into,
// and while a bound layer editor has its own prompt open: those keys are the
// child's, and the shell must not read the q in a pattern as quit.
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

// loadLayers is the detector catalogue and the project-wide fallback. It is
// read once per mount: the catalogue is a fixed list of names, and the fallback
// is a row nothing writes any more.
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

// ensureDetail loads the open policy's rules when the cursor has moved to
// another one. It is a no-op while the right policy is already loaded, so key
// repeat on ↑↓ does not fire a request per keystroke for a policy the user is
// scrolling past.
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
		// An answer for a policy the cursor has already left is stale: applying
		// it would replace the draft the user is looking at.
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
			// A policy adopted before this answer landed took an empty block as
			// its fallback. Re-adopting is safe while nothing is unsaved, and
			// is the difference between an old policy opening with its real
			// detectors and opening with none of them ticked.
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
		// The draft is not replaced with the answer. A save returns the policy
		// with its variants PROJECTED away, the default variant's rules moved
		// to the top level, which is the shape a guard reads, so adopting it
		// would collapse a policy with three variants into one. The reload
		// below reads the stored document back instead.
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
			return p, nil // a previous mount's clock: let the chain end here
		}
		t := p.tag()
		cmd := tea.Tick(3*time.Second, func(time.Time) tea.Msg { return polTickMsg{t} })
		// The list and which policy is active refresh in the background so a
		// change made elsewhere shows up. The OPEN policy's rules deliberately
		// do not: that would reset the cursor and clobber unsaved edits. ^R is
		// the full refresh.
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

	// Anything left is one of the bound editors' own messages, the burst scan,
	// its clock. They are forwarded whatever level is on screen, so the chain
	// a child started does not end the moment the cursor leaves its fold and
	// have to be started again when it comes back.
	return p, p.forwardToLayers(msg)
}

func (p *Policies) mutate() {
	p.dirty = true
	p.status = ""
}