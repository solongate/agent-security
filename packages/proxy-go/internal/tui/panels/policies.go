package panels

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/tui"
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
//	rule   : the rule editor, mirroring the dashboard — Effect, one Constraint
//	         type, Permissions, Priority, Description, Match
//	match  : the constraint's value list, with [ ] wildcard toggles
//	dlp    : that variant's secret detectors
//	rate   : that variant's rate limit, beside this project's real bursts
//
// A POLICY IS NOT ONE SET OF RULES, and this is the part worth reading before
// changing anything here. It is a set of interchangeable variants, each with
// its own rules and its own layers, and a machine enforces exactly one of them
// — which one is the host's choice, made on Fleet. The dashboard has said so
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

type (
	polListMsg struct {
		genTag
		data []api.PolicyListEntry
		err  error
	}
	polActiveMsg struct {
		genTag
		data api.ActivePolicy
		err  error
	}
	polDetailMsg struct {
		genTag
		id   string
		data api.PolicyDetail
		err  error
	}
	polSavedMsg struct {
		genTag
		rules api.Rules
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
		data api.SecurityLayersResponse
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

	policies    []api.PolicyListEntry
	listErr     error
	listLoading bool

	activeID   string
	activeBy   string
	activeLoad bool

	detailID      string // policy the draft belongs to
	detailLoading bool
	detailErr     error
	detail        api.PolicyDetail
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
	sec   api.SecurityLayers
	mode  api.PolicyMode
	dirty bool

	// available is the built-in detector list and fallback is the project-wide
	// block a policy written before variants existed inherits. Both are read
	// once, from the settings endpoint the old DLP and Rate Limit sections used
	// to own — every project that ever used those pages still has that row, and
	// it is what their machines are enforcing today, so an old policy opens
	// showing what is in force rather than a screen of defaults that would
	// quietly turn DLP off on the first save.
	available    []string
	fallback     api.SecurityLayers
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
	sec        api.SecurityLayers
}

func NewPolicies(d tui.Deps) *Policies {
	ti := textinput.New()
	ti.Prompt = ""
	return &Policies{
		deps: d, cols: 60, rows: 12,
		listLoading: true, activeLoad: true,
		mode: api.ModeDenylist, input: ti, tok: nextToken(),
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
		l, err := p.deps.API.Policies.List(bg())
		return polListMsg{genTag: t, data: l, err: err}
	}
}

func (p *Policies) loadActive() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		a, err := p.deps.API.Policies.Active(bg(), "")
		return polActiveMsg{genTag: t, data: a, err: err}
	}
}

// loadLayers is the detector catalogue and the project-wide fallback. It is
// read once per mount: the catalogue is a fixed list of names, and the fallback
// is a row nothing writes any more.
func (p *Policies) loadLayers() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		r, err := p.deps.API.Settings.GetSecurityLayers(bg())
		return polLayersMsg{genTag: t, data: r, err: err}
	}
}

func (p *Policies) loadDetail(id string) tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		d, err := p.deps.API.Policies.Get(bg(), id, 0)
		return polDetailMsg{genTag: t, id: id, data: d, err: err}
	}
}

func (p *Policies) selected() (api.PolicyListEntry, bool) {
	if len(p.policies) == 0 {
		return api.PolicyListEntry{}, false
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
		// with its variants PROJECTED away — the default variant's rules moved
		// to the top level, which is the shape a guard reads — so adopting it
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

	// Anything left is one of the bound editors' own messages — the burst scan,
	// its clock. They are forwarded whatever level is on screen, so the chain
	// a child started does not end the moment the cursor leaves its fold and
	// have to be started again when it comes back.
	return p, p.forwardToLayers(msg)
}

// forwardToLayers hands a message to both bound editors.
//
// Both, rather than the one on screen: each child's messages are its own types,
// so the other one drops it, and the alternative is a child whose ticker stops
// being fed the moment somebody opens the other fold.
func (p *Policies) forwardToLayers(msg tea.Msg) tea.Cmd {
	if _, isKey := msg.(tea.KeyMsg); isKey {
		return nil
	}
	ctx := p.childCtx()
	var cmds []tea.Cmd
	if p.dlpPanel != nil {
		next, cmd := p.dlpPanel.Update(msg, ctx)
		p.storeLayer(next)
		cmds = append(cmds, cmd)
	}
	if p.ratePanel != nil {
		next, cmd := p.ratePanel.Update(msg, ctx)
		p.storeLayer(next)
		cmds = append(cmds, cmd)
	}
	return tea.Batch(cmds...)
}

// adoptRules turns a wire rule array into editable rules, keeping each rule's
// original bytes beside its decoded form.
func adoptRules(r api.Rules) []ruleDoc {
	out := make([]ruleDoc, 0, len(r.Items))
	for i, item := range r.Items {
		doc := ruleDoc{rule: item}
		// The raw slice only lines up with the decoded one when every element
		// decoded. When some did not, the bytes are not attached rather than
		// attached to the wrong rule — and save() refuses anyway.
		if r.Unreadable == 0 && i < len(r.Raw) {
			doc.raw = r.Raw[i]
		}
		out = append(out, doc)
	}
	return out
}

// adoptPolicy turns a stored policy into the draft.
//
// A policy written before variants existed becomes exactly ONE of them, holding
// the rules it already had and the layers the project has been enforcing, so
// opening an old policy here and saving it back describes the same enforcement
// it described before. This is the same normalisation the dashboard does on the
// way into its editor, and the two must not disagree: a policy opened in one
// and saved in the other would otherwise change what it means.
func (p *Policies) adoptPolicy(set api.PolicySet) {
	p.variants = p.variants[:0]
	for _, v := range polDefaultFirst(set.VariantList(), set.DefaultVariant) {
		d := variantDraft{
			id:         v.ID,
			name:       v.Name,
			rules:      adoptRules(v.Rules),
			unreadable: v.Rules.Unreadable,
			sec:        p.layersOf(set, v),
		}
		if d.id == "" {
			d.id = polVariantID(len(p.variants))
		}
		if d.name == "" {
			d.name = polVariantName(p.variants)
		}
		p.variants = append(p.variants, d)
	}
	p.mode = set.Mode
	if p.mode == "" {
		p.mode = api.ModeDenylist
	}
	p.vi = min(p.vi, len(p.variants)-1)
	p.vi = max(0, p.vi)
	p.unfold()
}

// layersOf is which block a variant edits: its own, then the policy's, then the
// project-wide row the old sections wrote. The order is the dashboard's.
func (p *Policies) layersOf(set api.PolicySet, v api.PolicyVariant) api.SecurityLayers {
	switch {
	case v.Security != nil:
		return normaliseLayers(*v.Security)
	case set.Security != nil:
		return normaliseLayers(*set.Security)
	default:
		return normaliseLayers(p.fallback)
	}
}

// normaliseLayers fills in the modes a document can be missing and copies the
// slices, so editing a draft cannot reach back into what it was adopted from.
func normaliseLayers(l api.SecurityLayers) api.SecurityLayers {
	out := l
	if out.DLP.Mode == "" {
		out.DLP.Mode = api.LayerOff
	}
	if out.RateLimit.Mode == "" {
		out.RateLimit.Mode = api.LayerOff
	}
	out.DLP.Patterns = append([]string(nil), l.DLP.Patterns...)
	out.DLP.Custom = append([]api.CustomPattern(nil), l.DLP.Custom...)
	return out
}

// fold writes the visible half back into the variant it came from, and unfold
// takes the next one out. Every edit between the two happens on p.rules and
// p.sec, which is why a variant switch is the only place either is called.
func (p *Policies) fold() {
	if len(p.variants) == 0 {
		// A draft that was never adopted still has one variant: the rules on
		// screen are it. Creating it here rather than refusing means there is
		// no path through this panel that saves a policy with no variants.
		p.variants = []variantDraft{{id: polVariantID(0), name: "Base"}}
		p.vi = 0
	}
	if p.vi < 0 || p.vi >= len(p.variants) {
		return
	}
	p.variants[p.vi].rules = p.rules
	p.variants[p.vi].sec = p.sec
	p.variants[p.vi].unreadable = p.unreadable
}

func (p *Policies) unfold() {
	if p.vi < 0 || p.vi >= len(p.variants) {
		p.rules, p.sec, p.unreadable = nil, normaliseLayers(api.SecurityLayers{}), 0
		return
	}
	v := p.variants[p.vi]
	p.rules, p.sec, p.unreadable = v.rules, v.sec, v.unreadable
	p.ri = min(p.ri, max(0, len(p.rules)-1))
}

// polDefaultFirst puts the default variant at index 0.
//
// The editor treats "first" and "default" as the same thing, which is one fewer
// piece of state to keep true and one fewer way for a policy to name a default
// that has been deleted. The dashboard reorders on the way in for the same
// reason, and the two must agree: the top level of a saved document carries the
// first variant's rules, so a terminal that ordered them differently would
// hand every unpinned machine a different variant than the dashboard did.
func polDefaultFirst(list []api.PolicyVariant, defaultID string) []api.PolicyVariant {
	if defaultID == "" || len(list) < 2 {
		return list
	}
	for i, v := range list {
		if v.ID != defaultID || i == 0 {
			continue
		}
		out := append([]api.PolicyVariant{v}, list[:i]...)
		return append(out, list[i+1:]...)
	}
	return list
}

// polVariantID is the id a variant gets when it arrives without one, in the
// dashboard's spelling.
//
// It is generated rather than derived from the name or the position: the name
// is editable, the position is not stable across a removal, and this string is
// what a host's pin on a developer points AT. The index is in it because two
// variants added in the same millisecond would otherwise collide, which is
// exactly what pressing v twice does.
func polVariantID(i int) string {
	return "variant-" + itoa(int(time.Now().UnixMilli())) + "-" + itoa(i+1)
}

// polVariantName is the first free "Variant N", so adding, removing and adding
// again does not produce two tabs with one name. The first is Base rather than
// Default: a reader seeing two tabs called Default and Strict has to work out
// which is which, and Base says what it is.
func polVariantName(existing []variantDraft) string {
	if len(existing) == 0 {
		return "Base"
	}
	taken := map[string]bool{}
	for _, v := range existing {
		taken[strings.ToLower(strings.TrimSpace(v.name))] = true
	}
	for n := len(existing) + 1; n < len(existing)+polMaxVariants+2; n++ {
		name := "Variant " + itoa(n)
		if !taken[strings.ToLower(name)] {
			return name
		}
	}
	return "Variant " + itoa(len(existing)+1)
}

// polMaxVariants is the dashboard's bound, for the same reason: eight is far
// past any policy anyone has written and small enough that the tab strip stays
// a strip.
const polMaxVariants = 8

func (p *Policies) mutate() {
	p.dirty = true
	p.status = ""
}

// ── keys ───────────────────────────────────────────────────────────────────

func (p *Policies) key(k tea.KeyMsg) tea.Cmd {
	s := k.String()
	if s == "ctrl+r" {
		p.status = "⟳ refreshed " + time.Now().Format("15:04:05")
		cmds := []tea.Cmd{p.loadList(), p.loadActive()}
		if p.detailID != "" {
			cmds = append(cmds, p.loadDetail(p.detailID))
		}
		return tea.Batch(cmds...)
	}
	switch p.view {
	case viewList:
		return p.listKey(s)
	case viewPolicy:
		return p.policyKey(s)
	case viewRules:
		return p.rulesKey(s)
	case viewMatch:
		return p.matchKey(s)
	case viewDLP, viewRate:
		return p.layerKey(k, s)
	default:
		return p.ruleKey(k, s)
	}
}

// policyKey is one policy: its variants and its three layers.
func (p *Policies) policyKey(s string) tea.Cmd {
	switch s {
	case "left":
		p.view = viewList
		p.status = ""
	case "up":
		p.li = max(0, p.li-1)
	case "down":
		p.li = min(layerCount-1, p.li+1)
	case "enter", "right":
		switch p.li {
		case layerRules:
			p.view = viewRules
		case layerDLP:
			p.view = viewDLP
		case layerRate:
			p.view = viewRate
			// Once. Init arms the burst scan's clock, and calling it on every
			// visit would leave the previous chain running beside the new one
			// and poll twice as often for each time the fold was opened.
			if !p.rateStarted {
				p.rateStarted = true
				return p.ratePanel.Init(p.childCtx())
			}
		}
	case "tab":
		p.switchVariant(1)
	case "shift+tab":
		p.switchVariant(-1)
	case "m":
		p.flipMode()
	case "v":
		p.addVariant()
	case "V":
		p.dropVariant()
	case "s":
		return p.save()
	case "x":
		p.discard()
	}
	return nil
}

// switchVariant folds the visible half back before taking the next one out. A
// switch that forgot the fold would discard every edit made since the last one.
func (p *Policies) switchVariant(d int) {
	if len(p.variants) < 2 {
		return
	}
	p.fold()
	p.vi = (p.vi + d + len(p.variants)) % len(p.variants)
	p.unfold()
	p.status = ""
}

// addVariant copies the visible one rather than starting empty.
//
// A second variant is almost always "the same policy, with one thing different"
// — a contractor on a whitelist, everybody else on a denylist — and starting
// from nothing means retyping a rule set to change one rule in it.
func (p *Policies) addVariant() {
	if len(p.variants) >= polMaxVariants {
		p.status = "✗ " + itoa(polMaxVariants) + " variants is the limit — a tab strip past that is a list"
		return
	}
	p.fold()
	src := variantDraft{sec: normaliseLayers(p.fallback)}
	if p.vi < len(p.variants) {
		src = p.variants[p.vi]
	}
	next := variantDraft{
		id:   polVariantID(len(p.variants)),
		name: polVariantName(p.variants),
		sec:  normaliseLayers(src.sec),
	}
	// The rules are copied WITHOUT their original bytes: those bytes belong to
	// a rule that is already in the document, and two variants handing the same
	// object to the server is how one edit lands in both.
	for _, d := range src.rules {
		next.rules = append(next.rules, ruleDoc{rule: d.rule, edited: true})
	}
	p.variants = append(p.variants, next)
	p.vi = len(p.variants) - 1
	p.unfold()
	p.mutate()
	p.status = "added " + next.name + " — a copy of what you were looking at"
}

// dropVariant refuses to remove the last one. A policy with no variants is a
// policy with no rules, and that is a thing to notice rather than a thing to do
// with one keystroke.
func (p *Policies) dropVariant() {
	if len(p.variants) < 2 {
		p.status = "✗ a policy needs one variant — this is it"
		return
	}
	name := p.variants[p.vi].name
	p.variants = append(p.variants[:p.vi:p.vi], p.variants[p.vi+1:]...)
	p.vi = max(0, min(p.vi, len(p.variants)-1))
	p.unfold()
	p.mutate()
	p.status = "removed " + name + " — anybody pinned to it falls back to " + p.variants[0].name
}

func (p *Policies) flipMode() {
	if p.mode == api.ModeDenylist {
		p.mode = api.ModeWhitelist
	} else {
		p.mode = api.ModeDenylist
	}
	p.mutate()
}

// layerKey drives the two bound editors next door.
//
// The draft goes in before the key and comes back after, so there is one copy
// of a variant's layers and it is this panel's. Save, discard and back are
// taken first because they belong to the policy; everything else is the
// child's, including the keys that would mean something else here.
func (p *Policies) layerKey(k tea.KeyMsg, s string) tea.Cmd {
	child := p.layerPanel()
	if child == nil {
		p.view = viewPolicy
		return nil
	}
	if !p.childCapturing() {
		switch s {
		case "s":
			p.syncFromLayer()
			return p.save()
		case "x":
			p.discard()
			return nil
		case "left":
			if !p.layerWantsLeft() {
				p.syncFromLayer()
				p.view = viewPolicy
				return nil
			}
		}
	}
	p.syncToLayer()
	before := p.sec
	next, cmd := child.Update(k, p.childCtx())
	p.storeLayer(next)
	p.syncFromLayer()
	if !layersEqual(before, p.sec) {
		p.mutate()
	}
	return cmd
}

func (p *Policies) listKey(s string) tea.Cmd {
	switch s {
	case "up":
		p.pendingDel = ""
		p.pi = max(0, p.pi-1)
		return p.ensureDetail()
	case "down":
		p.pendingDel = ""
		p.pi = min(len(p.policies)-1, p.pi+1)
		return p.ensureDetail()
	case "enter", "right":
		p.status = ""
		p.view = viewPolicy
		p.li = layerRules
		return nil
	case "a":
		sel, ok := p.selected()
		if !ok {
			return nil
		}
		p.status = "Activating…"
		id, name := sel.ID, sel.Name
		t := p.tag()
		return func() tea.Msg {
			if err := p.deps.API.Policies.SetActive(bg(), id); err != nil {
				return polActionMsg{genTag: t, status: "✗ " + errText(err)}
			}
			return polActionMsg{
				genTag:        t,
				status:        `✓ "` + name + `" is now the ACTIVE policy (pinned) · reaches agents in ~30s`,
				refreshActive: true,
			}
		}
	case "x":
		p.status = "Deactivating…"
		t := p.tag()
		return func() tea.Msg {
			// The empty id is the unpin. The API takes "" rather than null here.
			if err := p.deps.API.Policies.SetActive(bg(), ""); err != nil {
				return polActionMsg{genTag: t, status: "✗ " + errText(err)}
			}
			return polActionMsg{
				genTag:        t,
				status:        "✓ active policy: NONE — no rules enforced, w/b grants are refused",
				refreshActive: true,
			}
		}
	case "n", "N":
		p.status = ""
		p.creating = true
		p.input.SetValue("")
		p.input.Focus()
		return nil
	case "d":
		sel, ok := p.selected()
		if !ok {
			return nil
		}
		if p.pendingDel != sel.ID {
			p.pendingDel = sel.ID
			p.status = `⚠ d again to DELETE policy "` + sel.Name + `" — cannot be undone`
			return nil
		}
		p.pendingDel = ""
		p.status = "Deleting…"
		id, name := sel.ID, sel.Name
		t := p.tag()
		return func() tea.Msg {
			if err := p.deps.API.Policies.Remove(bg(), id); err != nil {
				return polActionMsg{genTag: t, status: "✗ " + errText(err)}
			}
			return polActionMsg{
				genTag:        t,
				status:        `✓ deleted policy "` + name + `"`,
				refreshList:   true,
				refreshActive: true,
				resetCursor:   true,
			}
		}
	}
	return nil
}

func (p *Policies) rulesKey(s string) tea.Cmd {
	switch s {
	case "left":
		p.view = viewPolicy
		p.status = ""
	case "up":
		p.ri = max(0, p.ri-1)
	case "down":
		p.ri = min(len(p.rules)-1, p.ri+1)
	case "enter", "right":
		if p.ri < len(p.rules) {
			p.fi = 0
			p.view = viewRule
		}
	case " ":
		if p.ri < len(p.rules) {
			p.rules[p.ri].rule.Enabled = !p.rules[p.ri].rule.Enabled
			p.rules[p.ri].edited = true
			p.mutate()
		}
	case "e":
		if p.ri < len(p.rules) {
			p.flipEffect(p.ri)
		}
	case "d":
		if p.ri < len(p.rules) {
			p.rules = append(p.rules[:p.ri:p.ri], p.rules[p.ri+1:]...)
			p.ri = max(0, min(p.ri, len(p.rules)-1))
			p.mutate()
		}
	case "m":
		p.flipMode()
	case "n":
		// A fresh rule starts with a command constraint, exactly as the
		// dashboard does, so it is never a blanket match waiting to be saved —
		// the user only has to fill in the value.
		nr := api.PolicyRule{
			ID:                 "rule-" + itoa(int(time.Now().UnixMilli())),
			Effect:             "DENY",
			Priority:           100,
			ToolPattern:        "*",
			MinimumTrustLevel:  "UNTRUSTED",
			Enabled:            true,
			CommandConstraints: &api.Constraint{Denied: []string{}},
		}
		p.rules = append([]ruleDoc{{rule: nr, edited: true}}, p.rules...)
		p.ri = 0
		p.fi = 0
		p.view = viewRule
		p.mutate()
	case "s":
		return p.save()
	case "x":
		p.discard()
	}
	return nil
}

func (p *Policies) matchKey(s string) tea.Cmd {
	if p.ri >= len(p.rules) {
		p.view = viewRules
		return nil
	}
	items := matchItems(p.rules[p.ri].rule)
	switch s {
	case "left", "esc":
		p.view = viewRule
	case "up":
		p.matchSel = max(0, p.matchSel-1)
	case "down":
		p.matchSel = min(max(0, len(items)-1), p.matchSel+1)
	case "a":
		next := append(append([]string(nil), items...), "")
		p.setItems(next)
		p.matchSel = len(next) - 1
		p.beginEdit("")
	case "enter", "e":
		if len(items) == 0 {
			p.setItems([]string{""})
			p.matchSel = 0
			p.beginEdit("")
			return nil
		}
		p.beginEdit(items[min(p.matchSel, len(items)-1)])
	case "[", "]":
		side := "left"
		if s == "]" {
			side = "right"
		}
		if p.matchSel < len(items) {
			next := append([]string(nil), items...)
			next[p.matchSel] = flipStar(next[p.matchSel], side)
			p.setItems(next)
		}
	case "d":
		if len(items) > 0 && p.matchSel < len(items) {
			next := append(items[:p.matchSel:p.matchSel], items[p.matchSel+1:]...)
			p.setItems(next)
			p.matchSel = max(0, min(p.matchSel, len(next)-1))
		}
	case "s":
		return p.save()
	}
	return nil
}

func (p *Policies) ruleKey(k tea.KeyMsg, s string) tea.Cmd {
	if p.ri >= len(p.rules) {
		p.view = viewRules
		return nil
	}
	field := polFields[min(p.fi, len(polFields)-1)]
	switch {
	// ← leaves the editor, EXCEPT on the three fields whose own hint says ←→
	// picks a value. The Ink version tested leftArrow first in one else-if
	// chain, so its ctype / perms / priority left branches could never run and
	// those fields could only be cycled forwards. Anything ← used to do it
	// still does on Effect, Description and Match, so there is always a way
	// back out of the editor with one key.
	// esc ALWAYS leaves the editor, on every field.
	//
	// It was not handled here at all, so it fell through to the app and moved focus to
	// the section list — out of the panel entirely, with the rule still half-edited and
	// no way to answer the "unsaved (s save · x discard)" prompt the editor was showing.
	// ← only leaves from three of the six fields, because on the other three it picks a
	// value, so there was no key that reliably meant "get me out of here".
	case s == "esc":
		p.view = viewRules
	case s == "left" && field.kind != "ctype" && field.kind != "perms" && field.kind != "priority":
		p.view = viewRules
	case s == "up":
		p.fi = max(0, p.fi-1)
	case s == "down":
		p.fi = min(len(polFields)-1, p.fi+1)
	case field.kind == "effect" && (s == " " || s == "right"):
		p.flipEffect(p.ri)
	case field.kind == "ctype" && (s == " " || s == "right" || s == "left"):
		dir := 1
		if s == "left" {
			dir = -1
		}
		cur := currentCType(p.rules[p.ri].rule)
		idx := 0
		for i, t := range cTypes {
			if t == cur {
				idx = i
			}
		}
		setCType(&p.rules[p.ri].rule, cTypes[(idx+dir+len(cTypes))%len(cTypes)])
		p.rules[p.ri].edited = true
		p.mutate()
	case field.kind == "perms" && s == "left":
		p.permCursor = (p.permCursor + len(permsAll) - 1) % len(permsAll)
	case field.kind == "perms" && s == "right":
		p.permCursor = (p.permCursor + 1) % len(permsAll)
	case field.kind == "perms" && s == " ":
		togglePerm(&p.rules[p.ri].rule, permsAll[p.permCursor%len(permsAll)])
		p.rules[p.ri].edited = true
		p.mutate()
	case field.kind == "match" && (s == "enter" || s == "right"):
		// Match is a multi-value list, so it gets its own sub-editor, like the
		// dashboard's.
		p.matchSel = 0
		p.view = viewMatch
	case field.kind == "priority" && (s == "right" || s == "left"):
		d := 1
		if s == "left" {
			d = -1
		}
		p.rules[p.ri].rule.Priority = max(0, p.rules[p.ri].rule.Priority+d)
		p.rules[p.ri].edited = true
		p.mutate()
	case field.kind == "text" && s == "enter":
		p.beginEdit(p.rules[p.ri].rule.Description)
	case s == "s":
		return p.save()
	}
	_ = k
	return nil
}

// ── the two bound editors ──────────────────────────────────────────────────

func (p *Policies) layerPanel() tui.Panel {
	switch p.view {
	case viewDLP:
		return p.dlpPanel
	case viewRate:
		return p.ratePanel
	}
	return nil
}

// storeLayer puts back whatever Update returned. Both children return
// themselves today; taking the answer rather than assuming it means a child
// that starts replacing itself does not silently stop receiving keys.
func (p *Policies) storeLayer(next tui.Panel) {
	switch v := next.(type) {
	case *DLP:
		p.dlpPanel = v
	case *RateLimit:
		p.ratePanel = v
	}
}

// childCtx is the box a bound editor draws in: this panel's, minus the two
// lines of policy/variant header above it.
func (p *Policies) childCtx() tui.PanelContext {
	return tui.PanelContext{
		Deps:    p.deps,
		Cols:    p.cols,
		Rows:    max(1, p.rows-polLayerHeader),
		Focused: p.focused,
		Gen:     p.gen,
	}
}

func (p *Policies) childCapturing() bool {
	switch p.view {
	case viewDLP:
		return p.dlpPanel.CapturingKeys()
	case viewRate:
		return p.ratePanel.CapturingKeys()
	}
	return false
}

func (p *Policies) layerWantsLeft() bool {
	if p.view == viewRate {
		return p.ratePanel.WantsLeft()
	}
	return false
}

func (p *Policies) syncToLayer() {
	switch p.view {
	case viewDLP:
		p.dlpPanel.SetBound(p.sec, p.available, p.dirty)
	case viewRate:
		p.ratePanel.SetBound(p.sec, p.dirty)
	}
}

// syncFromLayer takes the child's edit back. Each child owns ONE part of the
// block, so only that part is copied: the DLP editor must not write back a rate
// limit it was handed and never touched.
func (p *Policies) syncFromLayer() {
	switch p.view {
	case viewDLP:
		p.sec.DLP = p.dlpPanel.Bound().DLP
	case viewRate:
		p.sec.RateLimit = p.ratePanel.Bound().RateLimit
	}
}

// layersEqual is what decides a keystroke was an EDIT. Comparing the block
// rather than trusting the child's own dirty flag keeps one definition of
// unsaved on this panel, and means a key that moved a cursor is not a change.
func layersEqual(a, b api.SecurityLayers) bool {
	if a.RateLimit != b.RateLimit || a.DLP.Mode != b.DLP.Mode {
		return false
	}
	if !sameStrings(a.DLP.Patterns, b.DLP.Patterns) {
		return false
	}
	if len(a.DLP.Custom) != len(b.DLP.Custom) {
		return false
	}
	for i := range a.DLP.Custom {
		if a.DLP.Custom[i] != b.DLP.Custom[i] {
			return false
		}
	}
	return true
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (p *Policies) flipEffect(i int) {
	next := "ALLOW"
	if p.rules[i].rule.Effect == "ALLOW" {
		next = "DENY"
	}
	migrateEffect(&p.rules[i].rule, next)
	p.rules[i].edited = true
	p.mutate()
}

func (p *Policies) setItems(items []string) {
	setMatchItems(&p.rules[p.ri].rule, items)
	p.rules[p.ri].edited = true
	p.mutate()
}

func (p *Policies) beginEdit(value string) {
	p.editing = true
	p.input.SetValue(value)
	p.input.CursorEnd()
	p.input.Focus()
}

// editingKey drives the inline text editor: the Description field in the rule
// view, and one value in the match list. esc abandons the edit and leaves the
// value as it was — the shell gives a capturing panel every key, so there has
// to be a way out that does not write anything.
func (p *Policies) editingKey(k tea.KeyMsg) tea.Cmd {
	if k.String() == "esc" {
		p.editing = false
		p.input.Blur()
		return nil
	}
	if k.String() != "enter" {
		var cmd tea.Cmd
		p.input, cmd = p.input.Update(k)
		return cmd
	}
	v := p.input.Value()
	p.editing = false
	p.input.Blur()
	if p.ri >= len(p.rules) {
		return nil
	}
	if p.view == viewMatch {
		items := matchItems(p.rules[p.ri].rule)
		val := strings.TrimSpace(v)
		next := append([]string(nil), items...)
		if p.matchSel < len(next) {
			next[p.matchSel] = val
		}
		// An emptied value is a removal: it is how the editor deletes the blank
		// row `a` just added when the user changes their mind.
		if val == "" && p.matchSel < len(next) {
			next = append(next[:p.matchSel:p.matchSel], next[p.matchSel+1:]...)
		}
		p.setItems(next)
		p.matchSel = max(0, min(p.matchSel, len(next)-1))
		return nil
	}
	p.rules[p.ri].rule.Description = v
	p.rules[p.ri].edited = true
	p.mutate()
	return nil
}

func (p *Policies) creatingKey(k tea.KeyMsg) tea.Cmd {
	if k.String() == "esc" {
		p.creating = false
		p.input.Blur()
		return nil
	}
	if k.String() != "enter" {
		var cmd tea.Cmd
		p.input, cmd = p.input.Update(k)
		return cmd
	}
	name := strings.TrimSpace(p.input.Value())
	p.creating = false
	p.input.Blur()
	if name == "" {
		return nil
	}
	p.status = "Creating…"
	// Keep the empty state hidden until the new policy shows up in the list, or
	// the panel says "No policies yet" in the same breath as creating one.
	p.busyCreate = true
	body := api.PolicySet{ID: "policy-" + itoa(int(time.Now().UnixMilli())), Name: name, Mode: api.ModeDenylist}
	t := p.tag()
	return func() tea.Msg {
		if _, err := p.deps.API.Policies.Create(bg(), body); err != nil {
			return polActionMsg{genTag: t, status: "✗ " + errText(err)}
		}
		return polActionMsg{
			genTag:      t,
			status:      `✓ created "` + name + `" - open it and press n to add rules`,
			refreshList: true,
		}
	}
}

func (p *Policies) save() tea.Cmd {
	body, ok := p.saveBody()
	if !ok {
		return nil
	}
	p.status = "Saving…"
	id := body.ID
	t := p.tag()
	return func() tea.Msg {
		res, err := p.deps.API.Policies.Update(bg(), id, body)
		return polSavedMsg{genTag: t, rules: res.Rules, err: err}
	}
}

// saveBody is the document that would be sent, and the refusals that stop it.
//
// It is separate from save() so the refusals can be tested without a server:
// what this panel must never do is write a policy back NARROWER than it read
// it, and every check below is one way that could happen.
func (p *Policies) saveBody() (api.PolicySet, bool) {
	if !p.haveDetail {
		return api.PolicySet{}, false
	}
	sel, ok := p.selected()
	if !ok {
		return api.PolicySet{}, false
	}
	p.fold()

	// Every variant is checked, not just the one on screen. A blanket rule in
	// the variant somebody edited five minutes ago is still a blanket rule the
	// moment this is saved, and finding out about it from the tab you are not
	// looking at is better than finding out from a machine that stopped denying.
	vars := make([]api.PolicyVariant, 0, len(p.variants))
	for vi, v := range p.variants {
		where := ""
		if len(p.variants) > 1 {
			where = " in " + v.name
		}
		// A policy this version could not fully read must not be written back.
		// The rules that failed to decode are not in the draft, so saving would
		// delete them from the policy while the dashboard still showed them as
		// active.
		if v.unreadable > 0 {
			p.status = "✗ " + itoa(v.unreadable) + " rule(s)" + where + " cannot be read by this version — saving would delete them; edit ~/.solongate/policy.json directly"
			return api.PolicySet{}, false
		}
		for i, d := range v.rules {
			if isBlanketRule(d.rule) {
				p.status = "✗ rule " + itoa(i+1) + where + " matches EVERYTHING — pick a Constraint + Match value, or narrow Permissions"
				return api.PolicySet{}, false
			}
		}
		raws := make([]json.RawMessage, 0, len(v.rules))
		for _, d := range v.rules {
			b, err := d.marshal()
			if err != nil {
				p.status = "✗ could not encode rule: " + errText(err)
				return api.PolicySet{}, false
			}
			raws = append(raws, b)
		}
		sec := v.sec
		vars = append(vars, api.PolicyVariant{
			ID:       polOrID(v.id, vi),
			Name:     v.name,
			Rules:    api.Rules{Raw: raws},
			Security: &sec,
		})
	}

	first := vars[0]
	return api.PolicySet{
		ID:          sel.ID,
		Name:        p.detail.Name,
		Description: p.detail.Description,
		Mode:        p.mode,
		Agents:      p.detail.Agents,
		Variants:    vars,
		// The top level carries the FIRST variant's rules and layers, and both
		// are mirrors rather than a second source of truth. Three readers in
		// the field take only $.rules, so a document whose rules live only
		// inside the bundle compiles to an empty rule set — which for a
		// denylist denies nothing. The server keeps this mirror true on every
		// write; writing it here as well means the document is already
		// consistent before it is sent.
		DefaultVariant: first.ID,
		Rules:          first.Rules,
		Security:       first.Security,
	}, true
}

// polOrID keeps a variant's id stable and gives an unnamed one the same id the
// dashboard would. A grant pins this string: an id that changed on save would
// move every developer pinned to it onto the default.
func polOrID(id string, i int) string {
	if id != "" {
		return id
	}
	return polVariantID(i)
}

func (p *Policies) discard() {
	if p.haveDetail {
		p.adoptPolicy(p.detail.PolicySet)
	}
	p.dirty = false
	p.status = "discarded"
}

// ── render ─────────────────────────────────────────────────────────────────

func (p *Policies) View(ctx tui.PanelContext) string {
	p.apply(ctx)
	switch p.view {
	case viewList:
		return clip(p.viewListBody(), p.cols, p.rows)
	case viewPolicy:
		return clip(p.viewPolicyBody(), p.cols, p.rows)
	case viewRules:
		return clip(p.viewRulesBody(), p.cols, p.rows)
	case viewMatch:
		return clip(p.viewMatchBody(), p.cols, p.rows)
	case viewDLP, viewRate:
		return clip(p.viewLayerBody(), p.cols, p.rows)
	default:
		return clip(p.viewRuleBody(), p.cols, p.rows)
	}
}

func (p *Policies) viewListBody() string {
	empty := !p.listLoading && p.listErr == nil && len(p.policies) == 0 && !p.creating && !p.busyCreate
	if p.listLoading && p.policies == nil {
		return dataView(true, nil, false, "", "")
	}
	if p.listErr != nil {
		return dataView(false, p.listErr, false, "", "")
	}
	if empty {
		return dataView(false, nil, true, "No policies yet — press n to create one.", "")
	}

	head := 3
	if p.status != "" {
		head++
	}
	if p.creating {
		head++
	}
	budget := max(3, p.rows-head)

	rows := make([]string, 0, len(p.policies))
	for i, pol := range p.policies {
		l := newLine(false)
		cursor, st := "  ", stPlain
		if i == p.pi {
			cursor, st = "▸ ", stAccentB
		}
		l.put(cursor+pad(truncate(pol.Name, 26), 27), st)
		l.put(pad(string(pol.Mode), 10)+" "+itoa(len(pol.Rules.Items)+pol.Rules.Unreadable)+" rules", stDim)
		if pol.ID == p.activeID && p.activeID != "" {
			l.put("  ● ACTIVE", stOKB)
		}
		rows = append(rows, l.String())
	}
	win, above, below := window(rows, p.pi, budget)

	var out []string
	al := newLine(false)
	al.put("active: ", stDim)
	switch {
	case p.activeLoad && p.activeID == "":
		al.put("…", stDim)
	case p.activeID != "":
		name := p.activeID
		for _, pol := range p.policies {
			if pol.ID == p.activeID {
				name = pol.Name
			}
		}
		al.put("● "+truncate(name, 28), stOKB)
		if p.activeBy != "" {
			al.put(" ("+p.activeBy+")", stDim)
		}
	default:
		al.put("○ NONE — nothing enforced, grants refused", stBadB)
	}
	out = append(out, al.String())

	hint := "press → to browse"
	if p.focused {
		hint = "↑↓ select · enter open · n new · a activate · x deactivate · d delete · ^R refresh" + scrollTag(above, below)
	}
	out = append(out, stDim.Render(hint))

	if p.creating {
		out = append(out, stWarn.Render("new policy name: ")+p.input.View())
	}
	out = append(out, "")
	out = append(out, win...)
	if p.status != "" {
		out = append(out, statusLine(p.status))
	}
	return joinLines(out)
}

func (p *Policies) dirtyTag(l *lineBuf) {
	if p.dirty {
		l.put("  ● unsaved (s save · x discard)", stWarn)
	}
}

// polLayerHeader is how many lines the policy/variant header takes above a
// bound editor. The child is given the rest, and it clips itself to exactly
// that: a header that grew without this number growing would push the child's
// last line past the frame. See the frame-height rule in the package comment.
const polLayerHeader = 3

// variantTabs is the row the dashboard draws as tabs. The one in force is lit
// and boxed; the rest are dim, and a policy with a single variant draws nothing
// at all, because one tab is not a choice.
func (p *Policies) variantTabs() string {
	if len(p.variants) < 2 {
		return ""
	}
	l := newLine(false)
	for i, v := range p.variants {
		if i == p.vi {
			l.put("[ "+truncate(v.name, 18)+" ]", stAccentB)
		} else {
			l.put("  "+truncate(v.name, 18)+"  ", stDim)
		}
	}
	l.put("   tab switches", stDim)
	return l.String()
}

// layerSummary is the right-hand side of a layer row: what it is set to, in the
// words the dashboard's fold headers use.
func (p *Policies) layerSummary(layer int) (string, lipgloss.Style) {
	switch layer {
	case layerRules:
		n := len(p.rules)
		off := 0
		for _, d := range p.rules {
			if !d.rule.Enabled {
				off++
			}
		}
		text := itoa(n) + " rules"
		if n == 1 {
			text = "1 rule"
		}
		if off > 0 {
			text += " · " + itoa(off) + " off"
		}
		if n == 0 {
			return "no rules yet", stDim
		}
		return text, stPlain
	case layerDLP:
		d := p.sec.DLP
		if d.Mode == api.LayerOff || d.Mode == "" {
			return "off · nothing scanned", stDim
		}
		text := string(d.Mode) + " · " + itoa(len(d.Patterns)+len(d.Custom)) + " detectors"
		return text, modeStyle(string(d.Mode))
	default:
		rl := p.sec.RateLimit
		if rl.Mode == api.LayerOff || rl.Mode == "" {
			return "off · no limit", stDim
		}
		return string(rl.Mode) + " · " + offOr(rl.PerMinute) + "/min · " +
			offOr(rl.PerHour) + "/hr · " + offOr(rl.PerDay) + "/day", modeStyle(string(rl.Mode))
	}
}

var polLayerNames = [layerCount]string{"Rules", "Secret detectors", "Rate limit"}

// A second, dimmer line used to sit under each layer explaining what it was for —
// "what is allowed and what is denied" under Rules, and so on. It doubled the height
// of the card to restate the three names next to it, and it never changed, so after
// the first read it was three lines of furniture between the reader and the numbers
// they came for.

// viewPolicyBody is one policy: its variants along the top, its three layers
// under them. It is the dashboard's policy card, which is always open and whose
// layers are the things that fold.
func (p *Policies) viewPolicyBody() string {
	if p.detailLoading && !p.haveDetail {
		return dataView(true, nil, false, "", "")
	}
	if p.detailErr != nil {
		return dataView(false, p.detailErr, false, "", "")
	}

	var out []string
	name := ""
	if sel, ok := p.selected(); ok {
		name = sel.Name
	}
	h := newLine(false)
	h.put(truncate(name, 30), stAccentB)
	h.put("  mode: ", stDim)
	modeSt := stPlain
	if p.mode == api.ModeWhitelist {
		modeSt = stWarn
	}
	h.put(string(p.mode), modeSt)
	if p.detailID != "" && p.detailID == p.activeID {
		h.put("  ● ACTIVE", stOKB)
	}
	p.dirtyTag(h)
	out = append(out, h.String())

	hint := "press → to open"
	if p.focused {
		hint = "↑↓ layer · enter open · tab variant · v new variant · V remove · m mode · s save · ← back"
	}
	out = append(out, stDim.Render(truncate(hint, p.cols)))

	if tabs := p.variantTabs(); tabs != "" {
		out = append(out, tabs)
	} else {
		out = append(out, stDim.Render("one variant · v adds a second, for a machine that needs different rules"))
	}
	out = append(out, "")

	for i := 0; i < layerCount; i++ {
		sel := p.focused && i == p.li
		l := newLine(sel)
		cursor, cst := "  ", stDim
		if sel {
			cursor, cst = "▸ ", stAccent
		}
		l.put(cursor, cst.Bold(sel))
		l.put(pad(polLayerNames[i], 18), stBold)
		text, st := p.layerSummary(i)
		l.put(pad(truncate(text, max(10, p.cols-42)), max(10, p.cols-42)), st)
		out = append(out, l.String())
	}

	if p.unreadable > 0 {
		// Never silently show fewer rules than the policy has.
		out = append(out, stBad.Render("⚠ "+itoa(p.unreadable)+" rule(s) here cannot be read by this version — edit ~/.solongate/policy.json directly"))
	}
	if p.status != "" {
		out = append(out, statusLine(p.status))
	}
	return joinLines(out)
}

// viewLayerBody is a bound editor with this panel's header above it, so the
// policy and the variant being edited are never off screen.
func (p *Policies) viewLayerBody() string {
	child := p.layerPanel()
	if child == nil {
		return ""
	}
	p.syncToLayer()

	var out []string
	name := ""
	if sel, ok := p.selected(); ok {
		name = sel.Name
	}
	h := newLine(false)
	h.put(truncate(name, 24), stAccentB)
	h.put(" · ", stDim)
	which := polLayerNames[layerDLP]
	if p.view == viewRate {
		which = polLayerNames[layerRate]
	}
	h.put(which, stBold)
	if len(p.variants) > 1 && p.vi < len(p.variants) {
		h.put("  ["+truncate(p.variants[p.vi].name, 18)+"]", stAccent)
	}
	// No unsaved tag here: the editor below draws its own, and two of them on
	// one screen reads as two different unsaved things.
	out = append(out, h.String())
	out = append(out, "")
	out = append(out, child.View(p.childCtx()))
	return joinLines(out)
}

func (p *Policies) viewRulesBody() string {
	if p.detailLoading && !p.haveDetail {
		return dataView(true, nil, false, "", "")
	}
	if p.detailErr != nil {
		return dataView(false, p.detailErr, false, "", "")
	}

	statusLines := 0
	if p.status != "" {
		statusLines = len(strings.Split(p.status, "\n"))
	}
	head := 4 + statusLines
	budget := max(3, p.rows-head)

	rows := make([]string, 0, len(p.rules))
	for i, d := range p.rules {
		r := d.rule
		l := newLine(false)
		cur := ""
		if i == p.ri {
			cur = "▸"
		}
		l.put(fit(cur, 2)+"  ", stAccentB)
		on, onStyle := "○", stDim
		if r.Enabled {
			on, onStyle = "●", stOK
		}
		l.put(fit(on, 2)+"  ", onStyle)
		effStyle := stBad
		if r.Effect == "ALLOW" {
			effStyle = stOK
		}
		if !r.Enabled {
			effStyle = stDim
		}
		l.put(fit(r.Effect, 7)+"  ", effStyle)
		l.put(fit(itoa(r.Priority), 4)+"  ", stDim)
		descStyle := stPlain
		if !r.Enabled {
			descStyle = stDim
		}
		l.put(fit(truncate(orDash(r.Description), 38), 38)+"  ", descStyle)
		l.put(fit(orDash(ruleSummary(r)), 14)+"  ", stDim)
		rows = append(rows, l.String())
	}
	win, above, below := window(rows, p.ri, budget)

	var out []string
	name := ""
	if sel, ok := p.selected(); ok {
		name = sel.Name
	}
	t := newLine(false)
	t.put(truncate(name, 28), stAccentB)
	t.put("  mode: ", stDim)
	modeStyleSel := stPlain
	if p.mode == api.ModeWhitelist {
		modeStyleSel = stWarn
	}
	t.put(string(p.mode), modeStyleSel)
	t.put("  "+itoa(len(p.rules))+" rules", stDim)
	if p.unreadable > 0 {
		// Never silently show fewer rules than the policy has.
		t.put("  ⚠ "+itoa(p.unreadable)+" unreadable", stBad)
	}
	p.dirtyTag(t)
	out = append(out, t.String())

	out = append(out, stDim.Render("↑↓ · enter edit · space on/off · e effect · n new · d del · m mode · s save · ← back"+scrollTag(above, below)))
	out = append(out, "")
	out = append(out, stDim.Render(fit("", 2)+"  "+fit("ON", 2)+"  "+fit("EFFECT", 7)+"  "+fit("PRIO", 4)+"  "+fit("DESCRIPTION", 38)+"  "+fit("CONSTRAINTS", 14)+"  "))
	out = append(out, win...)
	if len(p.rules) == 0 {
		out = append(out, stDim.Render("(no rules)"))
	}
	if p.status != "" {
		out = append(out, statusLine(p.status))
	}
	return joinLines(out)
}

func (p *Policies) viewMatchBody() string {
	var items []string
	t := cNone
	effect := ""
	if p.ri < len(p.rules) {
		items = matchItems(p.rules[p.ri].rule)
		t = currentCType(p.rules[p.ri].rule)
		effect = p.rules[p.ri].rule.Effect
	}

	var out []string
	h := newLine(false)
	h.put("Match values ", stAccentB)
	if effect != "" {
		h.put(effect+" · "+string(t), stDim)
	}
	p.dirtyTag(h)
	out = append(out, h.String())
	out = append(out, stDim.Render("↑↓ select · enter/e edit · a add · [ / ] wildcard L/R · d remove · s save · ← back"))
	out = append(out, "")

	rows := make([]string, 0, len(items))
	for i, it := range items {
		sel := i == p.matchSel
		l := newLine(false)
		if sel {
			l.put("▸ ", stAccent)
		} else {
			l.put("  ", stPlain)
		}
		if sel && p.editing {
			v := p.input.Value()
			txt, st := starLeft(strings.HasPrefix(v, "*"))
			l.put(txt, st)
			l.put(p.input.View(), stPlain)
			txt, st = starRight(len(v) > 0 && strings.HasSuffix(v, "*"))
			l.put(txt, st)
			rows = append(rows, l.String())
			continue
		}
		txt, st := starLeft(strings.HasPrefix(it, "*"))
		l.put(txt, st)
		if it == "" {
			l.put("(empty)", stDim)
		} else {
			l.put(it, stPlain)
		}
		txt, st = starRight(len(it) > 0 && strings.HasSuffix(it, "*"))
		l.put(txt, st)
		rows = append(rows, l.String())
	}
	if len(items) == 0 {
		out = append(out, stDim.Render("(no values — press a to add one)"))
	} else {
		// The Ink version drew every value and relied on the outer box to clip.
		// This windows instead, so a long value list scrolls rather than pushing
		// the help line and the status out of the frame.
		statusRows := 0
		if p.status != "" {
			statusRows = 1
		}
		budget := max(1, p.rows-4-statusRows)
		win, _, _ := window(rows, p.matchSel, budget)
		out = append(out, win...)
	}
	out = append(out, stDim.Render("  * = wildcard (any run of chars). Type it directly (rm*) or toggle with [ / ]. Green ✱ = active · left & right shown as you type. Multiple values = OR (any one matches)."))
	if p.status != "" {
		out = append(out, statusLine(p.status))
	}
	return joinLines(out)
}

func (p *Policies) viewRuleBody() string {
	var out []string
	var rule api.PolicyRule
	have := p.ri < len(p.rules)
	if have {
		rule = p.rules[p.ri].rule
	}

	h := newLine(false)
	h.put("Rule ", stAccentB)
	h.put(rule.ID, stDim)
	p.dirtyTag(h)
	out = append(out, h.String())
	out = append(out, stDim.Render("↑↓ field · enter edit/open · space toggle · ←→ move/pick · s save · ← back"))
	out = append(out, "")

	for i, f := range polFields {
		active := i == p.fi
		l := newLine(false)
		labelStyle := stPlain
		prefix := "  "
		if active {
			labelStyle, prefix = stAccent, "▸ "
		}
		l.put(prefix+pad(f.label, 13), labelStyle)

		switch {
		case f.kind == "perms" && have:
			// Four chips: green on, red off. ←→ moves the cursor, space toggles.
			for pi, perm := range permsAll {
				st := stBad
				if containsString(permListOf(rule), perm) {
					st = stOK
				}
				if active && pi == p.permCursor%len(permsAll) {
					st = st.Reverse(true)
				}
				text := perm
				if pi < len(permsAll)-1 {
					text += "  "
				}
				l.put(text, st)
			}
		case f.kind == "match" && have:
			items := matchItems(rule)
			preview := strings.Join(items, ", ")
			if preview == "" {
				l.put("—", stDim)
				l.put("   (enter: add values)", stDim)
			} else {
				l.put(preview, stPlain)
				plural := ""
				if len(items) > 1 {
					plural = "s"
				}
				l.put("   ("+itoa(len(items))+" value"+plural+" · enter: edit)", stDim)
			}
		case active && p.editing && f.kind == "text":
			l.put(p.input.View(), stPlain)
		default:
			val := ""
			if have {
				val = p.fieldValue(rule, f.kind)
			}
			switch {
			case val == "":
				l.put("—", stDim)
			case f.kind == "effect" && val == "ALLOW":
				l.put(val, stOK)
			case f.kind == "effect":
				l.put(val, stBad)
			default:
				l.put(val, stPlain)
			}
		}
		out = append(out, l.String())
	}
	if p.status != "" {
		out = append(out, statusLine(p.status))
	}
	return joinLines(out)
}

func (p *Policies) fieldValue(r api.PolicyRule, kind string) string {
	switch kind {
	case "effect":
		return r.Effect
	case "ctype":
		return string(currentCType(r))
	case "perms":
		return permDisplay(r)
	case "priority":
		return itoa(r.Priority)
	case "text":
		return r.Description
	case "match":
		return cValue(r)
	}
	return ""
}
