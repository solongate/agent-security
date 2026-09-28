package panels

import (
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/tui"
)

// No init(): DLP is not a section any more. See the note on NewRateLimit — a
// policy carries its own, per variant, and NewDLP is mounted there.

// The DLP panel, ported from tui/panels/Dlp.tsx. Draft-only edits, saved with
// `s`, never auto-saved.
//
// ONE scrollable cursor runs over two sections so nothing is ever clipped: the
// built-in secret patterns (space toggles each) and the custom patterns
// (a add · d remove).
//
// Custom patterns take the SAME GLOB syntax as the built-in
// patterns — `*` matches any run of characters — not regular expressions. The
// field is named `re` on the wire, which is exactly why the prompts say glob
// every time they are shown.
//
// The add editor is pinned at the TOP so what is being typed is always visible.
// Self-protection lives in Settings, not here.

var dlpModes = []api.LayerMode{api.LayerOff, api.LayerDetect, api.LayerBlock}

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
		data api.SecurityLayersResponse
		err  error
	}
	dlpSavedMsg struct {
		genTag
		layers api.SecurityLayers
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

	server  api.SecurityLayersResponse
	haveSrv bool
	loading bool
	loadErr error

	dlp       api.SecurityLayers // the draft; only the dlp part is edited
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
func (p *DLP) SetBound(sec api.SecurityLayers, available []string, dirty bool) {
	p.bound = true
	p.loading = false
	p.available = available
	p.dirty = dirty
	p.adoptServer(sec)
}

// Bound reads the draft back out.
func (p *DLP) Bound() api.SecurityLayers { return p.dlp }

// CapturingKeys is true while the add/edit prompt is open, so the shell leaves
// every key — including q and esc — to the prompt.
func (p *DLP) CapturingKeys() bool { return p.adding != dlpAddNone }

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
		r, err := p.deps.API.Settings.GetSecurityLayers(bg())
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
func (p *DLP) adoptServer(l api.SecurityLayers) {
	p.dlp = l
	p.dlp.DLP.Patterns = append([]string(nil), l.DLP.Patterns...)
	p.dlp.DLP.Custom = append([]api.CustomPattern(nil), l.DLP.Custom...)
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

func (p *DLP) mutated() {
	p.dirty = true
	p.status = ""
}

func (p *DLP) key(k tea.KeyMsg) tea.Cmd {
	if !p.hasDraft {
		return nil
	}
	cur, hasCur := p.current()
	selC := p.selClamped()

	switch k.String() {
	case "ctrl+r":
		if p.bound {
			return nil
		}
		p.status = "⟳ refreshed " + time.Now().Format("15:04:05")
		return p.load()

	case "up":
		p.sel = max(0, selC-1)

	case "down":
		p.sel = min(len(p.entries())-1, selC+1)

	case "m":
		i := 0
		for j, m := range dlpModes {
			if m == p.dlp.DLP.Mode {
				i = j
			}
		}
		p.dlp.DLP.Mode = dlpModes[(i+1)%len(dlpModes)]
		p.mutated()

	case " ":
		if hasCur && cur.kind == dlpBuiltin {
			p.dlp.DLP.Patterns = toggleString(p.dlp.DLP.Patterns, cur.name)
			p.mutated()
		}

	case "a":
		p.newName = ""
		p.editIdx = -1
		p.beginInput(dlpAddName, "")

	case "d":
		if !hasCur {
			return nil
		}
		switch cur.kind {
		case dlpCustom:
			p.dlp.DLP.Custom = append(p.dlp.DLP.Custom[:cur.i:cur.i], p.dlp.DLP.Custom[cur.i+1:]...)
			p.mutated()
			p.sel = max(0, selC-1)
		}

	case "e", "enter":
		// Edit the selected entry in place.
		if !hasCur {
			return nil
		}
		switch cur.kind {
		case dlpCustom:
			if cur.i < len(p.dlp.DLP.Custom) {
				p.editIdx = cur.i
				p.newName = p.dlp.DLP.Custom[cur.i].Name
				p.beginInput(dlpAddRe, p.dlp.DLP.Custom[cur.i].Re)
			}
		}

	case "s":
		if p.bound {
			// The owner saves. Reaching the settings endpoint from here would
			// write a project-wide row the policy does not read.
			return nil
		}
		return p.save()

	case "x":
		if p.bound {
			return nil
		}
		p.discard()
	}
	return nil
}

func (p *DLP) beginInput(mode dlpAdding, value string) {
	p.adding = mode
	p.input.SetValue(value)
	p.input.CursorEnd()
	p.input.Focus()
}

func (p *DLP) endInput() {
	p.adding = dlpAddNone
	p.editIdx = -1
	p.input.Blur()
	p.input.SetValue("")
}

// editKey drives the pinned prompt. Enter on an empty value cancels, as it did
// in the Ink version; esc cancels too, which it could not there. The shell hands
// a capturing panel every key, so without esc the only way out of this prompt
// would be to submit it.
func (p *DLP) editKey(k tea.KeyMsg) tea.Cmd {
	if k.String() == "esc" {
		p.endInput()
		return nil
	}
	if k.String() != "enter" {
		var cmd tea.Cmd
		p.input, cmd = p.input.Update(k)
		return cmd
	}
	v := strings.TrimSpace(p.input.Value())
	switch p.adding {
	case dlpAddName:
		if v == "" {
			p.endInput()
			return nil
		}
		p.newName = v
		p.beginInput(dlpAddRe, "")
		return nil

	default: // the pattern itself
		if v != "" {
			if p.editIdx >= 0 && p.editIdx < len(p.dlp.DLP.Custom) {
				p.dlp.DLP.Custom[p.editIdx] = api.CustomPattern{Name: p.newName, Re: v}
			} else {
				p.dlp.DLP.Custom = append(p.dlp.DLP.Custom, api.CustomPattern{Name: p.newName, Re: v})
			}
			p.mutated()
		}
		p.endInput()
		return nil
	}
}

func (p *DLP) save() tea.Cmd {
	if !p.hasDraft || !p.haveSrv {
		return nil
	}
	p.status = "Saving…"
	next := p.server.Layers
	next.DLP = p.dlp.DLP
	t := p.tag()
	return func() tea.Msg {
		got, err := p.deps.API.Settings.SetSecurityLayers(bg(), next)
		return dlpSavedMsg{genTag: t, layers: got, err: err}
	}
}

func (p *DLP) discard() {
	if !p.haveSrv {
		return
	}
	p.adoptServer(p.server.Layers)
	p.dirty = false
	p.status = "discarded"
}

// ── render ─────────────────────────────────────────────────────────────────

// wcParts splits a glob into its leading/trailing wildcard state and its core,
// so a row can show whether the `*` on either side is ON. It is the same
// clarity the policy editor's Match field gives.
func wcParts(pat string) (left bool, core string, right bool) {
	s := pat
	left = strings.HasPrefix(s, "*")
	right = len(s) > 1 && strings.HasSuffix(s, "*")
	core = s
	if left {
		core = strings.TrimLeft(core, "*")
	}
	if right {
		core = strings.TrimRight(core, "*")
	}
	if core == "" {
		core = s
	}
	return left, core, right
}

func starLeft(on bool) (string, lipgloss.Style) {
	if on {
		return "✱ ", stOK
	}
	return "· ", stDim
}

func starRight(on bool) (string, lipgloss.Style) {
	if on {
		return " ✱", stOK
	}
	return " ·", stDim
}

// dlpLine is one rendered row plus the entry index it selects (-1 for headers
// and help notes, which the cursor skips).
type dlpLine struct {
	text  string
	entry int
}

func (p *DLP) View(ctx tui.PanelContext) string {
	p.apply(ctx)
	if !p.hasDraft {
		return clip(dataView(p.loading, p.loadErr, false, "", ""), p.cols, p.rows)
	}

	enabled := map[string]bool{}
	for _, s := range p.dlp.DLP.Patterns {
		enabled[s] = true
	}
	selC := p.selClamped()

	var lines []dlpLine
	header := func(label, extra string) {
		l := newLine(false)
		l.put(label, stAccentB)
		if extra != "" {
			l.put("  "+extra, stDim)
		}
		lines = append(lines, dlpLine{l.String(), -1})
	}
	note := func(text string) { lines = append(lines, dlpLine{stDim.Render(text), -1}) }

	ei := 0
	header("built-in secret patterns", "space toggles on/off")
	for _, name := range p.available {
		on := enabled[name]
		isCur := p.focused && ei == selC
		l := newLine(isCur)
		cursorStyle := stDim
		cursor := "  "
		if isCur {
			cursorStyle, cursor = stAccent, "▸ "
		}
		l.put(cursor, cursorStyle.Bold(isCur))
		if on {
			l.put("● ", stOK.Bold(isCur))
			l.put(name, stPlain.Bold(isCur))
		} else {
			l.put("○ ", stDim.Bold(isCur))
			l.put(name, stDim.Bold(isCur))
		}
		lines = append(lines, dlpLine{l.String(), ei})
		ei++
	}

	header("custom patterns", "a add · d remove")
	note("  * = any chars · green ✱ on a side = wildcard active there · e.g.  sk-*   *PRIVATE KEY*")
	if len(p.dlp.DLP.Custom) == 0 {
		note("  (none — press a to add a name + pattern)")
	}
	for _, c := range p.dlp.DLP.Custom {
		isCur := p.focused && ei == selC
		left, core, right := wcParts(c.Re)
		l := newLine(isCur)
		cursorStyle, cursor := stDim, "  "
		if isCur {
			cursorStyle, cursor = stAccent, "▸ "
		}
		l.put(cursor, cursorStyle.Bold(isCur))
		l.put(c.Name, stAccent.Bold(isCur))
		l.put("  ", stDim)
		txt, st := starLeft(left)
		l.put(txt, st.Bold(isCur))
		l.put(truncate(core, max(6, p.cols-len([]rune(c.Name))-14)), stDim.Bold(isCur))
		txt, st = starRight(right)
		l.put(txt, st.Bold(isCur))
		lines = append(lines, dlpLine{l.String(), ei})
		ei++
	}

	// ── header block (always visible) + windowed list ──────────────────────
	editRows := 0
	if p.adding != dlpAddNone {
		editRows = 1
	}
	statusRows := 0
	if p.status != "" {
		statusRows = 1
	}
	headerRows := 2 + editRows + statusRows
	budget := max(3, p.rows-headerRows-1)

	selLine := 0
	for i, l := range lines {
		if l.entry == selC {
			selLine = i
			break
		}
	}
	texts := make([]string, len(lines))
	for i, l := range lines {
		texts[i] = l.text
	}
	win, above, below := window(texts, selLine, budget)

	var out []string

	modeLine := newLine(false)
	modeLine.put("mode: ", stPlain)
	modeLine.put(string(p.dlp.DLP.Mode), modeStyle(string(p.dlp.DLP.Mode)).Bold(true))
	switch p.dlp.DLP.Mode {
	case api.LayerOff:
		modeLine.put("  (scanning disabled)", stDim)
	case api.LayerDetect:
		modeLine.put("  (flag dlp:yes, redact output)", stDim)
	default:
		modeLine.put("  (deny + redact secrets)", stDim)
	}
	if p.dirty {
		modeLine.put("   ● unsaved (s save · x discard)", stWarn)
	}
	out = append(out, modeLine.String())

	hint := "press → to edit"
	if p.focused {
		tail := " · s save · ^R refresh"
		if p.bound {
			tail = " · s save · ← back"
		}
		hint = "↑↓ move · space on/off · m mode · a add · e/enter edit · d remove" +
			tail + scrollTag(above, below)
	}
	out = append(out, stDim.Render(hint))

	if p.adding != dlpAddNone {
		l := newLine(false)
		switch p.adding {
		case dlpAddName:
			l.put("new pattern name: ", stWarn)
		default:
			verb := "new"
			if p.editIdx >= 0 {
				verb = "edit"
			}
			l.put(verb+` pattern for "`+p.newName+`" (glob, * = any chars): `, stWarn)
		}
		v := p.input.Value()
		if p.adding != dlpAddName {
			txt, st := starLeft(strings.HasPrefix(v, "*"))
			l.put(txt, st)
		}
		l.put(p.input.View(), stPlain)
		if p.adding != dlpAddName {
			txt, st := starRight(len(v) > 1 && strings.HasSuffix(v, "*"))
			l.put(txt, st)
		}
		out = append(out, l.String())
	}

	out = append(out, "")
	out = append(out, win...)
	if p.status != "" {
		out = append(out, statusLine(p.status))
	}

	return clip(joinLines(out), p.cols, p.rows)
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

// toggleString adds or removes one value, keeping the order of the rest. The
// Ink version went through a Set, which preserves insertion order the same way;
// re-sorting here would rewrite a saved pattern list on every toggle.
func toggleString(list []string, v string) []string {
	out := make([]string, 0, len(list)+1)
	found := false
	for _, s := range list {
		if s == v {
			found = true
			continue
		}
		out = append(out, s)
	}
	if !found {
		out = append(out, v)
	}
	return out
}
