// SPDX-License-Identifier: Apache-2.0

package panels

// The Sandbox section: the closed boxes this machine has.
//
// WHY THIS IS A SECTION AND NOT A SETTING. Every other surface here tunes how a
// tool call is JUDGED, which rules match, what counts as a secret, how many
// calls a minute. All of it reads the strings in a call, and a string match is a
// game with no end: `rm game.c` is caught and `x=gam; y=e; rm "$x$y.c"` is not,
// nor is a script written to /tmp and run, nor a program the agent compiles that
// calls unlink itself.
//
// A box does not read strings. It gives the agent a new root, and outside it
// there is nothing to name. $HOME is not refused, it is not there.
//
// WHAT THE PROTECTED PATHS LIST IS, BY CONTRAST: files somebody remembered. It
// never contains ~/.ssh, a sibling customer's repository, or the credentials of
// a tool installed last month and forgotten. A box protects everything nobody
// thought to name.

import (
	"context"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/shared"
	"github.com/solongate/agent-security/packages/tui"
)

func init() {
	tui.Register(tui.SectionSandbox, func(d tui.Deps) tui.Panel { return NewSandbox(d) })
}

type sbMessage struct {
	text string
	bad  bool
}

type sbListMsg struct {
	gen   int
	boxes []shared.Sandbox
}

func (m sbListMsg) Generation() int { return m.gen }

type sbDoneMsg struct {
	gen  int
	text string
	err  error
}

func (m sbDoneMsg) Generation() int { return m.gen }

type Sandbox struct {
	deps tui.Deps

	cols, rows int
	focused    bool
	gen        int

	boxes  []shared.Sandbox
	loaded bool
	sel    int

	// editing is empty when the list has the keyboard. A box is created and
	// edited through the same prompt, because the only difference between the
	// two is whether an id already exists.
	editing bool
	editID  string
	input   textinput.Model

	// confirm holds the id awaiting a second press of d. Deleting is the only
	// destructive key here, so it does not happen on one keystroke.
	confirm string

	msg *sbMessage

	mech   string
	boxErr error
}

func NewSandbox(d tui.Deps) *Sandbox {
	in := textinput.New()
	in.Prompt = ""
	in.CharLimit = 4096
	// Both come from Deps rather than from the sandbox package: this module does
	// not import it, so a panel that draws a list does not drag go-landlock into
	// the TUI's dependency graph. See tui.Deps.Confinement.
	p := &Sandbox{deps: d, input: in, mech: d.Confinement.Mechanism, boxErr: d.Confinement.BoxUnavailable}
	return p
}

func (p *Sandbox) Init(ctx tui.PanelContext) tea.Cmd {
	p.apply(ctx)
	return p.load()
}

func (p *Sandbox) apply(ctx tui.PanelContext) {
	p.deps = ctx.Deps
	p.cols, p.rows = ctx.Cols, ctx.Rows
	p.focused = ctx.Focused
	p.gen = ctx.Gen
}

func (p *Sandbox) load() tea.Cmd {
	g := p.gen
	client := p.deps.API
	return func() tea.Msg {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		boxes, err := client.Settings.Sandboxes(c)
		if err != nil {
			return sbListMsg{gen: g}
		}
		return sbListMsg{gen: g, boxes: boxes}
	}
}

// CapturingKeys keeps the nav's keys out of the prompt: a path contains letters
// the nav treats as commands.
func (p *Sandbox) CapturingKeys() bool { return p.editing }

func (p *Sandbox) Update(msg tea.Msg, ctx tui.PanelContext) (tui.Panel, tea.Cmd) {
	p.apply(ctx)

	switch m := msg.(type) {
	case sbListMsg:
		if m.gen != p.gen {
			return p, nil
		}
		p.boxes, p.loaded = m.boxes, true
		if p.sel >= len(p.boxes) {
			p.sel = atLeastZero(len(p.boxes) - 1)
		}
		return p, nil

	case sbDoneMsg:
		if m.gen != p.gen {
			return p, nil
		}
		if m.err != nil {
			p.msg = &sbMessage{text: "✗ " + m.err.Error(), bad: true}
			return p, nil
		}
		p.msg = &sbMessage{text: "✓ " + m.text}
		return p, p.load()

	case tea.KeyMsg:
		return p, p.key(m)
	}
	return p, nil
}

func (p *Sandbox) key(k tea.KeyMsg) tea.Cmd {
	if p.editing {
		switch k.String() {
		case "esc":
			p.editing, p.editID = false, ""
			p.input.Blur()
			return nil
		case "enter":
			return p.submit()
		}
		var cmd tea.Cmd
		p.input, cmd = p.input.Update(k)
		return cmd
	}

	switch k.String() {
	case "up", "k":
		p.sel, p.confirm = atLeastZero(p.sel-1), ""
	case "down", "j":
		if p.sel < len(p.boxes)-1 {
			p.sel++
		}
		p.confirm = ""
	case "n":
		p.beginEdit("", "")
	case "enter", "e":
		if b, ok := p.cur(); ok {
			p.beginEdit(b.ID, b.Dir)
		}
	case "m":
		// The network toggle, written through the same setter the CLI reads, so
		// the row and the launch cannot disagree about it.
		if b, ok := p.cur(); ok {
			return p.save(b.ID, b.Dir, b.Label, !b.Network)
		}
	case "d":
		b, ok := p.cur()
		if !ok {
			return nil
		}
		if p.confirm != b.ID {
			p.confirm = b.ID
			p.msg = &sbMessage{text: "press d again to delete box " + b.ID + " · its id goes back in the pool"}
			return nil
		}
		p.confirm = ""
		return p.del(b.ID)
	}
	return nil
}

func (p *Sandbox) cur() (shared.Sandbox, bool) {
	if p.sel < 0 || p.sel >= len(p.boxes) {
		return shared.Sandbox{}, false
	}
	return p.boxes[p.sel], true
}

func (p *Sandbox) beginEdit(id, dir string) {
	p.editing, p.editID = true, id
	p.msg, p.confirm = nil, ""
	p.input.SetValue(dir)
	p.input.CursorEnd()
	p.input.Focus()
}

func (p *Sandbox) submit() tea.Cmd {
	v := strings.TrimSpace(p.input.Value())
	id := p.editID
	p.editing, p.editID = false, ""
	p.input.Blur()
	if v == "" {
		return nil
	}
	if id == "" {
		// A new box keeps the network, because that is the box that works. The
		// row says which it is and `m` changes it.
		return p.create(v)
	}
	net := true
	for _, b := range p.boxes {
		if b.ID == id {
			net = b.Network
		}
	}
	return p.save(id, v, "", net)
}

// All three writes go through the API, which is the code the CLI calls too. A
// path this panel accepted and the CLI refused would be a disagreement about
// what is confined, which is the worst kind to have here.

func (p *Sandbox) create(dir string) tea.Cmd {
	g, client := p.gen, p.deps.API
	return func() tea.Msg {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		b, err := client.Settings.SandboxCreate(c, dir, "", true)
		if err != nil {
			return sbDoneMsg{gen: g, err: err}
		}
		return sbDoneMsg{gen: g, text: "box " + b.ID + " · " + b.Dir}
	}
}

func (p *Sandbox) save(id, dir, label string, network bool) tea.Cmd {
	g, client := p.gen, p.deps.API
	return func() tea.Msg {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := client.Settings.SandboxUpdate(c, id, dir, label, network); err != nil {
			return sbDoneMsg{gen: g, err: err}
		}
		note := "network on"
		if !network {
			note = "no network · nothing leaves, and the agent cannot reach its model"
		}
		return sbDoneMsg{gen: g, text: "box " + id + " · " + note}
	}
}

func (p *Sandbox) del(id string) tea.Cmd {
	g, client := p.gen, p.deps.API
	return func() tea.Msg {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := client.Settings.SandboxDelete(c, id); err != nil {
			return sbDoneMsg{gen: g, err: err}
		}
		return sbDoneMsg{gen: g, text: "box " + id + " deleted · " + id + " is free again"}
	}
}

func (p *Sandbox) Hint() []string {
	if p.boxErr != nil {
		return []string{"▶ SANDBOX", "", "Not available on this machine.", "", "press → to read why"}
	}
	if len(p.boxes) == 0 {
		return []string{
			"▶ SANDBOX: CLOSED BOXES",
			"",
			"None yet. A box gives an agent one",
			"directory and nothing else.",
			"",
			"press → then n to make one",
		}
	}
	if len(p.boxes) == 1 {
		return []string{"▶ SANDBOX: CLOSED BOXES", "", "box " + p.boxes[0].ID, "",
			truncate(p.boxes[0].Dir, 44), "", "press → to manage"}
	}
	return []string{"▶ SANDBOX: CLOSED BOXES", "", itoa(len(p.boxes)) + " boxes", "", "press → to manage"}
}

func (p *Sandbox) View(ctx tui.PanelContext) string {
	p.apply(ctx)
	return clip(p.view(), p.cols, p.rows)
}

func (p *Sandbox) view() string {
	var out []string

	hint := "press → to configure"
	if p.focused {
		hint = "↑↓ move · n new · enter edit · m network · d d delete"
	}
	out = append(out, stDim.Render(hint))

	switch {
	case p.editing:
		out = append(out, stWarn.Render("directory (absolute path): ")+p.input.View())
	case p.msg != nil:
		st := stOK
		if p.msg.bad {
			st = stBad
		}
		out = append(out, st.Render(truncate(p.msg.text, p.cols)))
	default:
		out = append(out, " ")
	}
	out = append(out, "")

	// A machine that cannot build a box says so rather than listing boxes it
	// could not start.
	if p.boxErr != nil {
		out = append(out, stBad.Render("  No closed box on this machine."))
		out = append(out, "")
		for _, l := range wrapWords(p.boxErr.Error(), sbWidth(p.cols-4)) {
			out = append(out, stDim.Render("  "+l))
		}
		if p.mech != "" {
			out = append(out, "")
			out = append(out, stDim.Render("  `solongate run` is the weaker confinement this machine CAN do:"))
			out = append(out, stDim.Render("  "+p.mech+" over the protected-paths list, rather than a new root."))
		}
		return joinLines(out)
	}

	if !p.loaded {
		out = append(out, stDim.Render("  reading the policy file…"))
		return joinLines(out)
	}

	if len(p.boxes) == 0 {
		out = append(out, stWarn.Render("  No boxes."))
		out = append(out, "")
		out = append(out, stDim.Render("  A box gives an agent one directory and nothing else: no $HOME,"))
		out = append(out, stDim.Render("  no /etc/passwd, no other project. Not refused, absent."))
		out = append(out, "")
		out = append(out, stDim.Render("  press n, then type an absolute path"))
		return joinLines(out)
	}

	for i, b := range p.boxes {
		l := newLine(false)
		if i == p.sel && p.focused {
			l.put("▸ ", stAccent)
		} else {
			l.put("  ", stDim)
		}
		l.put(sbPad(b.ID, 5), stAccent)
		if b.Network {
			l.put(sbPad("net", 5), stDim)
		} else {
			// WARN rather than OK, and not because it is wrong: no network is
			// the STRONGER box and also the one where the agent cannot reach
			// its model. Somebody scanning this column needs to see which of
			// their boxes will not run an agent that needs an API.
			l.put(sbPad(", ", 5), stWarn)
		}
		l.put(truncate(b.Dir, sbWidth(p.cols-16)), stOK)
		out = append(out, l.String())
	}

	if b, ok := p.cur(); ok {
		out = append(out, "")
		out = append(out, stDim.Render("  solongate sandbox "+b.ID+" claude"))
		out = append(out, "")
		if b.Network {
			out = append(out, stDim.Render("  network ON, the agent can reach its model. What leaves over"))
			out = append(out, stDim.Render("  the wire is the DLP and egress layers' job, not the box's."))
		} else {
			out = append(out, stWarn.Render("  network OFF, nothing can leave this box at all, and an agent"))
			out = append(out, stWarn.Render("  that cannot reach its model can only do offline work."))
		}
	}

	return joinLines(out)
}

func sbWidth(n int) int {
	if n < 20 {
		return 20
	}
	return n
}

func atLeastZero(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func sbPad(s string, n int) string {
	for len(s) < n {
		s += " "
	}
	return s
}

// wrapWords breaks a sentence at spaces, so a long refusal reads as a paragraph
// rather than one clipped line.
func wrapWords(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	out := []string{}
	cur := words[0]
	for _, w := range words[1:] {
		if len(cur)+1+len(w) > width {
			out = append(out, cur)
			cur = w
			continue
		}
		cur += " " + w
	}
	return append(out, cur)
}
