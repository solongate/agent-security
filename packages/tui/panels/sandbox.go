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
	client := p.deps.Client
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

func (p *Sandbox) cur() (shared.Sandbox, bool) {
	if p.sel < 0 || p.sel >= len(p.boxes) {
		return shared.Sandbox{}, false
	}
	return p.boxes[p.sel], true
}

func atLeastZero(n int) int {
	if n < 0 {
		return 0
	}
	return n
}