// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

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

	editing bool
	editID  string
	input   textinput.Model

	confirm string

	msg *sbMessage

	mech   string
	boxErr error
}

func NewSandbox(d tui.Deps) *Sandbox {
	in := textinput.New()
	in.Prompt = ""
	in.CharLimit = 4096

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