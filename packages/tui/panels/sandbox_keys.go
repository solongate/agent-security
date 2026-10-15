// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"context"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Split from sandbox.go: key handling, the edit prompt, and the create/save/delete commands.

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
	g, client := p.gen, p.deps.Client
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
	g, client := p.gen, p.deps.Client
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
	g, client := p.gen, p.deps.Client
	return func() tea.Msg {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := client.Settings.SandboxDelete(c, id); err != nil {
			return sbDoneMsg{gen: g, err: err}
		}
		return sbDoneMsg{gen: g, text: "box " + id + " deleted · " + id + " is free again"}
	}
}