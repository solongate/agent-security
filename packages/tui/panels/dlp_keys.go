// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
)

// Split from dlp.go: key handling, the pinned add/edit prompt, save/discard.

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

	// The built-ins are a GRID and the custom patterns are a list, so ↑↓ means a
	// different distance in each. Crossing between them lands on the nearest edge
	// of the other section rather than skipping over it.
	case "up":
		nB := len(p.available)
		switch {
		case selC >= nB && selC-1 >= nB:
			p.sel = selC - 1
		case selC >= nB:
			p.sel = max(0, nB-1)
		default:
			p.sel = max(0, selC-dlpCols)
		}

	case "down":
		nB, total := len(p.available), len(p.entries())
		switch {
		case selC >= nB:
			p.sel = min(total-1, selC+1)
		case selC+dlpCols < nB:
			p.sel = selC + dlpCols
		default:
			p.sel = min(total-1, nB)
		}

	case "left":
		if selC < len(p.available) {
			p.sel = max(0, selC-1)
		}

	case "right":
		if nB := len(p.available); selC < nB {
			p.sel = min(nB-1, selC+1)
		}

	// All on / all off. The custom patterns are a different list and are left
	// exactly as they were: "every built-in" is not "everything".
	case "A":
		p.dlp.DLP.Patterns = append([]string(nil), p.available...)
		p.mutated()

	case "U":
		p.dlp.DLP.Patterns = nil
		p.mutated()

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
				p.dlp.DLP.Custom[p.editIdx] = client.CustomPattern{Name: p.newName, Re: v}
			} else {
				p.dlp.DLP.Custom = append(p.dlp.DLP.Custom, client.CustomPattern{Name: p.newName, Re: v})
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
		got, err := p.deps.Client.Settings.SetSecurityLayers(bg(), next)
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

// ── small slice helpers ────────────────────────────────────────────────────

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