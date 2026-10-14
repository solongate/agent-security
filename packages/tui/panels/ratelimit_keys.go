// SPDX-License-Identifier: Apache-2.0

package panels

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Split from ratelimit.go: key handling, field adjustment, save/discard.

func (p *RateLimit) key(k tea.KeyMsg) tea.Cmd {
	total, burstBudget := p.cursorTotal(), p.burstBudget()
	switch k.String() {
	case "ctrl+r":
		p.status = "⟳ refreshed " + time.Now().Format("15:04:05")
		if p.bound {
			return tea.Batch(p.loadHistory(), p.loadInsights())
		}
		return tea.Batch(p.loadLayers(), p.loadHistory(), p.loadInsights())
	case "up":
		p.sel = max(0, p.selClamped()-1)
	case "down":
		p.sel = min(total-1, p.selClamped()+1)
	case "pgdown":
		p.sel = min(total-1, p.selClamped()+burstBudget)
	case "pgup":
		p.sel = max(0, p.selClamped()-burstBudget)
	case "left":
		p.adjust(-1, 1)
	case "right":
		p.adjust(1, 1)
	case "shift+left":
		p.adjust(-1, 10)
	case "shift+right":
		p.adjust(1, 10)
	case "s":
		if p.bound {
			// The owner saves. See DLP.
			return nil
		}
		return p.save()
	case "x":
		if p.bound {
			// The owner discards, for the same reason it saves: the draft is the
			// policy's, and throwing away only this half would leave the two
			// disagreeing about what is unsaved.
			return nil
		}
		p.discard()
	}
	return nil
}

// discard drops the draft and takes the server's answer back.
func (p *RateLimit) discard() {
	if !p.haveSrv {
		return
	}
	p.draft, p.hasDraft = p.server.Layers, true
	p.dirty = false
	p.status = "discarded"
}

// adjust moves the field under the cursor. A cursor sitting on a burst row is
// not a field and must not silently edit the one above it.
func (p *RateLimit) adjust(dir, step int) {
	if !p.hasDraft {
		return
	}
	fi := p.fieldIndex()
	if fi < 0 {
		return
	}
	rl := &p.draft.RateLimit
	switch fi {
	case 0:
		i := 0
		for j, m := range rlModes {
			if m == rl.Mode {
				i = j
			}
		}
		rl.Mode = rlModes[(i+dir+len(rlModes))%len(rlModes)]
	case 1:
		rl.PerMinute = max(0, rl.PerMinute+dir*step)
	case 2:
		rl.PerHour = max(0, rl.PerHour+dir*step)
	case 3:
		rl.PerDay = max(0, rl.PerDay+dir*step)
	}
	p.dirty = true
	p.status = ""
}

func (p *RateLimit) save() tea.Cmd {
	if !p.hasDraft || !p.haveSrv {
		return nil
	}
	p.status = "Saving…"
	next := p.server.Layers
	next.RateLimit = p.draft.RateLimit
	t := p.tag()
	return func() tea.Msg {
		got, err := p.deps.Client.Settings.SetSecurityLayers(bg(), next)
		return rlSavedMsg{genTag: t, layers: got, err: err}
	}
}