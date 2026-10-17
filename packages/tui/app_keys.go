// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

func (a *App) onKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {

	if a.focus == focusPanel && a.capturing() {
		return a, a.toPanel(k)
	}

	if a.help {
		a.help = false
		return a, nil
	}
	key, str := k.Type, k.String()
	if str == "?" && a.focus == focusNav {
		a.help = true
		return a, nil
	}

	if a.focus == focusNav {
		switch {
		case key == tea.KeyUp:
			a.section = (a.section - 1 + sectionCount) % sectionCount
			return a, a.mount()
		case key == tea.KeyDown:
			a.section = (a.section + 1) % sectionCount
			return a, a.mount()
		case key == tea.KeyRight || key == tea.KeyEnter || key == tea.KeyTab:
			a.focus = focusPanel
			return a, nil
		case str == "a" || str == "A":
		case str == "q" || str == "Q":
			return a, tea.Quit
		}
		return a, nil
	}

	cmd := a.toPanel(k)
	switch {
	case key == tea.KeyEsc || key == tea.KeyTab:
		a.focus = focusNav
	case (str == "q" || str == "Q") && a.isTakeover():
		return a, tea.Quit
	}
	return a, cmd
}