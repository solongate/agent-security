// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/config"
)

func (m *setupModel) onKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	// While a path is being typed, the keyboard belongs to the text box. The
	// same discipline the panels use: otherwise a `q` in a path quits.
	if m.askingPath {
		switch k.Type {
		case tea.KeyEsc:
			m.askingPath = false
			m.input.Blur()
			return m, nil
		case tea.KeyEnter:
			path := strings.TrimSpace(m.input.Value())
			if path == "" {
				return m, nil
			}
			m.askingPath = false
			m.input.Blur()
			return m, m.write(path)
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(k)
		return m, cmd
	}

	switch k.String() {
	case "ctrl+c", "q":
		m.abandoned = true
		return m, tea.Quit

	case "up", "k":
		if m.step == stepPolicy && m.choice > 0 {
			m.choice--
		}
	case "down", "j":
		if m.step == stepPolicy && m.choice < len(setupPostures())-1 {
			m.choice++
		}

	case "enter", " ":
		switch m.step {
		case stepPolicy:
			if m.writing {
				return m, nil
			}
			if setupPostures()[m.choice].name == "path" {
				m.askingPath = true
				m.input.SetValue("")
				m.input.Focus()
				return m, textinput.Blink
			}
			return m, m.write("")
		case stepFinished:
			config.MarkSetupDone()
			return m, tea.Quit
		}
	}
	return m, nil
}