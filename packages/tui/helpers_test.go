// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"testing"
)

// newHome points HOME at a fresh, empty temp directory so tests that reach
// config.Dir() (via config.LocalLogFile, config.LoadTUIConfig, etc.) run
// entirely against a throwaway filesystem.
func newHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

// basicPanel is a minimal Panel implementation used to exercise App/setup
// plumbing without touching any real rendering or network code.
type basicPanel struct {
	inits   int
	initCtx PanelContext

	updates   []tea.Msg
	updateCtx []PanelContext
}

func (p *basicPanel) Init(ctx PanelContext) tea.Cmd {
	p.inits++
	p.initCtx = ctx
	return nil
}

func (p *basicPanel) Update(msg tea.Msg, ctx PanelContext) (Panel, tea.Cmd) {
	p.updates = append(p.updates, msg)
	p.updateCtx = append(p.updateCtx, ctx)
	return p, nil
}

func (p *basicPanel) View(PanelContext) string { return "" }

// takeoverPanel additionally satisfies the Takeover interface.
//
// Update is overridden (rather than left promoted from basicPanel) because
// the promoted method would return the embedded *basicPanel as the Panel
// result, not the outer *takeoverPanel — App.toPanel() would then replace
// a.panel with that inner value, silently losing the Hint method and the
// Takeover interface.
type takeoverPanel struct {
	basicPanel
	hint string
}

func (p *takeoverPanel) Update(msg tea.Msg, ctx PanelContext) (Panel, tea.Cmd) {
	p.updates = append(p.updates, msg)
	p.updateCtx = append(p.updateCtx, ctx)
	return p, nil
}

func (p *takeoverPanel) Hint(PanelContext) string { return p.hint }

// capturingPanel additionally satisfies the KeyCapture interface. Update is
// overridden for the same reason as takeoverPanel's above.
type capturingPanel struct {
	basicPanel
	capture bool
}

func (p *capturingPanel) Update(msg tea.Msg, ctx PanelContext) (Panel, tea.Cmd) {
	p.updates = append(p.updates, msg)
	p.updateCtx = append(p.updateCtx, ctx)
	return p, nil
}

func (p *capturingPanel) CapturingKeys() bool { return p.capture }

// withRegistry temporarily installs ctor for section and restores whatever
// was registered there once the test finishes, so tests don't leak global
// registry state into one another.
func withRegistry(t *testing.T, section int, ctor func(Deps) Panel) {
	t.Helper()
	orig := registry[section]
	registry[section] = ctor
	t.Cleanup(func() { registry[section] = orig })
}