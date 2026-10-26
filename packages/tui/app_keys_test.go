// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func runeKey(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func isQuitCmd(t *testing.T, cmd tea.Cmd) bool {
	t.Helper()
	if cmd == nil {
		return false
	}
	_, ok := cmd().(tea.QuitMsg)
	return ok
}

func TestOnKeyCapturingPanelBypassesNavHandling(t *testing.T) {
	fake := &capturingPanel{capture: true}
	withRegistry(t, SectionLive, func(Deps) Panel { return fake })
	a := New(Deps{})
	a.Init()
	a.focus = focusPanel
	a.help = false

	a.onKey(runeKey("?"))
	if a.help {
		t.Error("onKey() set help while the focused panel is capturing keys, want help untouched")
	}
	if len(fake.updates) != 1 {
		t.Errorf("capturing panel received %d updates, want 1 (the key forwarded)", len(fake.updates))
	}
}

func TestOnKeyDismissesHelpOnAnyKey(t *testing.T) {
	a := New(Deps{})
	a.help = true
	_, cmd := a.onKey(runeKey("x"))
	if a.help {
		t.Error("onKey() left help on, want it dismissed by the next keypress")
	}
	if cmd != nil {
		t.Error("onKey() dismissing help returned a non-nil cmd, want nil")
	}
}

func TestOnKeyQuestionMarkOpensHelpInNav(t *testing.T) {
	a := New(Deps{})
	a.focus = focusNav
	a.onKey(runeKey("?"))
	if !a.help {
		t.Error("onKey(\"?\") in nav focus did not set help, want true")
	}
}

func TestOnKeyNavArrowsWrapAroundSections(t *testing.T) {
	withRegistry(t, SectionLive, func(Deps) Panel { return &basicPanel{} })
	withRegistry(t, SectionSettings, func(Deps) Panel { return &basicPanel{} })

	a := New(Deps{})
	a.focus = focusNav
	a.section = SectionLive
	a.onKey(tea.KeyMsg{Type: tea.KeyUp})
	if a.section != sectionCount-1 {
		t.Errorf("KeyUp from section 0 = %d, want %d (wrapped to the last section)", a.section, sectionCount-1)
	}

	a.section = sectionCount - 1
	a.onKey(tea.KeyMsg{Type: tea.KeyDown})
	if a.section != 0 {
		t.Errorf("KeyDown from the last section = %d, want 0 (wrapped around)", a.section)
	}
}

func TestOnKeyEnterRightTabMoveFocusToPanel(t *testing.T) {
	for _, kt := range []tea.KeyType{tea.KeyRight, tea.KeyEnter, tea.KeyTab} {
		a := New(Deps{})
		a.focus = focusNav
		a.onKey(tea.KeyMsg{Type: kt})
		if a.focus != focusPanel {
			t.Errorf("onKey(%v) in nav focus left focus = %v, want focusPanel", kt, a.focus)
		}
	}
}

func TestOnKeyLetterAIsIgnoredInNav(t *testing.T) {
	a := New(Deps{})
	a.focus = focusNav
	section := a.section
	_, cmd := a.onKey(runeKey("a"))
	if a.section != section || a.focus != focusNav {
		t.Error("onKey(\"a\") in nav focus changed state, want no-op")
	}
	if cmd != nil {
		t.Error("onKey(\"a\") in nav focus returned a non-nil cmd, want nil")
	}
}

func TestOnKeyQQuitsFromNav(t *testing.T) {
	a := New(Deps{})
	a.focus = focusNav
	_, cmd := a.onKey(runeKey("q"))
	if !isQuitCmd(t, cmd) {
		t.Error("onKey(\"q\") in nav focus did not return tea.Quit")
	}
}

func TestOnKeyUnhandledNavKeyIsNoop(t *testing.T) {
	a := New(Deps{})
	a.focus = focusNav
	section := a.section
	_, cmd := a.onKey(runeKey("z"))
	if a.section != section {
		t.Error("onKey(\"z\") in nav focus changed the section, want no-op")
	}
	if cmd != nil {
		t.Error("onKey(\"z\") in nav focus returned a non-nil cmd, want nil")
	}
}

func TestOnKeyPanelFocusForwardsKeys(t *testing.T) {
	fake := &basicPanel{}
	withRegistry(t, SectionLive, func(Deps) Panel { return fake })
	a := New(Deps{})
	a.Init()
	a.focus = focusPanel

	a.onKey(runeKey("x"))
	if len(fake.updates) != 1 {
		t.Errorf("panel received %d updates, want 1", len(fake.updates))
	}
}

func TestOnKeyEscOrTabReturnsFocusToNav(t *testing.T) {
	for _, kt := range []tea.KeyType{tea.KeyEsc, tea.KeyTab} {
		fake := &basicPanel{}
		withRegistry(t, SectionLive, func(Deps) Panel { return fake })
		a := New(Deps{})
		a.Init()
		a.focus = focusPanel

		a.onKey(tea.KeyMsg{Type: kt})
		if a.focus != focusNav {
			t.Errorf("onKey(%v) in panel focus left focus = %v, want focusNav", kt, a.focus)
		}
	}
}

func TestOnKeyQQuitsFromTakeoverPanel(t *testing.T) {
	fake := &takeoverPanel{}
	withRegistry(t, SectionLive, func(Deps) Panel { return fake })
	a := New(Deps{})
	a.Init()
	a.focus = focusPanel

	_, cmd := a.onKey(runeKey("q"))
	if !isQuitCmd(t, cmd) {
		t.Error("onKey(\"q\") in a focused takeover panel did not return tea.Quit")
	}
	if a.focus != focusPanel {
		t.Error("onKey(\"q\") on a takeover panel changed focus, want unchanged")
	}
}

func TestOnKeyQDoesNotQuitNonTakeoverPanel(t *testing.T) {
	fake := &basicPanel{}
	withRegistry(t, SectionLive, func(Deps) Panel { return fake })
	a := New(Deps{})
	a.Init()
	a.focus = focusPanel

	_, cmd := a.onKey(runeKey("q"))
	if isQuitCmd(t, cmd) {
		t.Error("onKey(\"q\") quit a non-takeover panel, want the key just forwarded")
	}
	if len(fake.updates) != 1 {
		t.Errorf("panel received %d updates, want 1 (the \"q\" forwarded instead of quitting)", len(fake.updates))
	}
}