// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestSetupOnKeyAskingPathEscCancels(t *testing.T) {
	m := newSetup(Deps{})
	m.askingPath = true
	m.input.Focus()
	m.input.SetValue("/tmp/x")

	m.onKey(tea.KeyMsg{Type: tea.KeyEsc})
	if m.askingPath {
		t.Error("onKey(Esc) while asking for a path left askingPath true, want false")
	}
}

func TestSetupOnKeyAskingPathEnterWithEmptyValueIsNoop(t *testing.T) {
	m := newSetup(Deps{})
	m.askingPath = true
	m.input.Focus()
	m.input.SetValue("   ")

	_, cmd := m.onKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !m.askingPath {
		t.Error("onKey(Enter) with a blank path left askingPath false, want it to stay true")
	}
	if cmd != nil {
		t.Error("onKey(Enter) with a blank path returned a non-nil cmd, want nil")
	}
}

func TestSetupOnKeyAskingPathEnterWithValueWrites(t *testing.T) {
	m := newSetup(Deps{})
	m.askingPath = true
	m.input.Focus()
	m.input.SetValue("  /tmp/protected  ")

	_, cmd := m.onKey(tea.KeyMsg{Type: tea.KeyEnter})
	if m.askingPath {
		t.Error("onKey(Enter) with a path left askingPath true, want false")
	}
	if !m.writing {
		t.Error("onKey(Enter) with a path did not start the write, want writing = true")
	}
	if cmd == nil {
		t.Error("onKey(Enter) with a path returned a nil cmd, want the write cmd")
	}
}

func TestSetupOnKeyAskingPathOtherKeysEditInput(t *testing.T) {
	m := newSetup(Deps{})
	m.askingPath = true
	m.input.Focus()
	m.input.SetValue("")

	m.onKey(runeKey("a"))
	if m.input.Value() != "a" {
		t.Errorf("after typing \"a\" input value = %q, want \"a\"", m.input.Value())
	}
}

func TestSetupOnKeyCtrlCOrQAbandons(t *testing.T) {
	for _, k := range []tea.KeyMsg{{Type: tea.KeyCtrlC}, runeKey("q")} {
		m := newSetup(Deps{})
		_, cmd := m.onKey(k)
		if !m.abandoned {
			t.Errorf("onKey(%v) did not set abandoned, want true", k)
		}
		if !isQuitCmd(t, cmd) {
			t.Errorf("onKey(%v) did not return tea.Quit", k)
		}
	}
}

func TestSetupOnKeyUpDownAdjustChoiceOnlyDuringPolicyStep(t *testing.T) {
	t.Run("up/k decrements but floors at zero", func(t *testing.T) {
		m := newSetup(Deps{})
		m.step = stepPolicy
		m.choice = 0
		m.onKey(tea.KeyMsg{Type: tea.KeyUp})
		if m.choice != 0 {
			t.Errorf("choice = %d, want 0 (floored)", m.choice)
		}
		m.choice = 1
		m.onKey(runeKey("k"))
		if m.choice != 0 {
			t.Errorf("choice = %d, want 0 after decrementing from 1", m.choice)
		}
	})
	t.Run("down/j increments but caps at the last posture", func(t *testing.T) {
		m := newSetup(Deps{})
		m.step = stepPolicy
		last := len(setupPostures()) - 1
		m.choice = last
		m.onKey(tea.KeyMsg{Type: tea.KeyDown})
		if m.choice != last {
			t.Errorf("choice = %d, want %d (capped)", m.choice, last)
		}
		m.choice = 0
		m.onKey(runeKey("j"))
		if m.choice != 1 {
			t.Errorf("choice = %d, want 1 after incrementing from 0", m.choice)
		}
	})
	t.Run("ignored outside the policy step", func(t *testing.T) {
		m := newSetup(Deps{})
		m.step = stepGuard
		m.choice = 0
		m.onKey(runeKey("j"))
		if m.choice != 0 {
			t.Errorf("choice = %d, want 0 (up/down ignored outside stepPolicy)", m.choice)
		}
	})
}

func TestSetupOnKeyEnterDuringPolicyWhileWritingIsNoop(t *testing.T) {
	m := newSetup(Deps{})
	m.step = stepPolicy
	m.writing = true
	_, cmd := m.onKey(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Error("onKey(Enter) during an in-flight write returned a non-nil cmd, want nil")
	}
	if m.askingPath {
		t.Error("onKey(Enter) during an in-flight write started asking for a path, want unchanged")
	}
}

func TestSetupOnKeyEnterOnPathPostureAsksForPath(t *testing.T) {
	m := newSetup(Deps{})
	m.step = stepPolicy
	for i, p := range setupPostures() {
		if p.name == "path" {
			m.choice = i
		}
	}
	m.input.SetValue("leftover")

	_, cmd := m.onKey(tea.KeyMsg{Type: tea.KeySpace})
	if !m.askingPath {
		t.Error("onKey(space) on the path posture did not set askingPath, want true")
	}
	if m.input.Value() != "" {
		t.Errorf("onKey(space) on the path posture left input value %q, want cleared", m.input.Value())
	}
	if cmd == nil {
		t.Error("onKey(space) on the path posture returned a nil cmd, want textinput.Blink")
	}
}

func TestSetupOnKeyEnterOnNonPathPostureWrites(t *testing.T) {
	m := newSetup(Deps{})
	m.step = stepPolicy
	m.choice = 0 // "watch"

	_, cmd := m.onKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !m.writing {
		t.Error("onKey(Enter) on a non-path posture did not start the write, want writing = true")
	}
	if cmd == nil {
		t.Error("onKey(Enter) on a non-path posture returned a nil cmd, want the write cmd")
	}
}

func TestSetupOnKeyEnterAtFinishedMarksSetupDoneAndQuits(t *testing.T) {
	newHome(t)
	m := newSetup(Deps{})
	m.step = stepFinished

	_, cmd := m.onKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !isQuitCmd(t, cmd) {
		t.Error("onKey(Enter) at stepFinished did not return tea.Quit")
	}
}

func TestSetupOnKeyEnterOutsidePolicyOrFinishedIsNoop(t *testing.T) {
	for _, step := range []setupStep{stepGuard, stepFirstCall} {
		m := newSetup(Deps{})
		m.step = step
		_, cmd := m.onKey(tea.KeyMsg{Type: tea.KeyEnter})
		if cmd != nil {
			t.Errorf("onKey(Enter) at step %v returned a non-nil cmd, want nil", step)
		}
	}
}

func TestSetupOnKeyUnhandledKeyIsNoop(t *testing.T) {
	m := newSetup(Deps{})
	_, cmd := m.onKey(runeKey("z"))
	if cmd != nil {
		t.Error("onKey(\"z\") returned a non-nil cmd, want nil")
	}
}