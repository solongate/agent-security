// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestNewDefaults(t *testing.T) {
	a := New(Deps{})
	if a.cols != 100 || a.rows != 30 {
		t.Errorf("New() cols,rows = %d,%d, want 100,30", a.cols, a.rows)
	}
	if a.panelIdx != -1 {
		t.Errorf("New() panelIdx = %d, want -1", a.panelIdx)
	}
	if a.policyLabel != "reading…" {
		t.Errorf("New() policyLabel = %q, want %q", a.policyLabel, "reading…")
	}
	if a.section != SectionLive {
		t.Errorf("New() section = %d, want %d (SectionLive)", a.section, SectionLive)
	}
	if a.focus != focusNav {
		t.Errorf("New() focus = %v, want focusNav", a.focus)
	}
}

func TestAppInitMountsPanel(t *testing.T) {
	fake := &basicPanel{}
	withRegistry(t, SectionLive, func(Deps) Panel { return fake })

	a := New(Deps{})
	cmd := a.Init()
	if cmd == nil {
		t.Fatal("Init() returned a nil command, want a batch of mount+policy commands")
	}
	if a.panel != Panel(fake) {
		t.Fatal("Init() did not mount the registered panel for the current section")
	}
	if fake.inits != 1 {
		t.Errorf("registered panel Init() called %d times, want 1", fake.inits)
	}
	if a.panelIdx != SectionLive {
		t.Errorf("panelIdx = %d, want %d (SectionLive)", a.panelIdx, SectionLive)
	}
}

func TestBuildPanelFallsBackToNotPorted(t *testing.T) {
	withRegistry(t, SectionAudit, nil)
	p := buildPanel(SectionAudit, Deps{})
	np, ok := p.(*notPortedPanel)
	if !ok {
		t.Fatalf("buildPanel() with no registered ctor = %T, want *notPortedPanel", p)
	}
	if np.label != sectionLabels[SectionAudit] {
		t.Errorf("notPortedPanel label = %q, want %q", np.label, sectionLabels[SectionAudit])
	}
}

func TestBuildPanelCtorReturningNilFallsBack(t *testing.T) {
	withRegistry(t, SectionPolicies, func(Deps) Panel { return nil })
	p := buildPanel(SectionPolicies, Deps{})
	if _, ok := p.(*notPortedPanel); !ok {
		t.Fatalf("buildPanel() with a ctor returning nil = %T, want *notPortedPanel", p)
	}
}

func TestBuildPanelUsesRegisteredCtor(t *testing.T) {
	fake := &basicPanel{}
	withRegistry(t, SectionSandbox, func(Deps) Panel { return fake })
	p := buildPanel(SectionSandbox, Deps{})
	if p != Panel(fake) {
		t.Fatalf("buildPanel() = %v, want the registered fake panel", p)
	}
}

func TestRegisterIgnoresOutOfRangeSections(t *testing.T) {
	sentinel := &basicPanel{}
	withRegistry(t, SectionLive, func(Deps) Panel { return sentinel })

	Register(-1, func(Deps) Panel { return &basicPanel{} })
	Register(sectionCount, func(Deps) Panel { return &basicPanel{} })

	if p := buildPanel(SectionLive, Deps{}); p != Panel(sentinel) {
		t.Error("Register() with an out-of-range section disturbed an existing, valid registration")
	}
}

func TestNextPanelTokenIncrements(t *testing.T) {
	first := nextPanelToken()
	second := nextPanelToken()
	if second != first+1 {
		t.Errorf("nextPanelToken() sequence = %d, %d, want strictly increasing by 1", first, second)
	}
}

func TestAppUpdateWindowSizeMsg(t *testing.T) {
	fake := &basicPanel{}
	withRegistry(t, SectionLive, func(Deps) Panel { return fake })
	a := New(Deps{})
	a.Init()

	_, _ = a.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	if a.cols != 120 || a.rows != 40 || !a.sized {
		t.Errorf("after WindowSizeMsg cols,rows,sized = %d,%d,%v, want 120,40,true", a.cols, a.rows, a.sized)
	}
	if len(fake.updates) != 1 {
		t.Errorf("panel received %d updates, want 1 (the WindowSizeMsg forwarded)", len(fake.updates))
	}
}

func TestAppUpdateWindowSizeMsgNoPanelYet(t *testing.T) {
	a := New(Deps{})
	if _, cmd := a.Update(tea.WindowSizeMsg{Width: 10, Height: 10}); cmd != nil {
		t.Error("Update(WindowSizeMsg) with no mounted panel returned a non-nil cmd, want nil")
	}
}

// initCmdPanel is like basicPanel but returns a non-nil cmd from Init, so
// tests can tell a mount actually happened (basicPanel.Init always returns nil).
type initCmdPanel struct{ basicPanel }

func (p *initCmdPanel) Init(ctx PanelContext) tea.Cmd {
	p.inits++
	p.initCtx = ctx
	return func() tea.Msg { return nil }
}

func TestAppUpdateSectionRequestMsgMatch(t *testing.T) {
	fake := &initCmdPanel{}
	withRegistry(t, SectionPolicies, func(Deps) Panel { return fake })
	a := New(Deps{})

	_, cmd := a.Update(SectionRequestMsg{Label: "Policies"})
	if a.section != SectionPolicies {
		t.Errorf("section = %d, want %d (SectionPolicies)", a.section, SectionPolicies)
	}
	if a.focus != focusPanel {
		t.Errorf("focus = %v, want focusPanel", a.focus)
	}
	if cmd == nil {
		t.Error("Update(SectionRequestMsg) with a matching label returned a nil cmd, want the mount cmd")
	}
}

func TestAppUpdateSectionRequestMsgNoMatch(t *testing.T) {
	a := New(Deps{})
	origSection, origFocus := a.section, a.focus
	_, cmd := a.Update(SectionRequestMsg{Label: "not-a-real-section"})
	if a.section != origSection || a.focus != origFocus {
		t.Error("Update(SectionRequestMsg) with no matching label changed section/focus, want unchanged")
	}
	if cmd != nil {
		t.Error("Update(SectionRequestMsg) with no matching label returned a non-nil cmd, want nil")
	}
}

func TestAppUpdateStatusMsg(t *testing.T) {
	a := New(Deps{})
	msg := UpdateStatusMsg{Kind: "patch", Version: "1.2.3"}
	a.Update(msg)
	if a.update != msg {
		t.Errorf("update = %+v, want %+v", a.update, msg)
	}
}

func TestAppUpdatePolicyLabelMsg(t *testing.T) {
	a := New(Deps{})
	a.Update(policyLabelMsg{text: "my-policy · 3 rules"})
	if a.policyLabel != "my-policy · 3 rules" {
		t.Errorf("policyLabel = %q, want %q", a.policyLabel, "my-policy · 3 rules")
	}
}

type genMsg struct{ gen int }

func (g genMsg) Generation() int { return g.gen }

func TestAppUpdateGenMsgMismatchIsIgnored(t *testing.T) {
	fake := &basicPanel{}
	withRegistry(t, SectionLive, func(Deps) Panel { return fake })
	a := New(Deps{})
	a.Init()
	fake.updates = nil

	a.Update(genMsg{gen: a.gen + 1})
	if len(fake.updates) != 0 {
		t.Errorf("panel received %d updates for a stale-generation message, want 0", len(fake.updates))
	}
}

func TestAppUpdateGenMsgMatchIsForwarded(t *testing.T) {
	fake := &basicPanel{}
	withRegistry(t, SectionLive, func(Deps) Panel { return fake })
	a := New(Deps{})
	a.Init()
	fake.updates = nil

	a.Update(genMsg{gen: a.gen})
	if len(fake.updates) != 1 {
		t.Errorf("panel received %d updates for a current-generation message, want 1", len(fake.updates))
	}
}

func TestAppRemountBumpsGeneration(t *testing.T) {
	fake := &basicPanel{}
	withRegistry(t, SectionLive, func(Deps) Panel { return fake })
	a := New(Deps{})
	a.Init()
	gen := a.gen
	a.remount()
	if a.gen != gen+1 {
		t.Errorf("remount() gen = %d, want %d", a.gen, gen+1)
	}
}

func TestAppPanelBudget(t *testing.T) {
	cases := []struct {
		name       string
		cols, rows int
		wantCols   int
		wantRows   int
	}{
		{"narrow terminal uses the small shell", 60, 20, 38, 10},
		{"wide terminal uses the large shell", 100, 30, 78, 14},
		{"tiny terminal is clamped to the floor", 10, 5, 30, 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(Deps{})
			a.cols, a.rows = tc.cols, tc.rows
			cols, rows := a.panelBudget()
			if cols != tc.wantCols || rows != tc.wantRows {
				t.Errorf("panelBudget() = %d,%d, want %d,%d", cols, rows, tc.wantCols, tc.wantRows)
			}
		})
	}
}

func TestAppIsTakeover(t *testing.T) {
	t.Run("takeover panel", func(t *testing.T) {
		withRegistry(t, SectionLive, func(Deps) Panel { return &takeoverPanel{} })
		a := New(Deps{})
		a.Init()
		if !a.isTakeover() {
			t.Error("isTakeover() = false, want true for a panel implementing Takeover")
		}
	})
	t.Run("plain panel", func(t *testing.T) {
		withRegistry(t, SectionLive, func(Deps) Panel { return &basicPanel{} })
		a := New(Deps{})
		a.Init()
		if a.isTakeover() {
			t.Error("isTakeover() = true, want false for a plain Panel")
		}
	})
}

func TestAppCapturing(t *testing.T) {
	t.Run("capturing panel reporting true", func(t *testing.T) {
		withRegistry(t, SectionLive, func(Deps) Panel { return &capturingPanel{capture: true} })
		a := New(Deps{})
		a.Init()
		if !a.capturing() {
			t.Error("capturing() = false, want true")
		}
	})
	t.Run("capturing panel reporting false", func(t *testing.T) {
		withRegistry(t, SectionLive, func(Deps) Panel { return &capturingPanel{capture: false} })
		a := New(Deps{})
		a.Init()
		if a.capturing() {
			t.Error("capturing() = true, want false")
		}
	})
	t.Run("panel without KeyCapture", func(t *testing.T) {
		withRegistry(t, SectionLive, func(Deps) Panel { return &basicPanel{} })
		a := New(Deps{})
		a.Init()
		if a.capturing() {
			t.Error("capturing() = true for a panel without CapturingKeys(), want false")
		}
	})
}

func TestAppCtxUsesFullSizeDuringFocusedTakeover(t *testing.T) {
	withRegistry(t, SectionLive, func(Deps) Panel { return &takeoverPanel{} })
	a := New(Deps{})
	a.Init()
	a.cols, a.rows = 90, 40
	a.focus = focusPanel

	ctx := a.ctx()
	if ctx.Cols != a.cols || ctx.Rows != a.rows-1 {
		t.Errorf("ctx() during a focused takeover = %d,%d, want %d,%d", ctx.Cols, ctx.Rows, a.cols, a.rows-1)
	}
	if !ctx.Focused {
		t.Error("ctx().Focused = false while focus == focusPanel, want true")
	}
}

func TestAppCtxUsesPanelBudgetWhenNotTakeover(t *testing.T) {
	withRegistry(t, SectionLive, func(Deps) Panel { return &basicPanel{} })
	a := New(Deps{})
	a.Init()
	a.cols, a.rows = 90, 40
	a.focus = focusPanel

	wantCols, wantRows := a.panelBudget()
	ctx := a.ctx()
	if ctx.Cols != wantCols || ctx.Rows != wantRows {
		t.Errorf("ctx() for a non-takeover panel = %d,%d, want %d,%d", ctx.Cols, ctx.Rows, wantCols, wantRows)
	}
}