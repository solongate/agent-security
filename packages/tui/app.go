// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
)

type Deps struct {
	Client *client.Client
	Cfg    config.TUIConfig

	Confinement Confinement
}

type Confinement struct {
	Mechanism string

	BoxUnavailable error
}

type PanelContext struct {
	Deps

	Cols int
	Rows int

	Focused bool

	Gen int

	Now time.Time
}

type Panel interface {
	Init(ctx PanelContext) tea.Cmd

	Update(msg tea.Msg, ctx PanelContext) (Panel, tea.Cmd)

	View(ctx PanelContext) string
}

type Takeover interface {
	Panel

	Hint(ctx PanelContext) string
}

type KeyCapture interface{ CapturingKeys() bool }

type GenMsg interface{ Generation() int }

type SectionRequestMsg struct{ Label string }

type UpdateStatusMsg struct {
	Kind    string
	Version string
}

const (
	SectionLive = iota
	SectionPolicies
	SectionAudit
	SectionSandbox
	SectionSettings
	sectionCount
)

var sectionLabels = [sectionCount]string{
	"Solo Live", "Policies", "Audit", "Sandbox", "Settings",
}

var registry [sectionCount]func(Deps) Panel

func Register(section int, ctor func(Deps) Panel) {
	if section < 0 || section >= sectionCount {
		return
	}
	registry[section] = ctor
}

var panelTokens int

func nextPanelToken() int { panelTokens++; return panelTokens }

func buildPanel(section int, deps Deps) Panel {
	if ctor := registry[section]; ctor != nil {
		if p := ctor(deps); p != nil {
			return p
		}
	}
	return &notPortedPanel{label: sectionLabels[section]}
}

type notPortedPanel struct{ label string }

func (p *notPortedPanel) Init(PanelContext) tea.Cmd { return nil }

func (p *notPortedPanel) Update(_ tea.Msg, _ PanelContext) (Panel, tea.Cmd) { return p, nil }

type focusTarget int

const (
	focusNav focusTarget = iota
	focusPanel
)

type App struct {
	deps Deps

	gen int

	policyLabel string

	section int
	focus   focusTarget
	help    bool
	update  UpdateStatusMsg

	cols, rows int
	sized      bool

	panel    Panel
	panelIdx int
}

func New(deps Deps) *App {
	a := &App{
		deps:        deps,
		cols:        100,
		rows:        30,
		panelIdx:    -1,
		policyLabel: "reading…",
	}
	return a
}

func (a *App) Init() tea.Cmd {

	return tea.Batch(a.mount(), a.readPolicyLabel())
}

type policyLabelMsg struct{ text string }

func (a *App) readPolicyLabel() tea.Cmd {
	client := a.deps.Client
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		list, err := client.Policies.List(ctx)
		switch {
		case err != nil:
			return policyLabelMsg{text: err.Error()}
		case len(list) == 0:
			return policyLabelMsg{text: "none yet"}
		default:
			word := " rules"
			if len(list[0].Rules.Items) == 1 {
				word = " rule"
			}
			return policyLabelMsg{text: list[0].Name + " · " + strconv.Itoa(len(list[0].Rules.Items)) + word}
		}
	}
}

func (a *App) mount() tea.Cmd {
	idx := a.effectiveSection()
	a.panel = buildPanel(idx, a.deps)
	a.panelIdx = idx
	return a.panel.Init(a.ctx())
}

func (a *App) remount() tea.Cmd {
	a.gen++
	return a.mount()
}

func (a *App) effectiveSection() int { return a.section }

func (a *App) ctx() PanelContext {
	cols, rows := a.panelBudget()
	if a.isTakeover() && a.focus == focusPanel {
		cols, rows = a.cols, a.rows-1
	}
	return PanelContext{
		Deps:    a.deps,
		Cols:    cols,
		Rows:    rows,
		Focused: a.focus == focusPanel,
		Gen:     a.gen,
		Now:     time.Now(),
	}
}

func (a *App) isTakeover() bool {
	_, ok := a.panel.(Takeover)
	return ok
}

func (a *App) panelBudget() (cols, rows int) {
	shell := 10
	if a.cols >= 82 {
		shell = 16
	}
	cols, rows = a.cols-22, a.rows-shell
	if cols < 30 {
		cols = 30
	}
	if rows < 8 {
		rows = 8
	}
	return cols, rows
}

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.cols, a.rows, a.sized = m.Width, m.Height, true

		return a, a.toPanel(msg)

	case tea.KeyMsg:
		return a.onKey(m)

	case SectionRequestMsg:
		for i, label := range sectionLabels {
			if label == m.Label {
				a.section = i
				a.focus = focusPanel
				return a, a.mount()
			}
		}
		return a, nil

	case UpdateStatusMsg:
		a.update = m
		return a, nil

	case policyLabelMsg:
		a.policyLabel = m.text
		return a, nil
	}

	if g, ok := msg.(GenMsg); ok && g.Generation() != a.gen {
		return a, nil
	}
	return a, a.toPanel(msg)
}

func (a *App) toPanel(msg tea.Msg) tea.Cmd {
	if a.panel == nil {
		return nil
	}
	p, cmd := a.panel.Update(msg, a.ctx())
	if p != nil {
		a.panel = p
	}
	return cmd
}

func (a *App) capturing() bool {
	kc, ok := a.panel.(KeyCapture)
	return ok && kc.CapturingKeys()
}

func Run(c Confinement) error {
	cfg := config.LoadTUIConfig()
	setAccent(cfg.Accent)

	flatten()

	log.SetOutput(io.Discard)
	if config.EnsureDir() == nil {
		path := filepath.Join(config.Dir(), "tui-debug.log")
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			defer f.Close()
			log.SetOutput(f)
		}
	}

	deps := Deps{Client: client.New(), Cfg: cfg, Confinement: c}

	if needsSetup(cfg) {
		carryOn, err := runSetup(deps, os.Stdout)
		if err != nil {
			return err
		}
		if !carryOn {
			return nil
		}

		deps.Cfg = config.LoadTUIConfig()
	}

	app := New(deps)
	_, err := tea.NewProgram(app, tea.WithAltScreen()).Run()
	return err
}