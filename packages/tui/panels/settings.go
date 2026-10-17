// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/core/health"
	"github.com/solongate/agent-security/packages/core/install"
	"github.com/solongate/agent-security/packages/tui"
)

func init() { tui.Register(tui.SectionSettings, func(d tui.Deps) tui.Panel { return NewSettings(d) }) }

var doctorSteps = []string{"policy file", "active policy", "guard hook", "agent hooks", "local logs"}

type setRow struct {
	kind string
}

func (r setRow) key() string { return r.kind }

type setMessage struct {
	text string
	bad  bool
}

type (
	setLocalMsg struct {
		genTag
		data client.LocalLogsConfig
		err  error
	}
	setGuardMsg struct {
		genTag
		data client.GuardStatus
		err  error
	}
	setSelfMsg struct {
		genTag
		data bool
		err  error
	}

	setProtectedMsg struct {
		genTag
		rows []protectedLine
	}

	setRunMsg struct {
		genTag
		label  string
		err    error
		reload string
		hide   string
	}

	setDoctorMsg struct {
		genTag
		checks []health.Check
	}
	setSpinMsg struct{ genTag }
	setDiskMsg struct{ genTag }

	setInstallMsg struct {
		genTag
		verb    string
		ok      bool
		message string
		notes   []string

		repair *install.Report
	}
)

type Settings struct {
	deps tui.Deps

	cols, rows int
	focused    bool
	gen, tok   int

	local     client.LocalLogsConfig
	haveLocal bool
	localErr  error
	guard     client.GuardStatus
	haveGuard bool
	guardErr  error
	selfProt  bool
	haveSelf  bool

	protected []protectedLine
	selfErr   error

	hidden map[string]bool

	llSetting config.LocalLogSetting

	sel        int
	editing    string
	input      textinput.Model
	confirmDel string
	msg        *setMessage
	busy       bool

	installBusy bool

	repairReport *install.Report

	diag     []health.Check
	diagBusy bool
	diagStep int

	spin int
}

func NewSettings(d tui.Deps) *Settings {
	ti := textinput.New()
	ti.Prompt = ""
	return &Settings{
		deps:   d,
		cols:   60,
		rows:   12,
		hidden: map[string]bool{},
		input:  ti,
		tok:    nextToken(),
	}
}

var _ tui.Panel = (*Settings)(nil)

func (p *Settings) CapturingKeys() bool { return p.editing != "" }

func (p *Settings) apply(ctx tui.PanelContext) {
	p.cols, p.rows, p.focused, p.gen = ctx.Cols, ctx.Rows, ctx.Focused, ctx.Gen
}

func (p *Settings) tag() genTag { return genTag{gen: p.gen, tok: p.tok} }

func (p *Settings) Init(ctx tui.PanelContext) tea.Cmd {
	p.apply(ctx)
	p.readDisk()
	t := p.tag()
	return tea.Batch(p.reloadAll(),
		tea.Tick(3*time.Second, func(time.Time) tea.Msg { return setDiskMsg{t} }))
}

func (p *Settings) readDisk() {
	p.llSetting = config.LocalLogsSetting()
}

func (p *Settings) reloadAll() tea.Cmd {
	return tea.Batch(p.loadLocal(), p.loadGuard(), p.loadSelf(), p.loadProtected())
}

type protectedLine struct {
	path string
	lock config.Lock
}

func (p *Settings) loadProtected() tea.Cmd {
	t := p.tag()
	client := p.deps.Client
	return func() tea.Msg {
		paths, err := client.Settings.ProtectedPaths(bg())
		if err != nil {

			return setProtectedMsg{genTag: t}
		}
		rows := make([]protectedLine, 0, len(paths))
		for _, path := range paths {
			rows = append(rows, protectedLine{path: path, lock: config.CheckLock(path)})
		}
		return setProtectedMsg{genTag: t, rows: rows}
	}
}

func (p *Settings) loadLocal() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		c, err := p.deps.Client.Settings.GetLocalLogs(bg())
		return setLocalMsg{genTag: t, data: c, err: err}
	}
}

func (p *Settings) loadGuard() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		g, err := p.deps.Client.Settings.GetGuardStatus(bg())
		return setGuardMsg{genTag: t, data: g, err: err}
	}
}

func (p *Settings) loadSelf() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		v, err := p.deps.Client.Settings.GetSelfProtection(bg())
		return setSelfMsg{genTag: t, data: v, err: err}
	}
}

func (p *Settings) reloadNamed(which string) tea.Cmd {
	switch which {
	case "local":
		return p.loadLocal()
	case "guard":
		return p.loadGuard()
	case "self":
		return p.loadSelf()
	case "all":
		return p.reloadAll()
	}
	return nil
}

func (p *Settings) run(label string, fn func() error, reload string) tea.Cmd {
	return p.runHiding(label, fn, reload, "")
}

func (p *Settings) runHiding(label string, fn func() error, reload, hide string) tea.Cmd {
	if p.busy {
		return nil
	}
	p.busy = true
	p.msg = &setMessage{text: label + "…"}
	t := p.tag()
	return func() tea.Msg {
		return setRunMsg{genTag: t, label: label, err: fn(), reload: reload, hide: hide}
	}
}

func (p *Settings) Update(msg tea.Msg, ctx tui.PanelContext) (tui.Panel, tea.Cmd) {
	p.apply(ctx)
	switch m := msg.(type) {
	case setLocalMsg:
		p.localErr = m.err
		if m.err == nil {
			p.local, p.haveLocal = m.data, true
		}
	case setGuardMsg:
		p.guardErr = m.err
		if m.err == nil {
			p.guard, p.haveGuard = m.data, true
		}
	case setSelfMsg:
		p.selfErr = m.err
		if m.err == nil {
			p.selfProt, p.haveSelf = m.data, true
		}

	case setProtectedMsg:
		if m.tok != p.tok {
			return p, nil
		}
		p.protected = m.rows

	case setRunMsg:
		p.busy = false
		if m.err != nil {
			p.msg = &setMessage{text: "✗ " + errText(m.err), bad: true}
			return p, nil
		}
		p.msg = &setMessage{text: "✓ " + m.label}
		if m.hide != "" {
			p.hidden[m.hide] = true
		}
		return p, p.reloadNamed(m.reload)

	case setDiskMsg:
		if m.tok != p.tok {
			return p, nil
		}
		p.readDisk()
		t := p.tag()
		return p, tea.Tick(3*time.Second, func(time.Time) tea.Msg { return setDiskMsg{t} })

	case setSpinMsg:
		if m.tok != p.tok {
			return p, nil
		}
		p.spin++
		if p.diagBusy {

			if p.spin%2 == 0 {
				p.diagStep = min(p.diagStep+1, len(doctorSteps)-1)
			}
		}
		if p.busy || p.diagBusy {
			t := p.tag()
			return p, tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return setSpinMsg{t} })
		}
		return p, nil

	case setInstallMsg:
		p.installBusy = false
		if m.verb == "repair" {
			p.repairReport = m.repair
		}
		text := m.message
		if text == "" {
			text = m.verb + " finished"
		}

		for _, n := range m.notes {
			text += " · " + n
		}
		p.msg = &setMessage{text: text, bad: !m.ok}
		return p, p.loadGuard()

	case setDoctorMsg:
		p.diagBusy = false
		p.diag = m.checks
		bad, warn := 0, 0
		for _, c := range m.checks {
			switch c.OK {
			case health.StateFail:
				bad++
			case health.StateWarn:
				warn++
			}
		}
		switch {
		case bad > 0:
			text := "✗ " + itoa(bad) + " problem(s)"
			if warn > 0 {
				text += " · " + itoa(warn) + " warning(s)"
			}
			p.msg = &setMessage{text: text, bad: true}
		case warn > 0:
			p.msg = &setMessage{text: "✓ guard is working · " + itoa(warn) + " warning(s)"}
		default:
			p.msg = &setMessage{text: "✓ all good"}
		}
		return p, nil

	case tea.KeyMsg:
		if !p.focused {
			return p, nil
		}
		return p, p.key(m)
	}
	return p, nil
}

func (p *Settings) allRows() []setRow {
	rows := make([]setRow, 0, 6)
	for _, k := range []string{"guard", "self", "doctor", "repair", "ll-enabled", "ll-path", "range"} {
		rows = append(rows, setRow{kind: k})
	}
	return rows
}

func (p *Settings) current() setRow {
	rows := p.allRows()
	return rows[min(p.sel, len(rows)-1)]
}