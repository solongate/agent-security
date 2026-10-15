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

// The Settings panel, ported from tui/panels/Settings.tsx, the dashboard
// Settings page, TUI edition. Everything an operator configures, in ONE
// single-cursor list:
//
//	PROTECTION the guard hook, self-protection, doctor and repair
//	           turned on: `npm i -g` needs sudo on most macOS setups, so it must
//	           not run unasked)
//	LOCAL LOGS where the hooks write this machine's audit trail
//
// Installing, updating and removing the guard, doctor and repair all run for
// real now, through core/install and core/health. This panel reaches no
// further than that: the CLI is a sibling, not something the TUI calls. They are commands rather than inline calls because
// each writes several files, unlocks and relocks them, and may spawn a process;
// doing that on the update goroutine would freeze the terminal for as long as
// the disk takes, and a frozen terminal during a guard install is
// indistinguishable from a hung one.
//
// They were stubs until those modules existed, and the stubs said so on the row
// rather than offering a button that quietly did nothing, the subject of every
// one of these rows is whether this machine is protected.

// doctorSteps is what the health check looks at, in the order CollectChecks
// looks at it. The labels are honest about the passes; only the pacing is
// cosmetic, and it exists because a check that answers in 8ms would otherwise
// flash past unread and look like nothing ran.
// The names doctor reports, in order, so the panel can show progress before the run
// finishes. `login` was the first of them and is gone with the account: the first
// thing doctor checks is the policy FILE everything else comes from.
var doctorSteps = []string{"policy file", "active policy", "guard hook", "agent hooks", "local logs"}

// ── rows ───────────────────────────────────────────────────────────────────

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
	// setRunMsg is the answer to any one-shot action started by run(). hide is
	// the row key to drop on success, applied HERE rather than in the request
	// goroutine, which would be writing panel state while the update loop reads
	// it.
	setRunMsg struct {
		genTag
		label  string
		err    error
		reload string
		hide   string
	}
	// setDoctorMsg carries the health check, which is collected by the same code
	// `solongate doctor` prints from rather than by a second copy of it.
	setDoctorMsg struct {
		genTag
		checks []health.Check
	}
	setSpinMsg struct{ genTag }
	setDiskMsg struct{ genTag }

	// setInstallMsg carries the result of an install, an uninstall or a repair.
	//
	// These run as a command rather than inline because each of them writes
	// several files, unlocks and relocks them, and may spawn a process. Doing
	// that on the update goroutine would freeze the whole interface for as long
	// as the disk takes, and a frozen terminal during a guard install is
	// indistinguishable from a hung one.
	//
	// Notes are carried separately from Message on purpose: an install that
	// SUCCEEDED while doing less than usual is the outcome worth surfacing, and
	// dropping the notes would leave a machine looking freshly installed when it
	// is not.
	setInstallMsg struct {
		genTag
		verb    string
		ok      bool
		message string
		notes   []string
		// repair carries what was found and what was restored. The CLI prints
		// both lists; this panel used to take the summary line and drop them,
		// so pressing repair here looked like nothing had happened.
		repair *install.Report
	}
)

// Settings is the panel.
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

	// The protected paths, and what is holding each one RIGHT NOW. READ ONLY
	// HERE on purpose: adding one can need a sudo password on Linux, and a
	// program that has taken over the terminal is the wrong place to ask for
	// one. `solongate protect` is where that conversation belongs. This is the
	// surface that answers it afterwards, which is the half somebody opens the
	// TUI looking for.
	protected []protectedLine
	selfErr   error

	// hidden are rows deleted in this session. The row has to vanish the instant
	// the API confirms; without this it lingered until the background reload
	// caught up, which read as the delete not having worked.
	hidden map[string]bool

	llSetting config.LocalLogSetting

	sel        int
	editing    string // "" · path · wh-url · alert-target
	input      textinput.Model
	confirmDel string
	msg        *setMessage
	busy       bool
	// installBusy is separate from busy: an install writes files and may spawn a
	// process, so it must not be cancelled by an unrelated row finishing.
	installBusy bool

	// repairReport is the last repair, rendered as read-only lines under the
	// repair row, the same two lists `solongate repair` prints. Cleared when a
	// new repair starts so the old result cannot be read as the new one.
	repairReport *install.Report

	// diag is the last doctor run, rendered as read-only lines under the row
	// that produced it. Kept here rather than printed: Bubble Tea owns the
	// terminal and writing to the stream would tear the frame.
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

// CapturingKeys covers the text prompts. It used to cover a pairing overlay too,
// during which the only key that meant anything was esc.
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

// readDisk refreshes the answers that come from this machine rather than the
// cloud: where local logging actually lands, whether the local-logs service is
// up, and whether the background updater is on.
func (p *Settings) readDisk() {
	p.llSetting = config.LocalLogsSetting()
}

// All three read this machine's own files. They used to be skipped while
// unpaired, because each was an HTTP call that needed a key; there is nothing
// left to skip.
func (p *Settings) reloadAll() tea.Cmd {
	return tea.Batch(p.loadLocal(), p.loadGuard(), p.loadSelf(), p.loadProtected())
}

// protectedLine is one path with the lock that is on it, read from the
// FILESYSTEM rather than from the policy file. The file records what somebody
// asked for; only the filesystem says what happened, and the gap between those
// two is the thing worth showing.
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
			// No row rather than an error row. An unreadable policy file is
			// already reported by three other things on this panel, and a
			// fourth copy of it pushes the ones that are not duplicates off
			// the screen.
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

// run is the one-shot action wrapper: it says what it is doing, then says what
// happened, and reloads whatever the action changed.
func (p *Settings) run(label string, fn func() error, reload string) tea.Cmd {
	return p.runHiding(label, fn, reload, "")
}

// runHiding is run() plus the row to remove the moment the API confirms. A
// deleted row has to vanish at once; without it the row lingered until the
// background reload caught up, which read as the delete not having worked.
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
			return p, nil // a previous mount's answer
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
			return p, nil // a previous mount's clock: let the chain end here
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
			// The step list is paced rather than instantaneous: the health check
			// usually answers in well under a second, and a screen that flashed
			// past would read as nothing having run.
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
		// The notes are the point of carrying them: an install that succeeded
		// while doing less than usual has to say so, or the machine looks freshly
		// protected and is not.
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

// ── rows ───────────────────────────────────────────────────────────────────

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