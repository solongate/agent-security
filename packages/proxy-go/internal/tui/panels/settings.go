package panels

import (
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/commands"
	"github.com/codeyevsky/solongate/proxy/internal/config"
	"github.com/codeyevsky/solongate/proxy/internal/install"
	"github.com/codeyevsky/solongate/proxy/internal/tui"
)

func init() { tui.Register(tui.SectionSettings, func(d tui.Deps) tui.Panel { return NewSettings(d) }) }

// The Settings panel, ported from tui/panels/Settings.tsx — the dashboard
// Settings page, dataroom edition. Everything an operator configures, in ONE
// single-cursor list:
//
//	ACCOUNTS   accounts logged in on this device: view · make active · add
//	           (device login, in-panel) · remove
//	PROTECTION the guard hook, self-protection, doctor and repair
//	           turned on: `npm i -g` needs sudo on most macOS setups, so it must
//	           not run unasked)
//	LOCAL LOGS where the hooks write this machine's audit trail
//
// Installing, updating and removing the guard, doctor, repair and the CLI
// self-update all run for real now, through internal/install, internal/commands
// and internal/selfupdate. They are commands rather than inline calls because
// each writes several files, unlocks and relocks them, and may spawn a process;
// doing that on the update goroutine would freeze the terminal for as long as
// the disk takes, and a frozen terminal during a guard install is
// indistinguishable from a hung one.
//
// They were stubs until those modules existed, and the stubs said so on the row
// rather than offering a button that quietly did nothing — the subject of every
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
		data api.LocalLogsConfig
		err  error
	}
	setGuardMsg struct {
		genTag
		data api.GuardStatus
		err  error
	}
	setSelfMsg struct {
		genTag
		data bool
		err  error
	}
	// setRunMsg is the answer to any one-shot action started by run(). hide is
	// the row key to drop on success — applied HERE rather than in the request
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
		checks []commands.Check
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

	local     api.LocalLogsConfig
	haveLocal bool
	localErr  error
	guard     api.GuardStatus
	haveGuard bool
	guardErr  error
	selfProt  bool
	haveSelf  bool
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
	// repair row — the same two lists `solongate repair` prints. Cleared when a
	// new repair starts so the old result cannot be read as the new one.
	repairReport *install.Report

	// diag is the last doctor run, rendered as read-only lines under the row
	// that produced it. Kept here rather than printed: Bubble Tea owns the
	// terminal and writing to the stream would tear the frame.
	diag     []commands.Check
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
	return tea.Batch(p.loadLocal(), p.loadGuard(), p.loadSelf())
}

func (p *Settings) loadLocal() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		c, err := p.deps.API.Settings.GetLocalLogs(bg())
		return setLocalMsg{genTag: t, data: c, err: err}
	}
}

func (p *Settings) loadGuard() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		g, err := p.deps.API.Settings.GetGuardStatus(bg())
		return setGuardMsg{genTag: t, data: g, err: err}
	}
}

func (p *Settings) loadSelf() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		v, err := p.deps.API.Settings.GetSelfProtection(bg())
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
			case commands.StateFail:
				bad++
			case commands.StateWarn:
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
	for _, k := range []string{"guard", "self", "doctor", "repair", "ll-enabled", "ll-path"} {
		rows = append(rows, setRow{kind: k})
	}
	return rows
}

func (p *Settings) current() setRow {
	rows := p.allRows()
	return rows[min(p.sel, len(rows)-1)]
}

// ── keys ───────────────────────────────────────────────────────────────────

func (p *Settings) key(k tea.KeyMsg) tea.Cmd {
	s := k.String()

	if p.editing != "" {
		// esc abandons the prompt without writing. It is not in the Ink version,
		// and it has to be here: the shell gives a capturing panel every key, so
		// the only other way out of the path prompt would be to submit it — and
		// submitting an empty path CLEARS local logging.
		if s == "esc" {
			p.editing = ""
			p.input.Blur()
			return nil
		}
		if s != "enter" {
			var cmd tea.Cmd
			p.input, cmd = p.input.Update(k)
			return cmd
		}
		return p.submitInput()
	}

	rows := p.allRows()
	cur := p.current()
	p.msg = nil

	switch {
	case s == "up":
		p.sel = max(0, p.sel-1)
		p.confirmDel = ""
	case s == "down":
		p.sel = min(len(rows)-1, p.sel+1)
		p.confirmDel = ""
	case s == "enter" || s == " ":
		return p.activate(cur)
	case s == "m" && (cur.kind == "self" || cur.kind == "ll-enabled"):
		return p.activate(cur)
	case s == "e" && cur.kind == "ll-path":
		return p.activate(cur)
	case s == "d" && cur.kind == "guard":
		if p.installBusy {
			return nil
		}
		p.installBusy = true
		p.msg = &setMessage{text: "removing the guard from this device…"}
		t := p.tag()
		return tea.Batch(
			tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return setSpinMsg{t} }),
			func() tea.Msg {
				r := install.Uninstall()
				return setInstallMsg{genTag: t, verb: "remove", ok: r.OK, message: r.Message, notes: r.Notes}
			},
		)
	case s == "r":
		p.readDisk()
		return p.reloadAll()
	}
	return nil
}

func (p *Settings) beginInput(value string) {
	p.input.SetValue(value)
	p.input.CursorEnd()
	p.input.Focus()
}

// activate is what enter does to the row under the cursor.
func (p *Settings) activate(r setRow) tea.Cmd {
	switch r.kind {
	case "guard":
		if p.installBusy {
			return nil
		}
		p.installBusy = true
		p.msg = &setMessage{text: "installing the guard…"}
		t := p.tag()
		return tea.Batch(
			tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return setSpinMsg{t} }),
			func() tea.Msg {
				r := install.Install()
				return setInstallMsg{genTag: t, verb: "install", ok: r.OK, message: r.Message, notes: r.Notes}
			},
		)

	case "doctor":
		if p.diagBusy {
			return nil
		}
		p.diagBusy = true
		p.diagStep = 0
		p.diag = nil
		p.msg = nil
		client := p.deps.API
		t := p.tag()
		return tea.Batch(
			tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return setSpinMsg{t} }),
			func() tea.Msg { return setDoctorMsg{genTag: t, checks: commands.CollectChecks(bg(), client)} },
		)

	case "repair":
		if p.installBusy {
			return nil
		}
		p.installBusy = true
		p.repairReport = nil
		p.msg = &setMessage{text: "restoring the protection files…"}
		t := p.tag()
		return tea.Batch(
			tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return setSpinMsg{t} }),
			func() tea.Msg {
				r := install.Repair()
				return setInstallMsg{genTag: t, verb: "repair", ok: r.OK, message: r.Message, notes: r.Notes, repair: &r}
			},
		)

	case "self":
		if !p.haveSelf {
			return nil
		}
		want := !p.selfProt
		label := "self-protection enabled"
		if !want {
			label = "self-protection disabled"
		}
		return p.run(label, func() error {
			_, err := p.deps.API.Settings.SetSelfProtection(bg(), want)
			return err
		}, "self")

	case "ll-enabled":
		if !p.haveLocal {
			return nil
		}
		if !p.local.Enabled && strings.TrimSpace(p.local.Path) == "" {
			p.msg = &setMessage{text: "set a path first (↓ then enter)", bad: true}
			return nil
		}
		want := !p.local.Enabled
		label := "local logs enabled"
		if !want {
			label = "local logs disabled"
		}
		path := p.local.Path
		return p.run(label, func() error {
			_, err := p.deps.API.Settings.SetLocalLogs(bg(), api.LocalLogsConfig{Enabled: want, Path: path})
			return err
		}, "local")

	case "ll-path":
		p.editing = "path"
		p.beginInput(p.local.Path)

	}
	return nil
}

func (p *Settings) submitInput() tea.Cmd {
	v := strings.TrimSpace(p.input.Value())
	which := p.editing
	p.editing = ""
	p.input.Blur()

	switch which {
	case "path":
		enabled := p.haveLocal && p.local.Enabled && v != ""
		label := "path cleared (local logs off)"
		if v != "" {
			label = "path saved"
			if !enabled {
				label += " (press enter on enabled to turn on)"
			}
		}
		return p.run(label, func() error {
			_, err := p.deps.API.Settings.SetLocalLogs(bg(), api.LocalLogsConfig{Enabled: enabled, Path: v})
			return err
		}, "local")

	}
	return nil
}

// ── render ─────────────────────────────────────────────────────────────────

func onOff(on bool) (string, lipgloss.Style) {
	if on {
		return "on ", stOK
	}
	return "off", stDim
}

func (p *Settings) View(ctx tui.PanelContext) string {
	p.apply(ctx)
	return clip(p.viewList(), p.cols, p.rows)
}

func (p *Settings) firstError() error {
	for _, e := range []error{p.localErr, p.guardErr, p.selfErr} {
		if e != nil {
			return e
		}
	}
	return nil
}

// authErrorShape matched an error worth keeping the panel open for: every loader here
// spoke to a service, and a revoked key 401'd all of them at once. Rendering that
// error INSTEAD of the rows hid the Accounts section — the only way to remove the dead
// account and pair again — so a device revoked from the dashboard was stuck being told
// to use a panel it could not see.
//
// Nothing 401s. The loaders read a file, and the two failures a file has (absent,
// unparseable) are already the ordinary error path below.

func (p *Settings) viewList() string {
	loading := !p.haveLocal && !p.haveGuard && !p.haveSelf && p.firstError() == nil
	raw := p.firstError()

	err := raw
	if err != nil || loading {
		return dataView(loading, err, false, "", "")
	}

	rows := p.allRows()
	cur := p.current()
	curKey := cur.key()

	// Rows and their section headers are flattened into ONE line list, then
	// windowed around the selected row. Anything that is not selectable — a
	// header, a warning, the version at the bottom — carries an empty key.
	type flat struct {
		text string
		key  string
	}
	var lines []flat
	push := func(text, key string) { lines = append(lines, flat{text, key}) }

	lastSec := ""
	for _, r := range rows {
		sec := sectionOf(r)
		if sec != lastSec {
			if lastSec != "" {
				push(" ", "")
			}
			lastSec = sec
			push(stAccentB.Render(sec)+stDim.Render("  — "+p.sectionDesc(sec)), "")
			// Cloud notifications fire server-side off the cloud audit POST,
			// which the guard SKIPS in local-log mode. Say so, or it is a silent
			// no-op; the webhook test still delivers, because it posts directly.
			if (sec == "WEBHOOKS" || sec == "ALERTS") && p.haveLocal && p.local.Enabled {
				extra := ""
				if sec == "WEBHOOKS" {
					extra = " (t test still works)"
				}
				push(stWarn.Render("  ⚠ local logs on — real denials stay on this machine, so "+
					strings.ToLower(sec)+" do NOT fire"+extra), "")
			}
		}
		push(p.rowLine(r, r.key() == curKey && p.focused), r.key())

		// The repair's two lists, under the row that produced them, in the same
		// shape and order `solongate repair` prints. Not selectable.
		if r.kind == "repair" && p.repairReport != nil {
			rep := p.repairReport
			if len(rep.Before) > 0 {
				push(stDim.Render("    before:"), "")
				for _, l := range rep.Before {
					st := stOK
					if !l.OK {
						st = stBad
					}
					push(st.Render("      "+pad(l.Label, 20)+" "+l.Detail), "")
				}
			}
			if len(rep.After) > 0 {
				push(stDim.Render("    restored:"), "")
				for _, l := range rep.After {
					// A client the repair could not register is the one line worth
					// colouring: the run succeeded and that client is still
					// unguarded.
					st := stOK
					if !l.OK {
						st = stWarn
					}
					push(st.Render("      "+pad(l.Label, 20)+" "+l.Detail), "")
				}
			}
			for _, n := range rep.Notes {
				push(stDim.Render("      "+n), "")
			}
		}

		if r.kind == "doctor" {
			// While the check runs, the step list stands in for the result:
			// finished steps tick, the current one spins, the rest sit dim.
			if p.diagBusy {
				for i, label := range doctorSteps {
					mark, st := " ", stDim
					switch {
					case i < p.diagStep:
						mark, st = "✓", stOK
					case i == p.diagStep:
						mark, st = spinFrames[p.spin%len(spinFrames)], stAccent
					}
					push(st.Render("      "+mark+" "+label), "")
				}
			}
			// The last run's rows sit under the row that produced them, and are
			// not selectable.
			for _, c := range p.diag {
				mark, st := "✗", stBad
				switch c.OK {
				case commands.StateOK:
					mark, st = "✓", stOK
				case commands.StateWarn:
					mark, st = "!", stWarn
				}
				push(st.Render("    "+mark+" "+pad(c.Name, 16)+" "+c.Detail), "")
			}
		}
	}

	// The version sits at the very bottom of the scrollable list.
	push(" ", "")
	push(stDim.Render("solongate v"+Version), "")

	// hint + status take one line each. The panel must not grow past its box.
	//
	// A third line used to be reserved when the auth banner was showing. There is no
	// banner: nothing here can fail with a credential error.
	budget := max(4, p.rows-2)
	selLine := 0
	for i, l := range lines {
		if l.key == curKey {
			selLine = i
			break
		}
	}
	texts := make([]string, len(lines))
	for i, l := range lines {
		texts[i] = l.text
	}
	win, above, below := window(texts, selLine, budget)

	var out []string
	hint := "press → to configure"
	if p.focused {
		hint = "↑↓ move · enter act · m toggle · t test · e edit · x remove · d delete · n add" + scrollTag(above, below)
	}
	out = append(out, stDim.Render(hint))

	switch {
	case p.editing != "":
		prompt := "webhook url: "
		if p.editing == "path" {
			prompt = "local log path: "
		}
		out = append(out, stWarn.Render(prompt)+p.input.View())
	case p.msg != nil:
		st := stOK
		if p.msg.bad {
			st = stBad
		}
		out = append(out, st.Render(truncate(p.msg.text, p.cols)))
	default:
		out = append(out, " ")
	}

	out = append(out, win...)
	return joinLines(out)
}

func sectionOf(r setRow) string {
	switch r.kind {
	case "guard", "self", "doctor", "repair":
		return "PROTECTION"
	}
	return "LOCAL LOGS"
}

func (p *Settings) sectionDesc(sec string) string {
	switch sec {
	case "PROTECTION":
		return "guard hook, self-protection, doctor and repair"
	}
	return "where the hooks write this machine's audit trail"
}

func (p *Settings) rowLine(r setRow, isCur bool) string {
	l := newLine(false)
	if isCur {
		l.put("▸ ", stAccent)
	} else {
		l.put("  ", stDim)
	}
	spin := spinFrames[p.spin%len(spinFrames)]
	_ = spin

	switch r.kind {
	case "guard":
		l.put(pad("guard", 11), stDim)
		if !p.haveGuard {
			l.put("…", stDim)
			break
		}
		// The cloud's view: the newest hook, what this project's devices last
		// reported, and how many are behind. The LOCAL truth — which hook files
		// this device actually has — is what `doctor` reads, and enter on this
		// row installs through the same code path `solongate repair` uses.
		installed := "unknown"
		st := stWarn
		if p.guard.Installed != nil {
			installed = "v" + itoa(*p.guard.Installed)
			if p.guard.UpToDate {
				st = stOK
			}
		}
		l.put(installed, st)
		l.put("  latest v"+itoa(p.guard.Latest)+" · "+itoa(p.guard.DeviceCount)+" device(s), "+
			itoa(p.guard.OutdatedCount)+" outdated (cloud)", stDim)
		l.put(" · enter installs · d removes", stDim)

	case "self":
		l.put(pad("self-prot", 11), stDim)
		if p.haveSelf {
			txt, st := onOff(p.selfProt)
			l.put(txt, st)
		} else {
			l.put("…", stDim)
		}
		l.put("   blocks agents editing SolonGate's own hooks/config · enter toggles", stDim)

	case "doctor":
		l.put(pad("doctor", 11), stDim)
		if p.diagBusy {
			l.put(spinFrames[p.spin%len(spinFrames)]+" running health check…", stAccent)
		} else {
			l.put("health check: login, policy, guard, hooks, local logs · enter runs it", stDim)
		}

	case "repair":
		l.put(pad("repair", 11), stDim)
		l.put("restore every protection file after tampering or deletion", stDim)
		l.put(" · enter runs it", stDim)

	case "ll-enabled":
		l.put(pad("enabled", 11), stDim)
		txt, st := onOff(p.haveLocal && p.local.Enabled)
		l.put(txt, st)
		l.put("   enter toggles", stDim)

	case "ll-path":
		l.put(pad("path", 11), stDim)
		switch {
		case !p.haveLocal || p.local.Path == "":
			l.put("not set — enter to edit", stDim)
		case p.local.Enabled && !p.llSetting.UsableHere:
			// The folder is a PROJECT setting shared by every device on it, so
			// it can name a path that only exists on another OS. The hooks then
			// quietly fall back, and this row was the last place still claiming
			// the configured path was in use.
			half := max(12, (p.cols-20)/2)
			l.put(truncate(p.local.Path, half), stWarn)
			l.put("  not valid here → "+truncate(p.llSetting.File, half), stDim)
		default:
			l.put(truncate(p.local.Path, max(8, p.cols-14)), stAccent)
		}

	}
	return l.String()
}

// errString is a message that is already the whole error. errors.New would do,
// but this keeps the import list of this file to what it actually needs.
type errString string

func (e errString) Error() string { return string(e) }
