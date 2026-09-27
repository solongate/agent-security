package panels

import (
	"os"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/commands"
	"github.com/codeyevsky/solongate/proxy/internal/config"
	"github.com/codeyevsky/solongate/proxy/internal/install"
	"github.com/codeyevsky/solongate/proxy/internal/logsserver"
	"github.com/codeyevsky/solongate/proxy/internal/selfupdate"
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
//	UPDATES    this CLI's version, and the background auto-updater (off unless
//	           turned on: `npm i -g` needs sudo on most macOS setups, so it must
//	           not run unasked)
//	LOCAL LOGS mirror path and enable, plus the dashboard link
//	WEBHOOKS   POST every matching event to a URL
//	ALERTS     spike alerts to ONE email and ONE telegram
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

var setEvents = []string{"denials", "allowed", "all"}

type alertSignal = string

var (
	setSignals     = []alertSignal{"any", "deny", "dlp", "ratelimit"}
	setSignalLabel = map[alertSignal]string{
		"any": "any signal", "deny": "denials", "dlp": "dlp secrets", "ratelimit": "rate-limit",
	}
	setWindows = []int{30, 60, 300, 3600, 86400}
)

const (
	threshMin = 5
	threshMax = 100
)

// doctorSteps is what the health check looks at, in the order CollectChecks
// looks at it. The labels are honest about the passes; only the pacing is
// cosmetic, and it exists because a check that answers in 8ms would otherwise
// flash past unread and look like nothing ran.
var doctorSteps = []string{"login", "active policy", "guard hook", "agent hooks", "local logs"}

func winLabel(s int) string {
	switch {
	case s < 60:
		return itoa(s) + "s"
	case s < 3600:
		return itoa(s/60) + "m"
	case s < 86400:
		return itoa(s/3600) + "h"
	}
	return itoa(s/86400) + "d"
}

func nearestWindowIdx(s int) int {
	best := 0
	for i := 1; i < len(setWindows); i++ {
		if abs(setWindows[i]-s) < abs(setWindows[best]-s) {
			best = i
		}
	}
	return best
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// ── rows ───────────────────────────────────────────────────────────────────

type setRow struct {
	kind string
	acc  config.SavedAccount
	wh   api.DenialWebhook
	rule api.AlertRule
	ws   api.Workspace
}

func (r setRow) key() string {
	switch r.kind {
	case "acct":
		return "acct:" + r.acc.APIKey
	case "wh":
		return "wh:" + r.wh.ID
	case "alert":
		return "alert:" + r.rule.ID
	case "ws":
		return "ws:" + r.ws.ID
	}
	return r.kind
}

// alertEditor is the small focused form for one alert rule, new or existing.
type alertEditor struct {
	id      string // set = editing an existing rule
	channel string // email · telegram
	target  string
	signal  alertSignal
	thresh  int
	window  int
	enabled bool
	field   int // 0 target · 1 signal · 2 threshold · 3 window · 4 status
}

// A new rule has four fields; an existing one gets a fifth so it can be turned
// off from the same place it is edited.
func (e alertEditor) fieldCount() int {
	if e.id != "" {
		return 5
	}
	return 4
}

type loginPhase string

const (
	loginNone     loginPhase = ""
	loginStarting loginPhase = "starting"
	loginWaiting  loginPhase = "waiting"
	loginDone     loginPhase = "done"
	loginError    loginPhase = "error"
)

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
	setSpacesMsg struct {
		genTag
		data []api.Workspace
		err  error
	}
	setSwitchedMsg struct {
		genTag
		key string
		ws  api.Workspace
		err error
	}
	setWhMsg struct {
		genTag
		data []api.DenialWebhook
		err  error
	}
	setAlertsMsg struct {
		genTag
		data []api.AlertRule
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
	setLoginStartMsg struct {
		genTag
		token int
		start api.DeviceStart
		err   error
	}
	setLoginPollMsg struct {
		genTag
		token int
		res   api.DevicePoll
	}
	setLoginTickMsg struct {
		genTag
		token int
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
	viewKey    string

	accounts []config.SavedAccount

	// The workspaces this account owns, and which one this machine is in.
	//
	// A CLI SAW ONE WORKSPACE AND HAD NO WORD FOR THE REST. A machine pairs
	// once and every screen here belongs to whichever project the pairing landed
	// on; somebody with two of them had to remove the account and add it again
	// to see the second, which also moved what the guard on this machine
	// enforces. The list is read from the cloud because the key is what knows
	// who the owner is - nothing on disk does.
	spaces    []api.Workspace
	haveSpace bool
	spaceErr  error
	// spaceNow is the id of the workspace the viewing key is for, which the API
	// does not label in the list: it is the one this machine's own project row
	// matches by name, and after a switch it is the one that was switched to.
	spaceNow string

	local     api.LocalLogsConfig
	haveLocal bool
	localErr  error
	whs       []api.DenialWebhook
	haveWh    bool
	whErr     error
	alerts    []api.AlertRule
	haveAlert bool
	alertErr  error
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
	srvState  config.LogsServerState
	srvUp     bool
	autoUp    bool

	sel        int
	editing    string // "" · path · wh-url · alert-target
	input      textinput.Model
	confirmDel string
	msg        *setMessage
	busy       bool
	// installBusy is separate from busy: an install writes files and may spawn a
	// process, so it must not be cancelled by an unrelated row finishing.
	installBusy bool
	editor      *alertEditor

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

	login      loginPhase
	loginURL   string
	loginMsg   string
	loginToken int
	loginStart api.DeviceStart
	spin       int
}

func NewSettings(d tui.Deps) *Settings {
	ti := textinput.New()
	ti.Prompt = ""
	return &Settings{
		deps:     d,
		cols:     60,
		rows:     12,
		hidden:   map[string]bool{},
		input:    ti,
		tok:      nextToken(),
		accounts: config.ListAccounts(),
		autoUp:   config.LoadSelfUpdateState().Auto,
	}
}

var _ tui.Panel = (*Settings)(nil)

// CapturingKeys covers both the text prompts and the pairing overlay: during a
// device login the only key that means anything is esc, and the shell must not
// read `q` as quit while a browser round trip is in flight.
func (p *Settings) CapturingKeys() bool { return p.editing != "" || p.loginActive() }

func (p *Settings) apply(ctx tui.PanelContext) {
	p.cols, p.rows, p.focused, p.gen, p.viewKey = ctx.Cols, ctx.Rows, ctx.Focused, ctx.Gen, ctx.ViewAPIKey
}

func (p *Settings) tag() genTag { return genTag{gen: p.gen, tok: p.tok} }

func (p *Settings) loginActive() bool { return p.login == loginStarting || p.login == loginWaiting }

func (p *Settings) locked() bool { return len(p.accounts) == 0 }

func (p *Settings) Init(ctx tui.PanelContext) tea.Cmd {
	p.apply(ctx)
	p.accounts = config.ListAccounts()
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
	p.srvState = config.LoadLogsServerState()
	p.srvUp = pidAlive(p.srvState.Pid)
	p.autoUp = config.LoadSelfUpdateState().Auto
}

func (p *Settings) reloadAll() tea.Cmd {
	p.accounts = config.ListAccounts()
	if p.locked() {
		// No key, nothing to ask the cloud with. Every cloud row is inert while
		// unpaired and the panel still renders, because logging in happens here.
		return nil
	}
	return tea.Batch(p.loadLocal(), p.loadWebhooks(), p.loadAlerts(), p.loadGuard(), p.loadSelf(), p.loadSpaces())
}

// viewingAccount is the account this panel's cloud rows belong to: the one the
// shell is viewing, or the first on the device when nothing has been chosen -
// the same rule the account row's ● uses, so the two cannot disagree about
// whose workspaces are being listed.
func (p *Settings) viewingAccount() config.SavedAccount {
	if p.viewKey != "" {
		for _, a := range p.accounts {
			if a.APIKey == p.viewKey {
				return a
			}
		}
	}
	if len(p.accounts) > 0 {
		return p.accounts[0]
	}
	return config.SavedAccount{}
}

func (p *Settings) loadSpaces() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		w, err := p.deps.API.Projects.List(bg())
		return setSpacesMsg{genTag: t, data: w, err: err}
	}
}

// switchSpace mints a key for another workspace and stores it against this
// account.
//
// THE GUARD FOLLOWS, and that is the point rather than a side effect: a machine
// is IN a workspace, and enforcing one project's policy while the dataroom shows
// another's would be two answers to one question. It is the same
// revoke-then-mint pairing does, so nothing is left live in the workspace being
// left.
func (p *Settings) switchSpace(id string) tea.Cmd {
	t := p.tag()
	p.busy = true
	return func() tea.Msg {
		key, ws, err := p.deps.API.Projects.Switch(bg(), id)
		return setSwitchedMsg{genTag: t, key: key, ws: ws, err: err}
	}
}

func (p *Settings) loadLocal() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		c, err := p.deps.API.Settings.GetLocalLogs(bg())
		return setLocalMsg{genTag: t, data: c, err: err}
	}
}

func (p *Settings) loadWebhooks() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		w, err := p.deps.API.Settings.GetWebhooks(bg())
		return setWhMsg{genTag: t, data: w, err: err}
	}
}

func (p *Settings) loadAlerts() tea.Cmd {
	t := p.tag()
	return func() tea.Msg {
		a, err := p.deps.API.Settings.GetAlerts(bg())
		return setAlertsMsg{genTag: t, data: a, err: err}
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
	case "wh":
		return p.loadWebhooks()
	case "alert":
		return p.loadAlerts()
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
	case setSpacesMsg:
		p.spaceErr = m.err
		if m.err == nil {
			p.spaces, p.haveSpace = m.data, true
			// Which one this machine is in, when nothing has been switched yet:
			// the account row records the workspace NAME the pairing wrote, and
			// that is all there is to match on.
			if p.spaceNow == "" {
				for _, ws := range m.data {
					if ws.Name != "" && ws.Name == p.viewingAccount().Project {
						p.spaceNow = ws.ID
					}
				}
			}
		}
	case setSwitchedMsg:
		p.busy = false
		if m.err != nil {
			p.msg = &setMessage{text: "✗ " + errText(m.err), bad: true}
			return p, nil
		}
		p.spaceNow = m.ws.ID
		acc := p.viewingAccount()
		next := config.SavedAccount{
			APIKey: m.key, APIURL: acc.APIURL, Project: m.ws.Name,
			User: acc.User, Email: acc.Email,
		}
		if next.APIURL == "" {
			next.APIURL = config.DefaultAPIURL
		}
		// The account this machine had for the workspace it just left is gone:
		// its key was revoked by the mint, so keeping the row would leave a
		// dead credential in the list somebody could make active.
		config.RemoveAccount(acc.APIKey)
		config.SaveAccount(next)
		if config.IsActiveAccount(acc.APIKey) {
			// The guard was enforcing with the old key, which no longer
			// authenticates. Moving it is what keeps this machine in ONE
			// workspace rather than reading one and enforcing another.
			config.SetActiveAccount(config.Credential{APIKey: next.APIKey, APIURL: next.APIURL})
		}
		p.msg = &setMessage{text: "✓ now in " + m.ws.Name}
		return p, tea.Batch(
			p.reloadAll(),
			func() tea.Msg { return tui.ViewAccountMsg{APIKey: next.APIKey, APIURL: next.APIURL} },
		)
	case setWhMsg:
		p.whErr = m.err
		if m.err == nil {
			p.whs, p.haveWh = m.data, true
		}
	case setAlertsMsg:
		p.alertErr = m.err
		if m.err == nil {
			p.alerts, p.haveAlert = m.data, true
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
		p.accounts = config.ListAccounts()
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
		if p.loginActive() || p.busy || p.diagBusy {
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

	case setLoginStartMsg:
		if m.tok != p.tok || m.token != p.loginToken {
			return p, nil
		}
		if m.err != nil {
			p.login = loginError
			p.loginMsg = "could not reach SolonGate: " + errText(m.err)
			return p, nil
		}
		p.login = loginWaiting
		p.loginStart = m.start
		p.loginURL = m.start.VerifyURL
		api.OpenBrowser(m.start.VerifyURL)
		t, token := p.tag(), m.token
		return p, tea.Tick(m.start.Interval, func(time.Time) tea.Msg {
			return setLoginTickMsg{genTag: t, token: token}
		})

	case setLoginTickMsg:
		if m.tok != p.tok || m.token != p.loginToken || p.login != loginWaiting {
			return p, nil
		}
		if time.Now().After(p.loginStart.ExpiresAt) {
			p.login = loginError
			p.loginMsg = "timed out — press n to retry"
			return p, nil
		}
		code := p.loginStart.DeviceCode
		t := p.tag()
		return p, func() tea.Msg {
			return setLoginPollMsg{genTag: t, token: m.token, res: p.deps.API.Device.Poll(bg(), config.DefaultAPIURL, code)}
		}

	case setLoginPollMsg:
		if m.tok != p.tok || m.token != p.loginToken || p.login != loginWaiting {
			return p, nil
		}
		return p, p.onLoginPoll(m)

	case tea.KeyMsg:
		if !p.focused {
			return p, nil
		}
		return p, p.key(m)
	}
	return p, nil
}

func (p *Settings) onLoginPoll(m setLoginPollMsg) tea.Cmd {
	switch m.res.Status {
	case api.DeviceApproved:
		acc := config.SavedAccount{
			APIKey: m.res.APIKey, APIURL: config.DefaultAPIURL,
			Project: m.res.Project, User: m.res.User, Email: m.res.Email,
		}
		config.SaveAccount(acc)
		p.login = loginDone
		label := m.res.Email
		if label == "" {
			label = m.res.User
		}
		if label == "" {
			label = m.res.Project
		}
		if label == "" {
			label = "account"
		}
		p.loginMsg = "✓ added " + label
		// The dataroom starts VIEWING the account that was just added; the shell
		// re-points the client and remounts. The active (enforcing) key is a
		// separate decision, made with `m`.
		return tea.Batch(
			p.reloadAll(),
			func() tea.Msg { return tui.ViewAccountMsg{APIKey: acc.APIKey, APIURL: acc.APIURL} },
		)

	case api.DeviceExpired, api.DeviceNotFound:
		p.login = loginError
		p.loginMsg = "code expired — press n to retry"
		return nil
	}
	t, token := p.tag(), p.loginToken
	return tea.Tick(p.loginStart.Interval, func(time.Time) tea.Msg {
		return setLoginTickMsg{genTag: t, token: token}
	})
}

// ── rows ───────────────────────────────────────────────────────────────────

func alertChannel(r api.AlertRule) string {
	if len(r.Emails) > 0 {
		return "email"
	}
	if len(r.Telegram) > 0 {
		return "telegram"
	}
	return ""
}

func (p *Settings) visibleWebhooks() []api.DenialWebhook {
	out := make([]api.DenialWebhook, 0, len(p.whs))
	for _, w := range p.whs {
		if !p.hidden["wh:"+w.ID] {
			out = append(out, w)
		}
	}
	return out
}

func (p *Settings) visibleAlerts() []api.AlertRule {
	out := make([]api.AlertRule, 0, len(p.alerts))
	for _, r := range p.alerts {
		if !p.hidden["alert:"+r.ID] {
			out = append(out, r)
		}
	}
	return out
}

func (p *Settings) allRows() []setRow {
	var rows []setRow
	for _, a := range p.accounts {
		rows = append(rows, setRow{kind: "acct", acc: a})
	}
	rows = append(rows, setRow{kind: "acct-add"})
	if p.locked() {
		return rows
	}
	// Only when there is more than one. A section listing the single workspace
	// this account has answers a question nobody asked and puts a control under
	// the cursor that cannot do anything.
	if len(p.spaces) > 1 {
		for _, ws := range p.spaces {
			rows = append(rows, setRow{kind: "ws", ws: ws})
		}
	}
	for _, k := range []string{"guard", "self", "doctor", "repair", "cli-update", "auto-update", "ll-enabled", "ll-path", "ll-server"} {
		rows = append(rows, setRow{kind: k})
	}
	for _, w := range p.visibleWebhooks() {
		rows = append(rows, setRow{kind: "wh", wh: w})
	}
	rows = append(rows, setRow{kind: "wh-add"})
	alerts := p.visibleAlerts()
	hasEmail, hasTG := false, false
	for _, r := range alerts {
		rows = append(rows, setRow{kind: "alert", rule: r})
		switch alertChannel(r) {
		case "email":
			hasEmail = true
		case "telegram":
			hasTG = true
		}
	}
	// One channel each: the add row disappears once that channel is in use, so
	// the panel cannot grow a second email alert nobody asked for.
	if !hasEmail {
		rows = append(rows, setRow{kind: "alert-add-email"})
	}
	if !hasTG {
		rows = append(rows, setRow{kind: "alert-add-tg"})
	}
	return rows
}

func (p *Settings) current() setRow {
	rows := p.allRows()
	if len(rows) == 0 {
		return setRow{kind: "acct-add"}
	}
	return rows[min(p.sel, len(rows)-1)]
}

// ── keys ───────────────────────────────────────────────────────────────────

func (p *Settings) key(k tea.KeyMsg) tea.Cmd {
	s := k.String()

	// While pairing, only esc is live: it cancels.
	if p.loginActive() {
		if s == "esc" {
			p.loginToken++
			p.login = loginNone
			p.loginMsg = ""
		}
		return nil
	}

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

	if p.editor != nil {
		return p.editorKey(s)
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
	case s == "m":
		return p.makeActive(cur)
	case s == "x" && cur.kind == "acct":
		return p.removeAccount(cur.acc)
	case s == "t" && cur.kind == "wh":
		id := cur.wh.ID
		return p.run("webhook test sent — check your endpoint", func() error {
			delivered, err := p.deps.API.Settings.SendTestWebhook(bg(), id)
			if err != nil {
				return err
			}
			if !delivered {
				return errString("endpoint rejected the test (non-2xx)")
			}
			return nil
		}, "wh")
	case s == "e" && cur.kind == "ll-path":
		return p.activate(cur)
	case s == "e" && cur.kind == "wh":
		idx := 0
		for i, ev := range setEvents {
			if ev == cur.wh.Events {
				idx = i
			}
		}
		next := setEvents[(idx+1)%len(setEvents)]
		id := cur.wh.ID
		return p.run("webhook events → "+next, func() error {
			return p.deps.API.Settings.UpdateWebhook(bg(), id, map[string]any{"events": next})
		}, "wh")
	case s == "e" && cur.kind == "alert":
		if ch := alertChannel(cur.rule); ch != "" {
			p.openAlertEditor(ch, &cur.rule)
		}
	case s == "n":
		return p.beginLogin()
	case s == "a":
		switch cur.kind {
		case "wh", "wh-add":
			p.editing = "wh-url"
			p.beginInput("")
		case "alert-add-email":
			p.openAlertEditor("email", nil)
		case "alert-add-tg":
			p.openAlertEditor("telegram", nil)
		}
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
	case s == "d" && (cur.kind == "wh" || cur.kind == "alert"):
		key := cur.key()
		if p.confirmDel != key {
			p.confirmDel = key
			p.msg = &setMessage{text: "press d again to delete", bad: true}
			return nil
		}
		p.confirmDel = ""
		if cur.kind == "wh" {
			id := cur.wh.ID
			return p.runHiding("webhook deleted", func() error {
				return p.deps.API.Settings.DeleteWebhook(bg(), id)
			}, "wh", "wh:"+id)
		}
		id := cur.rule.ID
		return p.runHiding("alert deleted", func() error {
			return p.deps.API.Settings.DeleteAlert(bg(), id)
		}, "alert", "alert:"+id)
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
	case "acct":
		acc := r.acc
		p.msg = &setMessage{text: "viewing " + acctLabel(acc)}
		return func() tea.Msg { return tui.ViewAccountMsg{APIKey: acc.APIKey, APIURL: acc.APIURL} }

	case "acct-add":
		return p.beginLogin()

	case "ws":
		// The workspace this machine is already in is not a move, and doing the
		// round trip anyway would revoke and re-mint a working key to arrive
		// exactly where it started.
		if r.ws.ID == p.spaceNow || p.busy {
			return nil
		}
		p.msg = &setMessage{text: "moving to " + r.ws.Name + "…"}
		return p.switchSpace(r.ws.ID)

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

	case "cli-update":
		if p.installBusy {
			return nil
		}
		p.installBusy = true
		p.msg = &setMessage{text: "checking for an update…"}
		t := p.tag()
		return tea.Batch(
			tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return setSpinMsg{t} }),
			func() tea.Msg {
				st := selfupdate.UpdateNow(bg())
				ok := st.Kind != selfupdate.KindFailed && st.Kind != selfupdate.KindNeedsAdmin
				return setInstallMsg{genTag: t, verb: "update", ok: ok, message: updateLine(st)}
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

	case "auto-update":
		if autoUpdateForcedByEnv() {
			p.msg = &setMessage{text: "SOLONGATE_AUTO_UPDATE is set — unset it to change this here", bad: true}
			return nil
		}
		next := !p.autoUp
		st := config.LoadSelfUpdateState()
		st.Auto = next
		if err := config.SaveSelfUpdateState(st); err != nil {
			p.msg = &setMessage{text: "✗ could not save the setting: " + errText(err), bad: true}
			return nil
		}
		p.autoUp = next
		if next {
			// Honest about the half of this that is missing: the flag is what
			// the npm package's background updater reads, and this binary has
			// no updater of its own yet.
			p.msg = &setMessage{text: "✓ auto-update on — the npm package installs new versions in the background", bad: false}
		} else {
			p.msg = &setMessage{text: "✓ auto-update off — update with: npx @solongate/proxy update"}
		}

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

	case "ll-server":
		// This row is the ONLY place a user can turn the service off for good.
		// Everything else about it is designed to bring it back: closing the
		// dataroom, closing the terminal and rebooting only kill the process,
		// and the next CLI run restarts it. So stopping here disables as well.
		if p.srvUp {
			logsserver.Stop()
			p.srvState, p.srvUp = config.LoadLogsServerState(), false
			p.msg = &setMessage{text: "✓ dashboard link stopped and disabled"}
		} else {
			st := logsserver.Start()
			p.srvState, p.srvUp = config.LoadLogsServerState(), st.Running
			if st.Running {
				p.msg = &setMessage{text: "✓ dashboard link on 127.0.0.1:" + itoa(st.Port)}
			} else {
				// The daemon writes its own reason to a log rather than to
				// this frame, which Bubble Tea owns.
				p.msg = &setMessage{text: "✗ could not start it — see " + config.LogsServerLogPath(), bad: true}
			}
		}

	case "wh":
		want := !r.wh.Enabled
		label := "webhook enabled"
		if !want {
			label = "webhook disabled"
		}
		id := r.wh.ID
		return p.run(label, func() error {
			return p.deps.API.Settings.UpdateWebhook(bg(), id, map[string]any{"enabled": want})
		}, "wh")

	case "wh-add":
		p.editing = "wh-url"
		p.beginInput("")

	case "alert":
		if ch := alertChannel(r.rule); ch != "" {
			p.openAlertEditor(ch, &r.rule)
		}

	case "alert-add-email":
		p.openAlertEditor("email", nil)

	case "alert-add-tg":
		p.openAlertEditor("telegram", nil)
	}
	return nil
}

// makeActive is `m`: on an account it changes which key the GUARD enforces
// with; on a toggle row it is another way to press enter.
func (p *Settings) makeActive(r setRow) tea.Cmd {
	switch r.kind {
	case "acct":
		ok := config.SetActiveAccount(config.Credential{APIKey: r.acc.APIKey, APIURL: r.acc.APIURL})
		if ok {
			// The machine-local log is one file per device and carries no
			// account, so what is already in it belongs to whoever was active
			// before. Re-owning it separates the history instead of showing
			// another account's calls under this one.
			config.EnsureLocalLogOwner(r.acc.APIKey)
			p.deps.API.Invalidate()
			p.msg = &setMessage{text: "✓ " + acctLabel(r.acc) + " is now the ACTIVE key (guard + logging)"}
		} else {
			p.msg = &setMessage{text: "✗ could not set active", bad: true}
		}
		p.accounts = config.ListAccounts()
		return nil

	case "alert":
		want := !r.rule.Enabled
		label := "alert enabled"
		if !want {
			label = "alert disabled"
		}
		id := r.rule.ID
		return p.run(label, func() error {
			return p.deps.API.Settings.SetAlertEnabled(bg(), id, want)
		}, "alert")

	case "wh", "self", "auto-update", "ll-enabled", "ll-server":
		return p.activate(r)
	}
	return nil
}

// removeAccount is `x`: forget an account on THIS device. The cloud account is
// untouched — revoking a key is a dashboard action, and conflating the two
// would mean tidying a laptop locked out every other machine.
func (p *Settings) removeAccount(target config.SavedAccount) tea.Cmd {
	key := "acct:" + target.APIKey
	wasActive := config.IsActiveAccount(target.APIKey)
	var others []config.SavedAccount
	for _, a := range p.accounts {
		if a.APIKey != target.APIKey {
			others = append(others, a)
		}
	}

	if p.confirmDel != key {
		p.confirmDel = key
		note := " (the cloud account is untouched)"
		if wasActive {
			if len(others) > 0 {
				note = " — the ACTIVE guard key; " + acctLabel(others[0]) + " takes over"
			} else {
				note = " — your ONLY account & the active guard key; this signs the device out (guard has no key until you log in again)"
			}
		}
		p.msg = &setMessage{text: "press x again to remove " + acctLabel(target) + " from this device" + note, bad: true}
		return nil
	}
	p.confirmDel = ""

	// Remove from accounts.json, then repair the ACTIVE key so it is not
	// re-seeded as a ghost by ListAccounts: promote another account, or clear
	// the credential entirely when this was the last one.
	config.RemoveAccount(target.APIKey)
	extra := " from this device"
	if wasActive {
		if len(others) > 0 {
			config.SetActiveAccount(config.Credential{APIKey: others[0].APIKey, APIURL: others[0].APIURL})
			extra = " · " + acctLabel(others[0]) + " is now the active key"
		} else {
			config.ClearActiveCredential()
			extra = " · signed out of this device"
		}
	}
	config.EnsureLocalLogOwner(config.EnforcingKey())
	p.deps.API.Invalidate()
	p.msg = &setMessage{text: "✓ removed " + acctLabel(target) + extra}
	p.accounts = config.ListAccounts()
	// The shell re-derives the header, the viewed account and the locked state
	// from disk: they have to move together or the header names an account that
	// is no longer there.
	return func() tea.Msg { return tui.AccountsChangedMsg{} }
}

func (p *Settings) beginLogin() tea.Cmd {
	if p.loginActive() {
		return nil
	}
	p.loginToken++
	token := p.loginToken
	p.login = loginStarting
	p.loginMsg = ""
	t := p.tag()
	return tea.Batch(
		tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return setSpinMsg{t} }),
		func() tea.Msg {
			st, err := p.deps.API.Device.Start(bg(), config.DefaultAPIURL)
			return setLoginStartMsg{genTag: t, token: token, start: st, err: err}
		},
	)
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

	case "wh-url":
		url := strings.TrimSpace(trimWrappers(v))
		if url == "" {
			return nil
		}
		if !httpURL.MatchString(url) {
			p.msg = &setMessage{text: "✗ webhook url must start with http:// or https://", bad: true}
			return nil
		}
		return p.run("webhook added", func() error {
			_, err := p.deps.API.Settings.CreateWebhook(bg(), map[string]any{"url": url, "events": "denials"})
			return err
		}, "wh")

	case "alert-target":
		if p.editor != nil {
			p.editor.target = v
			p.editor.field = 1 // move on to the signal once a target is entered
		}
	}
	return nil
}

// ── the alert editor ───────────────────────────────────────────────────────

func (p *Settings) openAlertEditor(channel string, rule *api.AlertRule) {
	e := &alertEditor{channel: channel, signal: "any", thresh: threshMin, window: 300, enabled: true}
	if rule != nil {
		e.id = rule.ID
		if channel == "email" && len(rule.Emails) > 0 {
			e.target = rule.Emails[0]
		}
		if channel == "telegram" && len(rule.Telegram) > 0 {
			e.target = rule.Telegram[0]
		}
		if rule.Signal != "" {
			e.signal = rule.Signal
		}
		if rule.Threshold != 0 {
			e.thresh = rule.Threshold
		}
		if rule.WindowSeconds != 0 {
			e.window = rule.WindowSeconds
		}
		e.enabled = rule.Enabled
		e.field = 1 // an existing rule starts on the signal
	}
	p.editor = e
	if rule == nil {
		p.editing = "alert-target"
		p.beginInput("")
	}
}

func (p *Settings) editorKey(s string) tea.Cmd {
	e := p.editor
	switch s {
	case "esc":
		p.editor = nil
		return nil
	case "e":
		p.editing = "alert-target"
		p.beginInput(e.target)
		return nil
	case "enter":
		if e.field == 0 {
			p.editing = "alert-target"
			p.beginInput(e.target)
			return nil
		}
		return p.saveEditor()
	case "up":
		n := e.fieldCount()
		e.field = (e.field + n - 1) % n
	case "down":
		n := e.fieldCount()
		e.field = (e.field + 1) % n
	case "left", "right":
		d := 1
		if s == "left" {
			d = -1
		}
		switch e.field {
		case 1:
			idx := 0
			for i, sig := range setSignals {
				if sig == e.signal {
					idx = i
				}
			}
			e.signal = setSignals[(idx+d+len(setSignals))%len(setSignals)]
		case 2:
			e.thresh = max(threshMin, min(threshMax, e.thresh+d*5))
		case 3:
			e.window = setWindows[max(0, min(len(setWindows)-1, nearestWindowIdx(e.window)+d))]
		case 4:
			e.enabled = !e.enabled
		}
	}
	return nil
}

func (p *Settings) saveEditor() tea.Cmd {
	e := p.editor
	if e == nil {
		return nil
	}
	value, err := normTarget(e.channel, e.target)
	if err != nil {
		p.msg = &setMessage{text: "✗ " + err.Error(), bad: true}
		return nil
	}
	body := map[string]any{
		"signal":        e.signal,
		"threshold":     e.thresh,
		"windowSeconds": e.window,
		"enabled":       e.enabled,
	}
	if e.channel == "email" {
		body["emails"] = []string{value}
		body["telegram"] = []string{}
	} else {
		body["telegram"] = []string{value}
		body["emails"] = []string{}
	}
	id, channel := e.id, e.channel
	p.editor = nil
	if id != "" {
		return p.run("alert updated", func() error {
			_, err := p.deps.API.Settings.UpdateAlert(bg(), id, body)
			return err
		}, "alert")
	}
	create := map[string]any{"name": "SolonGate alert"}
	for k, v := range body {
		create[k] = v
	}
	return p.run(channel+" alert added", func() error {
		_, err := p.deps.API.Settings.CreateAlert(bg(), create)
		return err
	}, "alert")
}

// There is deliberately no send-test for alerts. Delivering a real message to an
// arbitrary address or chat id on demand is a spam and rate-limit vector; only
// webhooks, which POST to the user's own URL, are testable.

var (
	mailtoPrefix  = regexp.MustCompile(`(?i)^mailto:`)
	leadWrappers  = regexp.MustCompile(`^["'<]+`)
	trailWrappers = regexp.MustCompile(`["'>]+$`)
	trailPunct    = regexp.MustCompile(`[.,;:]+$`)
	anySpace      = regexp.MustCompile(`\s+`)
	emailShape    = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	tgLead        = regexp.MustCompile(`(?i)^(chat[\s_-]*)?id[:=\s]*`)
	tgShape       = regexp.MustCompile(`^-?\d{5,}$`)
	httpURL       = regexp.MustCompile(`(?i)^https?://\S+$`)
)

func trimWrappers(s string) string {
	return trailWrappers.ReplaceAllString(leadWrappers.ReplaceAllString(s, ""), "")
}

// normTarget cleans up what people actually paste — a mailto:, a quoted
// address, a trailing full stop, an @handle, "chat id: 12345" — and refuses
// anything that still does not look like the thing it claims to be. An alert
// pointed at a malformed address fails silently, at the moment it matters.
func normTarget(channel, raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if channel == "email" {
		e := mailtoPrefix.ReplaceAllString(v, "")
		e = trimWrappers(e)
		e = trailPunct.ReplaceAllString(e, "")
		e = anySpace.ReplaceAllString(e, "")
		if !emailShape.MatchString(e) {
			return e, errString("that does not look like an e-mail address")
		}
		return e, nil
	}
	t := strings.TrimPrefix(v, "@")
	t = tgLead.ReplaceAllString(t, "")
	t = anySpace.ReplaceAllString(t, "")
	if !tgShape.MatchString(t) {
		return t, errString("a telegram chat id is a number — get yours from @userinfobot")
	}
	return t, nil
}

// ── render ─────────────────────────────────────────────────────────────────

func acctLabel(a config.SavedAccount) string {
	if a.Email != "" {
		return a.Email
	}
	if a.User != "" {
		return a.User
	}
	tail := a.APIKey
	if len(tail) > 4 {
		tail = tail[len(tail)-4:]
	}
	return "account …" + tail
}

func autoUpdateForcedByEnv() bool { return os.Getenv("SOLONGATE_AUTO_UPDATE") != "" }

// pidAlive probes a recorded pid without touching it.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Windows FindProcess opens a handle and fails when the process is gone,
	// which is the whole answer; everywhere else it always succeeds and signal 0
	// is what actually tests for existence.
	if runtime.GOOS == "windows" {
		return true
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func onOff(on bool) (string, lipgloss.Style) {
	if on {
		return "on ", stOK
	}
	return "off", stDim
}

func (p *Settings) View(ctx tui.PanelContext) string {
	p.apply(ctx)
	if p.loginActive() {
		return clip(p.viewLogin(), p.cols, p.rows)
	}
	if p.editor != nil {
		return clip(p.viewEditor(), p.cols, p.rows)
	}
	return clip(p.viewList(), p.cols, p.rows)
}

func (p *Settings) viewLogin() string {
	spin := spinFrames[p.spin%len(spinFrames)]
	var out []string
	out = append(out, stAccentB.Render("Add an account"))
	if p.login == loginStarting {
		out = append(out, stDim.Render(spin+" starting device pairing…"))
		return joinLines(out)
	}
	out = append(out, "")
	out = append(out, stDim.Render("Opening your browser to authorize. If it didn't open, visit:"))
	out = append(out, stAccentB.Render(truncate(p.loginURL, p.cols)))
	out = append(out, "")
	out = append(out, stWarn.Render(spin+" waiting for authorization… ")+stDim.Render("esc to cancel"))
	return joinLines(out)
}

func (p *Settings) viewEditor() string {
	e := p.editor
	var out []string
	title := "New"
	if e.id != "" {
		title = "Edit"
	}
	out = append(out, stAccentB.Render(title+" "+e.channel+" alert"))
	out = append(out, stDim.Render("↑↓ field · ←→ change · e edit target · enter save · esc cancel"))

	switch {
	case p.editing == "alert-target":
		prompt := "telegram chat id (from @userinfobot): "
		if e.channel == "email" {
			prompt = "e-mail address: "
		}
		out = append(out, "")
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
	out = append(out, "")

	field := func(idx int, label, value, hint string, valueStyle lipgloss.Style) string {
		l := newLine(false)
		if e.field == idx {
			l.put("▸ ", stAccent)
		} else {
			l.put("  ", stDim)
		}
		l.put(pad(label, 11), stDim)
		l.put(value, valueStyle)
		if e.field == idx && hint != "" {
			l.put("   "+hint, stDim)
		}
		return l.String()
	}

	target, targetStyle := e.target, stAccent
	if target == "" {
		target, targetStyle = "empty — press e", stDim
	} else {
		target = truncate(target, max(8, p.cols-16))
	}
	out = append(out, field(0, "target", target, "press e to edit", targetStyle))
	out = append(out, field(1, "signal", setSignalLabel[e.signal], "←→ change", stAccent))
	out = append(out, field(2, "threshold", "≥ "+itoa(e.thresh), "←→ ±5", stAccent))
	out = append(out, field(3, "window", winLabel(e.window), "←→ change", stAccent))
	if e.id != "" {
		v, st := "off", stDim
		if e.enabled {
			v, st = "on", stOK
		}
		out = append(out, field(4, "status", v, "←→ turn on/off", st))
	}
	out = append(out, "")
	if e.id != "" && !e.enabled {
		out = append(out, stWarn.Render("disabled — this alert will NOT fire until you set status back to on"))
	} else {
		l := newLine(false)
		l.put("fires when ", stDim)
		l.put(setSignalLabel[e.signal], stAccent)
		l.put(" reach ", stDim)
		l.put(itoa(e.thresh), stAccent)
		l.put(" within ", stDim)
		l.put(winLabel(e.window), stAccent)
		out = append(out, l.String())
	}
	return joinLines(out)
}

func (p *Settings) firstError() error {
	if p.locked() {
		return nil
	}
	for _, e := range []error{p.localErr, p.whErr, p.alertErr, p.guardErr, p.selfErr} {
		if e != nil {
			return e
		}
	}
	return nil
}

var authErrorShape = regexp.MustCompile(`(?i)invalid api key|authentication|401|unauthor|not logged in`)

func (p *Settings) viewList() string {
	loading := !p.locked() && !p.haveLocal && !p.haveWh && !p.haveAlert && !p.haveGuard && !p.haveSelf && p.firstError() == nil
	raw := p.firstError()

	// An AUTH failure must never take the panel over. Every cloud loader here
	// 401s when the stored key is revoked, and rendering the error INSTEAD of
	// the rows hides the Accounts section — which is the only way to remove the
	// dead account and pair again. A device revoked from the dashboard was then
	// stuck: the CLI said "log in from the Accounts panel" while that panel
	// showed nothing but that sentence.
	var authErr error
	var err error
	if raw != nil && authErrorShape.MatchString(raw.Error()) {
		authErr = raw
	} else {
		err = raw
	}
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

	hasEmail, hasTG := false, false
	for _, r := range p.visibleAlerts() {
		switch alertChannel(r) {
		case "email":
			hasEmail = true
		case "telegram":
			hasTG = true
		}
	}
	if hasEmail && hasTG {
		push(stDim.Render("  both channels in use — remove one (d) to change it"), "")
	}

	// The version sits at the very bottom of the scrollable list.
	push(" ", "")
	push(stDim.Render("solongate v"+Version), "")

	// hint + status take one line each, and the auth banner one more when it is
	// shown. The panel must not grow past its box.
	budget := max(4, p.rows-2)
	if authErr != nil {
		budget = max(4, p.rows-3)
	}
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

	if authErr != nil {
		// Two different problems, two different ways out: a key that exists and
		// is rejected, versus no key at all. Telling someone already inside the
		// dataroom to "run solongate" is the message that made this look broken.
		text := "✗ this device's key is invalid or was revoked — press x on the account below to remove it, then + add account to pair again"
		if strings.Contains(strings.ToLower(authErr.Error()), "not logged in") {
			text = "✗ this device is not paired yet — press + add account below to sign in and pair it"
		}
		out = append(out, stBad.Render(truncate(text, p.cols)))
	}

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
	case p.loginMsg != "":
		st := stOK
		if p.login == loginError {
			st = stBad
		}
		out = append(out, st.Render(truncate(p.loginMsg, p.cols)))
	default:
		out = append(out, " ")
	}

	out = append(out, win...)
	return joinLines(out)
}

func sectionOf(r setRow) string {
	switch r.kind {
	case "acct", "acct-add":
		return "ACCOUNTS"
	case "ws":
		return "WORKSPACES"
	case "guard", "self", "doctor", "repair":
		return "PROTECTION"
	case "cli-update", "auto-update":
		return "UPDATES"
	case "ll-enabled", "ll-path", "ll-server":
		return "LOCAL LOGS"
	case "wh", "wh-add":
		return "WEBHOOKS"
	}
	return "ALERTS"
}

func (p *Settings) sectionDesc(sec string) string {
	switch sec {
	case "ACCOUNTS":
		return "on this device (" + itoa(len(p.accounts)) + ") · ● viewing · ACTIVE = guard key · x removes"
	case "WORKSPACES":
		return "this account's projects (" + itoa(len(p.spaces)) + ") · enter moves this machine · the guard follows"
	case "PROTECTION":
		return "guard hook, self-protection, doctor and repair"
	case "UPDATES":
		return "the solongate CLI itself · background auto-update is off unless you turn it on"
	case "LOCAL LOGS":
		return "mirror every decision to a file + dashboard link"
	case "WEBHOOKS":
		return "POST events to a URL (" + itoa(len(p.visibleWebhooks())) + ") · t tests"
	}
	return "one email + one telegram (" + itoa(len(p.visibleAlerts())) + ") · enter edits · m on/off"
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
	case "acct":
		viewKey := p.viewKey
		isView := false
		if viewKey != "" {
			isView = r.acc.APIKey == viewKey
		} else if len(p.accounts) > 0 {
			isView = p.accounts[0].APIKey == r.acc.APIKey
		}
		l.put(pad(truncate(acctLabel(r.acc), 30), 31), stAccent)
		if isView {
			l.put("● viewing ", stOK)
		} else {
			l.put("          ", stDim)
		}
		if config.IsActiveAccount(r.acc.APIKey) {
			l.put("ACTIVE ", stWarn)
		} else {
			l.put("       ", stDim)
		}
		if r.acc.Project != "" {
			l.put(truncate(r.acc.Project, 20), stDim)
		}

	case "acct-add":
		l.put("+ add account (enter — device login in the browser)", stDim)

	case "ws":
		name := r.ws.Name
		if name == "" {
			name = r.ws.ID
		}
		l.put(pad(truncate(name, 30), 31), stAccent)
		if r.ws.ID == p.spaceNow {
			l.put("● this machine", stOK)
		} else {
			l.put("enter to move here", stDim)
		}

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

	case "cli-update":
		l.put(pad("version", 11), stDim)
		l.put("v"+Version, stOK)
		l.put("   enter checks npm and updates · needs admin rights on most macOS setups", stDim)

	case "auto-update":
		l.put(pad("auto", 11), stDim)
		txt, st := onOff(p.autoUp)
		l.put(txt, st)
		switch {
		case autoUpdateForcedByEnv():
			l.put("   set by SOLONGATE_AUTO_UPDATE", stDim)
		case p.autoUp:
			l.put("   the npm package installs new versions in the background · enter toggles", stDim)
		default:
			l.put("   off: nothing installs on its own (npm -g may need sudo) · enter toggles", stDim)
		}

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

	case "ll-server":
		l.put(pad("dashboard", 11), stDim)
		if p.srvUp {
			port := p.srvState.Port
			if port == 0 {
				port = config.LogsServerPort
			}
			l.put("running 127.0.0.1:"+itoa(port), stOK)
		} else if p.srvState.Desired == "on" {
			l.put("enabled, not running", stWarn)
		} else {
			l.put("stopped", stDim)
		}
		if p.srvUp {
			// Worth saying on the row: people close the dataroom expecting the
			// link to close with it, and then stop it a second time somewhere
			// else because they assume the first attempt failed.
			l.put("   survives closing the dataroom · enter stops and disables", stDim)
		} else {
			l.put("   enter starts the dashboard local-logs link", stDim)
		}

	case "wh":
		txt, st := onOff(r.wh.Enabled)
		l.put(txt, st)
		l.put(pad(" "+r.wh.Events, 9), stWarn)
		l.put(truncate(r.wh.URL, max(8, p.cols-16)), stAccent)

	case "wh-add":
		l.put("+ add webhook (enter)", stDim)

	case "alert":
		txt, st := onOff(r.rule.Enabled)
		l.put(txt, st)
		l.put(pad(" "+setSignalLabel[r.rule.Signal], 13), stWarn)
		l.put(pad("≥"+itoa(r.rule.Threshold)+"/"+winLabel(r.rule.WindowSeconds)+" ", 11), stPlain)
		l.put(truncate(chanOf(r.rule), max(8, p.cols-34)), stAccent)

	case "alert-add-email":
		l.put("+ add email alert (enter)", stDim)

	case "alert-add-tg":
		l.put("+ add telegram alert (enter — numeric chat id from @userinfobot)", stDim)
	}
	return l.String()
}

func chanOf(r api.AlertRule) string {
	var parts []string
	parts = append(parts, r.Emails...)
	for _, t := range r.Telegram {
		parts = append(parts, "tg "+t)
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, ", ")
}

// errString is a message that is already the whole error. errors.New would do,
// but this keeps the import list of this file to what it actually needs.
type errString string

func (e errString) Error() string { return string(e) }

// updateLine turns an update Status into the one line the panel shows.
//
// It lives here rather than in internal/selfupdate because the CLI prints
// several lines with colour and this is a single row in a list; a shared
// formatter would end up serving neither well.
func updateLine(st selfupdate.Status) string {
	switch st.Kind {
	case selfupdate.KindUpdated:
		return "updated to " + st.Version + " · restart the CLI to use it"
	case selfupdate.KindCurrent:
		return "already on the latest version (" + st.Version + ")"
	case selfupdate.KindNeedsAdmin:
		// Not a failure, and saying "failed" here would send someone looking for
		// a bug instead of typing sudo.
		return "an update is available but the install needs admin rights · run `sudo npm i -g @solongate/proxy`"
	case selfupdate.KindUnreachable:
		return "could not reach the registry · the installed version keeps working"
	case selfupdate.KindFailed:
		return "the update did not complete · the installed version keeps working"
	}
	return "no update available"
}
