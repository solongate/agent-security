// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

// Package tui is the SolonGate TUI: the fullscreen terminal UI behind
// `solongate` with no arguments.
//
// It is the Bubble Tea port of packages/proxy/src/tui. The shell in this file
// is App.tsx, the frame, the nav, the account switcher and the key routing,
// and the sections plug into it through the Panel interface below. Two rules
// carry over from the Ink implementation and are not negotiable:
//
//  1. A frame is at most (terminal rows, 1) lines tall. Ink abandoned its diff
//     and did clearTerminal plus a full rewrite on EVERY render once a frame
//     reached the terminal's height, which looked like a glitch whenever bright
//     content was on screen. Bubble Tea repaints the same way. clampBlock below
//     makes the budget a hard guarantee rather than an arithmetic promise.
//
//  2. Nothing here writes to stdout. Bubble Tea owns the alternate screen and a
//     stray line paints over the frame; Run redirects the standard logger to a
//     file for the same reason Ink was rendered with patchConsole off.
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

// ── the panel plug ─────────────────────────────────────────────────────────

// Deps is what every panel is built with. It is handed to the constructor
// rather than reached for globally so two panels cannot end up talking to two
// different accounts.
type Deps struct {
	Client *client.Client
	Cfg    config.TUIConfig

	// Confinement is what this machine can do about confining an agent, as
	// PLAIN DATA rather than as a package the TUI imports.
	//
	// THE TUI DOES NOT IMPORT packages/sandbox, and that is the point of this
	// field. The Sandbox panel needs two facts, which kernel mechanism is
	// available, and why a closed box cannot be built when it cannot, and
	// reaching for them directly meant the TUI module required go-landlock and
	// libcap/psx for a panel that draws a list. Somebody reading the TUI found
	// kernel confinement in it.
	//
	// The caller fills it. `app` links the sandbox package already, because the
	// CLI it dispatches to does; asking there and passing the answer in costs
	// one struct and removes a dependency from a module that only renders.
	Confinement Confinement
}

// Confinement is the answer to "what can this machine do", flattened so no
// layer above the sandbox package has to depend on it.
type Confinement struct {
	// Mechanism is the kernel feature `solongate run` would use here:
	// "Landlock", "Seatbelt", "icacls deny (per run)", or "" where there is
	// none.
	Mechanism string

	// BoxUnavailable is why `solongate sandbox` cannot build a closed box here,
	// and nil when it can. A sentence, because it is printed: a missing bwrap
	// names the package to install, and a kernel with no user namespaces says
	// which sysctl said so.
	BoxUnavailable error
}

// PanelContext is what the shell knows at the moment a panel updates or
// renders. It is passed by value on every call: none of it is a panel's to
// keep, and a panel that cached Cols would be wrong on the next resize.
type PanelContext struct {
	Deps

	// Cols and Rows are the panel's BUDGET, not the terminal's size: the exact
	// number of columns and lines View may emit. Anything beyond them is cut,
	// so a panel that miscounts loses content rather than breaking the frame.
	Cols int
	Rows int

	// Focused is whether the panel has the keyboard. A panel still updates and
	// still renders while it does not.
	Focused bool

	// Gen is the mount generation. Any message a panel sends back to itself
	// asynchronously should carry it and implement GenMsg, or a response that
	// was in flight when the panel remounted lands in the panel that replaced it
	// and shows the previous mount's data.
	Gen int

	// Now is fixed for the whole update-and-render pass, so a row cannot be
	// dated one second before the counter that summarises it.
	Now time.Time
}

// Panel is one section of the TUI.
//
// Implementations are POINTERS: a panel holds buffers and in-flight state, and
// value semantics would have every Update copy them and every stale copy still
// look alive.
type Panel interface {
	// Init runs once, when the section is opened. Returning a command here is
	// how a panel starts its first load and its own tickers.
	Init(ctx PanelContext) tea.Cmd

	// Update receives every message while the section is open, including keys
	// (only while Focused), window sizes and the panel's own results.
	Update(msg tea.Msg, ctx PanelContext) (Panel, tea.Cmd)

	// View renders at most ctx.Rows lines of at most ctx.Cols columns.
	View(ctx PanelContext) string
}

// Takeover is a panel that owns the WHOLE terminal once opened, rather than
// rendering inside the boxed layout. The two live consoles are the ones: a
// stream squeezed into the boxed layout is four rows of history, which is a log
// rather than a console.
type Takeover interface {
	Panel
	// Hint is what the boxed layout shows while the section is selected but not
	// yet entered.
	Hint(ctx PanelContext) string
}

// KeyCapture is a panel that is editing text. While it reports true the shell
// touches no keys at all, so a `q` typed into a search box does not quit the
// TUI.
type KeyCapture interface{ CapturingKeys() bool }

// GenMsg is a panel message that belongs to one mount of that panel. The shell
// drops any whose generation is not the current one.
type GenMsg interface{ Generation() int }

// SectionRequestMsg asks the shell to open another section, by its nav label.
type SectionRequestMsg struct{ Label string }

// UpdateStatusMsg is where an update flow would report in. The shell only renders it;
// nothing here installs anything.
//
// NOTHING SENDS IT in this build. The producer was a background `npm i -g` off a
// version the service advertised, and it went with the service. The message and its
// renderer are kept deliberately: they are the seam an update mechanism plugs into,
// send one of these and the banner appears, and re-deriving the render path would be
// more work than leaving it. The banner cannot appear on its own.
type UpdateStatusMsg struct {
	// Kind is one of "idle", "available", "updating", "updated", "needs-admin".
	Kind    string
	Version string
}

// ── the section table ──────────────────────────────────────────────────────

// Section order, matching the dashboard's navigation. The order is part of the
// UI: people navigate it by muscle memory.
//
// Rate Limit and DLP are NOT in it any more, and their absence is the point. A
// policy is rules AND a DLP configuration AND a rate limit, in
// as many variants as a team keeps, so a rate limit that lived beside policies
// rather than inside one described enforcement that no longer exists. They are
// levels of the Policies panel, on the variant they belong to.
// SANDBOX IS ITS OWN SECTION, not a row under Settings, and the reason is what
// it decides. Every other setting on this product tunes how a tool call is
// JUDGED, which rules apply, what counts as a secret, how many calls a minute.
// The sandbox decides what the agent can reach at all, before any call is
// judged, and it is the only setting whose answer the agent cannot argue with.
// A one-line row beside "doctor" and "repair" described it as an option of the
// same size as those.
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

// Register installs a panel constructor for a section.
//
// Each panel file calls it from its own init(), so adding a section never means
// editing this file, several people porting different panels at the same time
// would otherwise all be editing one list. A section with no constructor still
// appears in the nav and says it is not ported yet, which is the honest answer
// and keeps the numbering stable while the port is half done.
func Register(section int, ctor func(Deps) Panel) {
	if section < 0 || section >= sectionCount {
		return
	}
	registry[section] = ctor
}

// panelTokens hands each mounted panel instance its own identity.
//
// The mount generation is not enough on its own: leaving a section and coming
// straight back builds a NEW panel of the SAME generation while the previous
// one's ticker is still in flight. That tick is delivered to the new panel,
// which re-arms it on top of the chain its own Init already started, and the
// section quietly polls twice as often for the rest of the session, once more
// per visit. A panel that stamps its token on its ticks can tell them apart.
//
// Not atomic on purpose: Bubble Tea builds and updates models on one goroutine.
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

// notPortedPanel stands in for a section nobody has ported yet. It says so
// rather than rendering an empty box: this whole UI is about what your security
// posture currently is, and a blank panel reads as "nothing configured".
type notPortedPanel struct{ label string }

func (p *notPortedPanel) Init(PanelContext) tea.Cmd { return nil }

func (p *notPortedPanel) Update(_ tea.Msg, _ PanelContext) (Panel, tea.Cmd) { return p, nil }

// ── the shell ──────────────────────────────────────────────────────────────

type focusTarget int

const (
	focusNav focusTarget = iota
	focusPanel
)

// App is the TUI shell.
type App struct {
	deps Deps

	// gen is bumped whenever a panel has to be rebuilt, so an answer still in
	// flight for the previous mount is dropped rather than rendered.
	gen int

	// policyLabel is what is being enforced, read from the policy file. It used
	// to be which account the TUI was viewing.
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

// New builds the shell. Every section is reachable from the first frame: they all
// read this machine, and there is nothing to be paired with.
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
	// a.reconcileLocalLogOwner() ran here, before any panel read the log. See below.
	return tea.Batch(a.mount(), a.readPolicyLabel())
}

// policyLabelMsg carries the header line back to the shell.
type policyLabelMsg struct{ text string }

// readPolicyLabel fills the header line from the policy file. An unreadable file
// is worth saying out loud there: the guard reads the same one and enforces
// nothing when it cannot parse it.
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

// mount builds the panel for the current section and runs its Init. It is the
// equivalent of a React mount: a section that is not on screen does not poll,
// which is what keeps the TUI inside the API's rate limit.
func (a *App) mount() tea.Cmd {
	idx := a.effectiveSection()
	a.panel = buildPanel(idx, a.deps)
	a.panelIdx = idx
	return a.panel.Init(a.ctx())
}

// remount rebuilds the current panel from scratch after the viewed account
// changed. The generation bump is what makes the previous account's in-flight
// responses land nowhere.
func (a *App) remount() tea.Cmd {
	a.gen++
	return a.mount()
}

// effectiveSection is the section actually shown. There is no longer anything
// that makes one unreachable: `locked()` used to answer "no account on file", and
// every section but Settings was inert behind it.
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

// panelBudget is the content area a boxed panel gets: the banner, the account
// line, the nav, the borders and the key hints subtracted, plus two lines of
// headroom so the total can never reach the terminal's height.
func (a *App) panelBudget() (cols, rows int) {
	shell := 10 // narrow: one title line instead of the full banner
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
		// The panel sees the resize too: its own budgets are computed from the
		// context, but a panel holding a text input has a width to update.
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
		return a, nil // a previous mount's answer, arriving after the switch
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

// reconcileLocalLogOwner lived here. It stamped a `.owner` marker beside the log
// naming the account the log belonged to, so a newly paired account did not open onto
// the previous one's calls. One machine has one log and no account to own it.

// ── entry point ────────────────────────────────────────────────────────────

// Run opens the TUI and returns when the user quits.
//
// The caller is responsible for the human-only gate: every command in this CLI
// changes or reveals a security posture, and the TUI is the one that does
// both. See assertHumanTerminal in main.go.
// Run opens the TUI. The confinement facts are passed in rather than looked up:
// see Deps.Confinement for why this module does not import the sandbox package.
func Run(c Confinement) error {
	cfg := config.LoadTUIConfig()
	setAccent(cfg.Accent)
	// NO_COLOR after the accent, so it wins over whatever tui-config.json asked
	// for. A user who has turned colour off has turned it off.
	flatten()

	// Anything written to stderr lands on top of the frame, and the standard
	// logger's default destination is stderr. Ink had the same problem with
	// console.log and solved it the same way: send it to a file instead.
	log.SetOutput(io.Discard)
	if config.EnsureDir() == nil {
		path := filepath.Join(config.Dir(), "tui-debug.log")
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			defer f.Close()
			log.SetOutput(f)
		}
	}

	deps := Deps{Client: client.New(), Cfg: cfg, Confinement: c}

	// THE FIRST RUN COMES FIRST, and the TUI does not open behind it. See
	// setup.go for why this is a gate rather than a section in the nav: the
	// state it is about is the one where everything looks fine and nothing is
	// enforced. A user who leaves it gets no TUI and no record, so the
	// next run starts there again.
	if needsSetup(cfg) {
		carryOn, err := runSetup(deps, os.Stdout)
		if err != nil {
			return err
		}
		if !carryOn {
			return nil
		}
		// Re-read: the first run just wrote a policy and the completion stamp,
		// and the shell's header line is built from the config it was handed.
		deps.Cfg = config.LoadTUIConfig()
	}

	app := New(deps)
	_, err := tea.NewProgram(app, tea.WithAltScreen()).Run()
	return err
}