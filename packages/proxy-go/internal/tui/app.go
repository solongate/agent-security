// SPDX-License-Identifier: Apache-2.0

// Package tui is the SolonGate dataroom: the fullscreen terminal UI behind
// `solongate` with no arguments.
//
// It is the Bubble Tea port of packages/proxy/src/tui. The shell in this file
// is App.tsx — the frame, the nav, the account switcher and the key routing —
// and the sections plug into it through the Panel interface below. Two rules
// carry over from the Ink implementation and are not negotiable:
//
//  1. A frame is at most (terminal rows - 1) lines tall. Ink abandoned its diff
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
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/solongate/agent-security/packages/proxy-go/internal/api"
	"github.com/solongate/agent-security/packages/proxy-go/internal/config"
	"github.com/solongate/agent-security/packages/proxy-go/internal/term"
)

// ── the panel plug ─────────────────────────────────────────────────────────

// Deps is what every panel is built with. It is handed to the constructor
// rather than reached for globally so two panels cannot end up talking to two
// different accounts.
type Deps struct {
	API *api.Client
	Cfg config.TUIConfig
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

// Panel is one section of the dataroom.
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
// dataroom.
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
// renderer are kept deliberately: they are the seam an update mechanism plugs into —
// send one of these and the banner appears — and re-deriving the render path would be
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
// as many variants as a team keeps — so a rate limit that lived beside policies
// rather than inside one described enforcement that no longer exists. They are
// levels of the Policies panel, on the variant they belong to.
const (
	SectionLive = iota
	SectionPolicies
	SectionAudit
	SectionSettings
	sectionCount
)

var sectionLabels = [sectionCount]string{
	"Solo Live", "Policies", "Audit", "Settings",
}

var registry [sectionCount]func(Deps) Panel

// Register installs a panel constructor for a section.
//
// Each panel file calls it from its own init(), so adding a section never means
// editing this file — several people porting different panels at the same time
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
// section quietly polls twice as often for the rest of the session — once more
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

func (p *notPortedPanel) View(ctx PanelContext) string {
	return strings.Join([]string{
		renderRow(ctx.Cols, sgb(strings.ToUpper(p.label), theme.AccentBright)),
		"",
		renderRow(ctx.Cols, sg("This section did not register a panel.", theme.Warn)),
		renderRow(ctx.Cols, sg("That is a bug in this build, not something you can work around.", theme.Dim)),
	}, "\n")
}

// ── the shell ──────────────────────────────────────────────────────────────

type focusTarget int

const (
	focusNav focusTarget = iota
	focusPanel
)

// App is the dataroom shell.
type App struct {
	deps Deps

	// gen is bumped whenever a panel has to be rebuilt, so an answer still in
	// flight for the previous mount is dropped rather than rendered.
	gen int

	// policyLabel is what is being enforced, read from the policy file. It used
	// to be which account the dataroom was viewing.
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
	client := a.deps.API
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
// which is what keeps the dataroom inside the API's rate limit.
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

func (a *App) onKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	// A panel editing text owns the keyboard completely. Ink left the shell's
	// handler armed while ink-text-input had focus, so typing a `q` into Live's
	// search box quit the dataroom; this is the one deliberate difference from
	// the TypeScript key routing.
	if a.focus == focusPanel && a.capturing() {
		return a, a.toPanel(k)
	}

	if a.help {
		a.help = false
		return a, nil
	}
	key, str := k.Type, k.String()
	if str == "?" && a.focus == focusNav {
		a.help = true
		return a, nil
	}

	if a.focus == focusNav {
		switch {
		case key == tea.KeyUp:
			a.section = (a.section - 1 + sectionCount) % sectionCount
			return a, a.mount()
		case key == tea.KeyDown:
			a.section = (a.section + 1) % sectionCount
			return a, a.mount()
		case key == tea.KeyRight || key == tea.KeyEnter || key == tea.KeyTab:
			a.focus = focusPanel
			return a, nil
		case str == "a" || str == "A":
		case str == "q" || str == "Q":
			return a, tea.Quit
		}
		return a, nil
	}

	// Focused on a panel. The panel sees the key as well: Ink ran both handlers,
	// so esc leaves a sub-view AND returns to the menu in one press.
	cmd := a.toPanel(k)
	switch {
	case key == tea.KeyEsc || key == tea.KeyTab:
		a.focus = focusNav
	case (str == "q" || str == "Q") && a.isTakeover():
		return a, tea.Quit
	}
	return a, cmd
}

// reconcileLocalLogOwner lived here. It stamped a `.owner` marker beside the log
// naming the account the log belonged to, so a newly paired account did not open onto
// the previous one's calls. One machine has one log and no account to own it.

// ── rendering ──────────────────────────────────────────────────────────────

func (a *App) View() string {
	if !a.sized {
		return ""
	}
	if a.help {
		return clampBlock(a.helpView(), a.cols, a.rows-1)
	}
	// Live takeover: the console owns the whole terminal, one row short of it.
	if a.isTakeover() && a.focus == focusPanel {
		return clampBlock(a.panel.View(a.ctx()), a.cols, a.rows-1)
	}
	return clampBlock(a.boxedView(), a.cols, a.rows-1)
}

func (a *App) boxedView() string {
	inner := a.cols - 2 // paddingX = 1
	if inner < 10 {
		inner = 10
	}
	lines := []string{""} // paddingTop = 1
	lines = append(lines, a.bannerLines(inner)...)
	lines = append(lines, a.policyLine(inner))
	lines = append(lines, "") // marginTop = 1 on the nav+panel row
	lines = append(lines, a.navAndPanel(inner)...)
	lines = append(lines, a.hintsLine(inner))

	for i, l := range lines {
		lines[i] = " " + l
	}
	return strings.Join(lines, "\n")
}

func (a *App) bannerLines(width int) []string {
	if a.cols < 82 {
		return []string{renderRow(width,
			sgb("SolonGate", theme.AccentBright),
			sg(" — security control center", theme.Dim))}
	}
	out := make([]string, 0, len(term.BannerFull)+1)
	for _, l := range term.BannerFull {
		out = append(out, renderRow(width, sgb(l, theme.White)))
	}
	out = append(out, renderRow(width,
		sg(" security control center · manage policies, rate limits, DLP & more", theme.Dim)))
	return out
}

// policyLine names what is being ENFORCED. It used to name who was logged in.
func (a *App) policyLine(width int) string {
	segs := []seg{sg("policy: ", theme.Dim), sgb(a.policyLabel, theme.AccentBright)}
	segs = append(segs, sg("  · this machine, nothing leaves it", theme.Dim))
	switch a.update.Kind {
	case "updating":
		segs = append(segs, sg("  ↑ updating to v"+a.update.Version+"…", theme.Warn))
	case "updated":
		segs = append(segs, sgb("  ↑ v"+a.update.Version+" installed · restart (q, then solongate) to apply", theme.OK))
	case "available":
		segs = append(segs, sg("  ↑ v"+a.update.Version+" out · Settings → UPDATES", theme.Warn))
	case "needs-admin":
		segs = append(segs, sg("  ↑ v"+a.update.Version+" needs admin rights · Settings → UPDATES", theme.Warn))
	}
	return renderRow(width, segs...)
}

func (a *App) navAndPanel(width int) []string {
	contentCols, contentRows := a.panelBudget()

	navColor := lipgloss.TerminalColor(lipgloss.Color("8"))
	panelColor := navColor
	if a.focus == focusNav {
		navColor = theme.Accent
	} else {
		panelColor = theme.Accent
	}

	navLines := make([]string, 0, sectionCount)
	for i, label := range sectionLabels {
		isCur := i == a.effectiveSection()
		prefix, color := "  ", lipgloss.TerminalColor(nil)
		if isCur {
			prefix, color = "▸ ", theme.AccentBright
		}
		navLines = append(navLines, renderRow(12, seg{text: prefix + label, fg: color, bold: isCur}))
	}

	body := ""
	if a.panel != nil {
		body = clampBlock(a.panelBody(), contentCols, contentRows)
	}

	// flexShrink=0 in Ink; a fixed 14 columns of content here. Without it a
	// panel with very wide rows (Audit's dated stream lines) inflated the row's
	// minimum width and the sidebar visibly resized between sections.
	// The nav is as tall as the panel, not as tall as its seven entries: Ink
	// stretched it to the row and the two borders closed at the same line.
	nav := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(navColor).
		Padding(0, 1).Width(14).Height(maxInt(sectionCount, contentRows)).
		Render(strings.Join(navLines, "\n"))
	panel := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(panelColor).
		Padding(0, 1).Width(contentCols + 2).Height(contentRows).
		Render(body)

	return strings.Split(lipgloss.JoinHorizontal(lipgloss.Top, nav, panel), "\n")
}

// panelBody renders the section inside the box. A takeover panel that has not
// been entered shows its hint instead of its console.
func (a *App) panelBody() string {
	ctx := a.ctx()
	if t, ok := a.panel.(Takeover); ok && a.focus != focusPanel {
		return t.Hint(ctx)
	}
	return a.panel.View(ctx)
}

func (a *App) hintsLine(width int) string {
	switch {
	case a.focus == focusNav:
		return keyHints([][2]string{{"↑↓", "section"}, {"→/enter", "open"},
			{"?", "help"}, {"q", "quit"}}, width)
	default:
		return keyHints([][2]string{{"←/esc", "back"}, {"↑↓", "in-panel"}, {"space/s", "act"}}, width)
	}
}

var shellHelp = []helpGroup{
	{"Global", [][2]string{
		{"↑↓", "move between sections"},
		{"→ / enter", "open a section"},
		{"← / esc", "back to the menu"},
		{"?", "this help"},
		{"q", "quit"},
	}},
	{"Solo Live", [][2]string{
		{"↑↓", "select a stream row"},
		{"enter", "full entry content"},
		{"w", "whitelist the selected DENY"},
		{"b", "block the selected ALLOW"},
		{"d / x / r", "filter denies / dlp / rate-limit"},
		{"f", "local / cloud filter"},
		{"/", "search"},
		{"space", "copy mode (freeze)"},
	}},
	{"Policies", [][2]string{
		{"↑↓", "browse / select"},
		{"a", "activate (pin) selected policy"},
		{"x", "deactivate — no active policy"},
		{"enter", "open a policy → a layer → a rule"},
		{"tab", "switch variant (v new · V remove)"},
		{"space", "toggle a rule on/off"},
		{"e", "flip effect"},
		{"n", "new rule"},
		{"d", "delete rule"},
		{"m", "flip mode"},
		{"s", "save · x discard"},
	}},
	{"Policies · secret detectors", [][2]string{
		{"↑↓", "move"},
		{"space", "toggle a built-in detector on/off"},
		{"m", "cycle mode"},
		{"a", "add custom pattern (name → glob, * = any chars)"},
		{"d", "remove custom / route"},
		{"s", "save · ← back"},
	}},
	{"Policies · rate limit", [][2]string{
		{"↑↓", "field, then the bursts"},
		{"←→", "adjust (shift = ±10)"},
		{"s", "save · ← back (from a burst row)"},
	}},
	{"Audit", [][2]string{
		{"← →", "prev / next page (500 each)"},
		{"↑↓", "select (list scrolls)"},
		{"enter", "full entry / session logs"},
		{"f / g", "decision / signal filter"},
		{"t / n / /", "tool / agent / search"},
		{"x / X", "delete entry / ALL (press twice)"},
		{"c", "clear filters"},
	}},
	{"Settings", [][2]string{
		{"↑↓", "move"},
		{"enter / space", "toggle · edit · add"},
		{"e", "webhook events"},
		{"d d", "delete"},
		{"r", "refresh"},
	}},
}

func (a *App) helpView() string {
	width := a.cols - 4 // paddingX = 2
	if width < 20 {
		width = 20
	}
	lines := []string{"", renderRow(width, sgb("SolonGate — keyboard shortcuts", theme.AccentBright)), ""}
	lines = append(lines, helpBlock(shellHelp, 16, width)...)
	lines = append(lines, renderRow(width, sg("press any key to close", theme.Dim)))
	for i, l := range lines {
		lines[i] = "  " + l
	}
	return strings.Join(lines, "\n")
}

// clampBlock is the hard guarantee behind the frame budget: at most `rows`
// lines, each at most `cols` columns. Arithmetic decides the layout; this
// decides what actually reaches the terminal, so a panel that miscounts loses
// its last line instead of triggering a full-screen repaint on every render.
func clampBlock(s string, cols, rows int) string {
	if rows < 1 {
		rows = 1
	}
	lines := strings.Split(s, "\n")
	if len(lines) > rows {
		lines = lines[:rows]
	}
	cut := lipgloss.NewStyle().MaxWidth(cols)
	for i, l := range lines {
		if lipgloss.Width(l) > cols {
			lines[i] = cut.Render(l)
		}
	}
	return strings.Join(lines, "\n")
}

// ── entry point ────────────────────────────────────────────────────────────

// Run opens the dataroom and returns when the user quits.
//
// The caller is responsible for the human-only gate: every command in this CLI
// changes or reveals a security posture, and the dataroom is the one that does
// both. See assertHumanTerminal in main.go.
func Run() error {
	cfg := config.LoadTUIConfig()
	setAccent(cfg.Accent)

	// Anything written to stderr lands on top of the frame, and the standard
	// logger's default destination is stderr. Ink had the same problem with
	// console.log and solved it the same way: send it to a file instead.
	log.SetOutput(io.Discard)
	if config.EnsureDir() == nil {
		path := filepath.Join(config.Dir(), "dataroom-debug.log")
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			defer f.Close()
			log.SetOutput(f)
		}
	}

	app := New(Deps{API: api.New(), Cfg: cfg})
	_, err := tea.NewProgram(app, tea.WithAltScreen()).Run()
	return err
}
