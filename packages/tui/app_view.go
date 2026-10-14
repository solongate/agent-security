// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/solongate/agent-security/packages/core/term"
)

func (p *notPortedPanel) View(ctx PanelContext) string {
	return strings.Join([]string{
		renderRow(ctx.Cols, sgb(strings.ToUpper(p.label), theme.AccentBright)),
		"",
		renderRow(ctx.Cols, sg("This section did not register a panel.", theme.Warn)),
		renderRow(ctx.Cols, sg("That is a bug in this build, not something you can work around.", theme.Dim)),
	}, "\n")
}

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
			sg(", security control center", theme.Dim))}
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
		{"x", "deactivate, no active policy"},
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
	lines := []string{"", renderRow(width, sgb("SolonGate, keyboard shortcuts", theme.AccentBright)), ""}
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