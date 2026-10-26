// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/solongate/agent-security/packages/core/term"
)

func (p *notPortedPanel) View(ctx PanelContext) string {
	return strings.Join([]string{
		RenderRow(ctx.Cols, Sgb(strings.ToUpper(p.label), Theme.AccentBright)),
		"",
		RenderRow(ctx.Cols, Sg("This section did not register a panel.", Theme.Warn)),
		RenderRow(ctx.Cols, Sg("That is a bug in this build, not something you can work around.", Theme.Dim)),
	}, "\n")
}

func (a *App) View() string {
	if !a.sized {
		return ""
	}
	if a.help {
		return ClampBlock(a.helpView(), a.cols, a.rows-1)
	}

	if a.isTakeover() && a.focus == focusPanel {
		return ClampBlock(a.panel.View(a.ctx()), a.cols, a.rows-1)
	}
	return ClampBlock(a.boxedView(), a.cols, a.rows-1)
}

func (a *App) boxedView() string {
	inner := a.cols - 2
	if inner < 10 {
		inner = 10
	}
	lines := []string{""}
	lines = append(lines, a.bannerLines(inner)...)
	lines = append(lines, a.policyLine(inner))
	lines = append(lines, "")
	lines = append(lines, a.navAndPanel(inner)...)
	lines = append(lines, a.hintsLine(inner))

	for i, l := range lines {
		lines[i] = " " + l
	}
	return strings.Join(lines, "\n")
}

func (a *App) bannerLines(width int) []string {
	if a.cols < 82 {
		return []string{RenderRow(width,
			Sgb("SolonGate", Theme.AccentBright),
			Sg(", security control center", Theme.Dim))}
	}
	out := make([]string, 0, len(term.BannerFull)+1)
	for _, l := range term.BannerFull {
		out = append(out, RenderRow(width, Sgb(l, Theme.White)))
	}
	out = append(out, RenderRow(width,
		Sg(" security control center · manage policies, rate limits, DLP & more", Theme.Dim)))
	return out
}

func (a *App) policyLine(width int) string {
	segs := []Seg{Sg("policy: ", Theme.Dim), Sgb(a.policyLabel, Theme.AccentBright)}
	segs = append(segs, Sg("  · this machine, nothing leaves it", Theme.Dim))
	switch a.update.Kind {
	case "updating":
		segs = append(segs, Sg("  ↑ updating to v"+a.update.Version+"…", Theme.Warn))
	case "updated":
		segs = append(segs, Sgb("  ↑ v"+a.update.Version+" installed · restart (q, then solongate) to apply", Theme.OK))
	case "available":
		segs = append(segs, Sg("  ↑ v"+a.update.Version+" out · Settings → UPDATES", Theme.Warn))
	case "needs-admin":
		segs = append(segs, Sg("  ↑ v"+a.update.Version+" needs admin rights · Settings → UPDATES", Theme.Warn))
	}
	return RenderRow(width, segs...)
}

func (a *App) navAndPanel(width int) []string {
	contentCols, contentRows := a.panelBudget()

	navColor := lipgloss.TerminalColor(lipgloss.Color("8"))
	panelColor := navColor
	if a.focus == focusNav {
		navColor = Theme.Accent
	} else {
		panelColor = Theme.Accent
	}

	navLines := make([]string, 0, sectionCount)
	for i, label := range sectionLabels {
		isCur := i == a.effectiveSection()
		prefix, color := "  ", lipgloss.TerminalColor(nil)
		if isCur {
			prefix, color = "▸ ", Theme.AccentBright
		}
		navLines = append(navLines, RenderRow(12, Seg{Text: prefix + label, Fg: color, Bold: isCur}))
	}

	body := ""
	if a.panel != nil {
		body = ClampBlock(a.panelBody(), contentCols, contentRows)
	}

	nav := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(navColor).
		Padding(0, 1).Width(14).Height(MaxInt(sectionCount, contentRows)).
		Render(strings.Join(navLines, "\n"))
	panel := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).BorderForeground(panelColor).
		Padding(0, 1).Width(contentCols + 2).Height(contentRows).
		Render(body)

	return strings.Split(lipgloss.JoinHorizontal(lipgloss.Top, nav, panel), "\n")
}

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

var shellHelp = []HelpGroup{
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
	width := a.cols - 4
	if width < 20 {
		width = 20
	}
	lines := []string{"", RenderRow(width, Sgb("SolonGate, keyboard shortcuts", Theme.AccentBright)), ""}
	lines = append(lines, HelpBlock(shellHelp, 16, width)...)
	lines = append(lines, RenderRow(width, Sg("press any key to close", Theme.Dim)))
	for i, l := range lines {
		lines[i] = "  " + l
	}
	return strings.Join(lines, "\n")
}

func ClampBlock(s string, cols, rows int) string {
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