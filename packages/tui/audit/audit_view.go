// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package audit

import (
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/tui"
)

var auditHelp = []tui.HelpGroup{
	{Title: "Logs", Keys: [][2]string{
		{"↑↓ / PgUp PgDn", "select a row (window follows)"},
		{"enter", "open the FULL entry (reason + arguments)"},
		{"← →", "previous / next page (500 per page, jumps to top)"},
		{"f", "decision filter: all → DENY → ALLOW"},
		{"g", "signal filter: all → dlp → ratelimit"},
		{"t / n", "tool / agent filter (type, enter done)"},
		{"/", "free-text search"},
		{"x", "delete ONLY the selected entry (press x twice)"},
		{"X", "delete ALL matched logs of the source (press X twice)"},
		{"e", "export this page → ~/.solongate/audit-export.jsonl"},
		{"E", "export ALL matched rows"},
		{"c", "clear every filter (incl. session)"},
	}},

	{Title: "Anywhere in Audit", Keys: [][2]string{
		{"space", "copy mode: freeze screen for mouse selection"},
		{"?", "this help · any key closes"},
		{"esc", "back to the menu"},
	}},
	{Title: "Entry (full content)", Keys: [][2]string{
		{"↑↓ / PgUp PgDn", "scroll the reason + arguments"},
		{"space", "copy mode (freeze, then select)"},
		{"← / esc", "back to the list"},
	}},
}

func (p *Audit) View(ctx tui.PanelContext) string {
	var lines []string
	switch {
	case p.help:
		lines = p.viewHelp(ctx)
	case p.view == "detail" && p.hasRows():
		lines = p.viewEntry(ctx)
	default:
		lines = p.viewLogs(ctx)
	}

	return tui.ClampBlock(strings.Join(lines, "\n"), ctx.Cols, ctx.Rows)
}

func (p *Audit) hasRows() bool {
	rows, _ := p.pageRows()
	return len(rows) > 0
}

func (p *Audit) viewHelp(ctx tui.PanelContext) []string {
	note := "· press any key to close · space = copy mode (works here too)"
	if p.frozen {
		note = "· screen frozen, space resumes, other keys are locked"
	}
	lines := []string{}
	if b := p.copyBanner(ctx.Cols); b != "" {
		lines = append(lines, b)
	}
	lines = append(lines, tui.RenderRow(ctx.Cols,
		tui.Sgb("AUDIT, all keys ", tui.Theme.AccentBright), tui.Sg(note, tui.Theme.Dim)), "")

	half := tui.MaxInt(20, (ctx.Cols-2)/2)
	left := tui.HelpBlock(auditHelp[:1], auditKeyColumn, half)
	right := tui.HelpBlock(auditHelp[1:], auditKeyColumn, half)
	rows := tui.MaxInt(len(left), len(right))
	return append(lines, tui.JoinColumns([][]string{left, right}, []int{half, half}, rows)...)
}

func (p *Audit) copyBanner(width int) string {
	if !p.frozen {
		return ""
	}
	return tui.RenderRow(width, tui.Seg{
		Text: " ⏵ COPY MODE, screen frozen, select & copy freely · space resume ",
		Fg:   lipgloss.Color(tui.HexOKFG), Bg: lipgloss.Color(tui.HexOKBG), Bold: true})
}

func (p *Audit) strip(width int) string {
	{
		calls, allow, deny, policies := "····", "···", "··", "·"
		if p.stats != nil {
			calls = strconv.Itoa(p.stats.TotalCalls)
			allow = strconv.Itoa(p.stats.Allowed)
			deny = strconv.Itoa(p.stats.Denied)
			policies = strconv.Itoa(p.stats.ActivePolicies)
		}

		return tui.RenderRow(width,
			tui.Seg{Text: calls, Bold: true}, tui.Sg(" calls · ", tui.Theme.Dim),
			tui.Sg(allow+" allow", tui.Theme.OK), tui.Sg(" · ", tui.Theme.Dim),
			tui.Sg(deny+" deny", tui.Theme.Bad), tui.Sg(" · "+policies+" policies", tui.Theme.Dim),
			tui.Sg(" · "+config.LocalLogFile(), tui.Theme.Dim))
	}
}

func chip(label, value string, on bool) []tui.Seg {
	color := lipgloss.TerminalColor(tui.Theme.Dim)
	if on {
		color = tui.Theme.AccentBright
	}
	return []tui.Seg{tui.Sg(label+":", tui.Theme.Dim), tui.Seg{Text: value, Fg: color}, tui.Plain(" ")}
}

func orDot(s string) string {
	if s == "" {
		return "·"
	}
	return s
}

func (p *Audit) viewEntry(ctx tui.PanelContext) []string {
	rows, _ := p.pageRows()
	e, ok := p.current(rows)
	if !ok {
		return p.viewLogs(ctx)
	}
	bodyW := tui.MaxInt(20, ctx.Cols-4)
	width := ctx.Cols - 2

	why := tui.WhyBlock(e.decision, e.reason, e.rule, e.dlp, e.burst, bodyW)
	whyN, whyFG := len(why), tui.WhyColor(e.decision, e.burst, e.dlp)
	content := why
	argsText := "(no arguments recorded)"
	if e.args != "" {
		argsText = tui.PrettyJson(e.args)
	} else if len(content) == 0 && e.reason != "" {
		argsText = e.reason
	}
	content = append(content, tui.WrapLines(argsText, bodyW)...)

	bodyRows := tui.MaxInt(4, ctx.Rows-6-boolInt(p.frozen))
	maxScroll := tui.MaxInt(0, len(content)-bodyRows)
	off := tui.MinInt(p.detailScroll, maxScroll)

	head := []tui.Seg{
		{Text: " ENTRY ", Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexPanelBG), Bold: true},
		tui.Sgb("  "+e.decision, tui.DecisionColor(e.decision)),
		tui.Sgb("  "+e.tool, tui.Theme.Accent),
	}
	if len(e.dlp) > 0 {
		head = append(head, tui.Sg("  DLP!", tui.Theme.Bad))
	}
	if e.burst {
		head = append(head, tui.Sg("  BURST", tui.Theme.Warn))
	}
	head = append(head, tui.Sg("  ← back", tui.Theme.Dim))

	evalText, evalColor := ", ", lipgloss.TerminalColor(nil)
	if e.evalMs != nil {
		evalText = tui.Num(*e.evalMs) + "ms"
		if *e.evalMs > 500 {
			evalColor = tui.Theme.Warn
		}
	}
	rule, ruleColor := e.rule, lipgloss.TerminalColor(tui.Theme.Dim)
	if rule == "" {
		rule = ", "
	} else if e.decision != "ALLOW" {
		ruleColor = tui.Theme.Bad
	}
	scrollNote := ""
	if maxScroll > 0 {
		scrollNote = " · ▼" + strconv.Itoa(maxScroll-off) + " more · ↑↓ scroll"
	}

	lines := []string{}
	if b := p.copyBanner(width); b != "" {
		lines = append(lines, b)
	}
	lines = append(lines,
		tui.RenderRow(width, head...),
		tui.RenderRow(width,
			tui.Sg("│ when ", tui.Theme.Dim), tui.Plain(time.UnixMilli(e.at).Format("2006-01-02 15:04:05")),
			tui.Sg(" │ perm ", tui.Theme.Dim), tui.Plain(orEmDash(e.permission)),
			tui.Sg(" │ trust ", tui.Theme.Dim), tui.Plain(orEmDash(e.trust)),
			tui.Sg(" │ eval ", tui.Theme.Dim), tui.Seg{Text: evalText, Fg: evalColor},
			tui.Sg(" │ agent ", tui.Theme.Dim), tui.Plain(orEmDash(e.agent)),
			tui.Sg(" │", tui.Theme.Dim)),
		tui.RenderRow(width,
			tui.Sg("│ session ", tui.Theme.Dim), tui.Sg(orEmDash(e.session), tui.Theme.Dim),
			tui.Sg(" │ rule ", tui.Theme.Dim), tui.Seg{Text: rule, Fg: ruleColor},
			tui.Sg(" │", tui.Theme.Dim)),
		tui.PaneTitle("FULL CONTENT", strconv.Itoa(len(content))+" lines"+scrollNote+
			" · space copy · ← back", width))
	for i := 0; i < bodyRows; i++ {
		idx := off + i
		if idx >= len(content) {
			lines = append(lines, "")
			continue
		}
		if idx < whyN {
			lines = append(lines, tui.RenderRow(width, tui.Seg{Text: content[idx], Fg: whyFG, Bold: idx == 0}))
			continue
		}
		lines = append(lines, tui.RenderRow(width, tui.Plain(content[idx])))
	}
	return append(lines, tui.RenderRow(width,
		tui.Seg{Text: " ENTRY ", Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexPanelBG), Bold: true},
		tui.Seg{Text: " " + e.id + " ", Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexFooterBG)},
		tui.Seg{Text: " ↑↓ scroll · space copy · ? all keys · ← back · esc menu ",
			Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexPanelBG)}))
}

func (p *Audit) viewLogs(ctx tui.PanelContext) []string {
	width := ctx.Cols
	rows, total := p.pageRows()
	pages := p.pages(total)

	headerRows := 6 + boolInt(p.editing != "") +
		boolInt(p.note != nil) + boolInt(p.frozen)
	listRows := tui.MaxInt(4, ctx.Rows-headerRows)
	sel := tui.MinInt(p.sel, tui.MaxInt(0, len(rows)-1))
	start := tui.MinInt(tui.MaxInt(0, sel-(listRows-1)/2), tui.MaxInt(0, len(rows)-listRows))
	end := tui.MinInt(start+listRows, len(rows))

	head := []tui.Seg{tui.Sgb("LOGS", tui.Theme.AccentBright), tui.Sg(" ", tui.Theme.Dim)}
	head = append(head, chip("dec", orAll(auditDecisions[p.di]), p.di != 0)...)
	head = append(head, chip("sig", orAll(auditSignals[p.gi]), p.gi != 0)...)
	head = append(head, chip("tool", orDot(p.tool), p.tool != "")...)
	head = append(head, chip("agent", orDot(p.agent), p.agent != "")...)
	head = append(head, chip("search", orDot(p.search), p.search != "")...)

	hint := "press → to browse"
	if ctx.Focused {
		hint = "↑↓ select · enter full entry · ←→ page · ^R refresh · ? all keys"
	}

	var body []string
	body = append(body, p.strip(width))
	if b := p.copyBanner(width); b != "" {
		body = append(body, b)
	}
	body = append(body, tui.RenderRow(width, head...), tui.RenderRow(width, tui.Sg(hint, tui.Theme.Dim)))
	if p.note != nil {
		color := tui.Theme.OK
		if p.note.level == "bad" {
			color = tui.Theme.Bad
		}
		body = append(body, tui.RenderRow(width, tui.Sg(tui.Truncate(p.note.text, width), color)))
	}
	if p.editing != "" {
		body = append(body, tui.RenderRow(width, tui.Sg(p.editing+": ", tui.Theme.Warn))+p.input.View())
	}

	counts := strconv.Itoa(total) + " matched · page " + strconv.Itoa(tui.MinInt(p.page+1, pages)) +
		"/" + strconv.Itoa(pages) + " · " + strconv.Itoa(auditPage) + "/page · "
	if len(rows) > 0 {
		counts += strconv.Itoa(sel + 1)
	} else {
		counts += "0"
	}
	counts += "/" + strconv.Itoa(len(rows))
	if start > 0 {
		counts += " · ▲" + strconv.Itoa(start) + " newer"
	}
	if start+listRows < len(rows) {
		counts += " · ▼" + strconv.Itoa(len(rows)-start-listRows) + " older"
	}
	body = append(body, tui.RenderRow(width, tui.Sg(counts, tui.Theme.Dim)))

	for i := start; i < end; i++ {
		body = append(body, tui.StreamLine(rows[i].stream(),
			i == sel && ctx.Focused, true, width))
	}
	if len(rows) == 0 {
		body = append(body, tui.RenderRow(width, tui.Sg("(no entries, c clears filters)", tui.Theme.Dim)))
	}
	return tui.DataView(p.logsLoading() && !p.frozen, p.logsError(), false, "", width, body)
}

func orAll(s string) string {
	if s == "" {
		return "all"
	}
	return s
}

func orEmDash(s string) string {
	if s == "" {
		return ", "
	}
	return s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}