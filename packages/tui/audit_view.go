// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/solongate/agent-security/packages/core/config"
)

var auditHelp = []helpGroup{
	{"Logs", [][2]string{
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

	{"Anywhere in Audit", [][2]string{
		{"space", "copy mode: freeze screen for mouse selection"},
		{"?", "this help · any key closes"},
		{"esc", "back to the menu"},
	}},
	{"Entry (full content)", [][2]string{
		{"↑↓ / PgUp PgDn", "scroll the reason + arguments"},
		{"space", "copy mode (freeze, then select)"},
		{"← / esc", "back to the list"},
	}},
}

func (p *Audit) View(ctx PanelContext) string {
	var lines []string
	switch {
	case p.help:
		lines = p.viewHelp(ctx)
	case p.view == "detail" && p.hasRows():
		lines = p.viewEntry(ctx)
	default:
		lines = p.viewLogs(ctx)
	}

	return clampBlock(strings.Join(lines, "\n"), ctx.Cols, ctx.Rows)
}

func (p *Audit) hasRows() bool {
	rows, _ := p.pageRows()
	return len(rows) > 0
}

func (p *Audit) viewHelp(ctx PanelContext) []string {
	note := "· press any key to close · space = copy mode (works here too)"
	if p.frozen {
		note = "· screen frozen, space resumes, other keys are locked"
	}
	lines := []string{}
	if b := p.copyBanner(ctx.Cols); b != "" {
		lines = append(lines, b)
	}
	lines = append(lines, renderRow(ctx.Cols,
		sgb("AUDIT, all keys ", theme.AccentBright), sg(note, theme.Dim)), "")

	half := maxInt(20, (ctx.Cols-2)/2)
	left := helpBlock(auditHelp[:1], auditKeyColumn, half)
	right := helpBlock(auditHelp[1:], auditKeyColumn, half)
	rows := maxInt(len(left), len(right))
	return append(lines, joinColumns([][]string{left, right}, []int{half, half}, rows)...)
}

func (p *Audit) copyBanner(width int) string {
	if !p.frozen {
		return ""
	}
	return renderRow(width, seg{
		text: " ⏵ COPY MODE, screen frozen, select & copy freely · space resume ",
		fg:   lipgloss.Color(hexOKFG), bg: lipgloss.Color(hexOKBG), bold: true})
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

		return renderRow(width,
			seg{text: calls, bold: true}, sg(" calls · ", theme.Dim),
			sg(allow+" allow", theme.OK), sg(" · ", theme.Dim),
			sg(deny+" deny", theme.Bad), sg(" · "+policies+" policies", theme.Dim),
			sg(" · "+config.LocalLogFile(), theme.Dim))
	}
}

func chip(label, value string, on bool) []seg {
	color := lipgloss.TerminalColor(theme.Dim)
	if on {
		color = theme.AccentBright
	}
	return []seg{sg(label+":", theme.Dim), seg{text: value, fg: color}, plain(" ")}
}

func orDot(s string) string {
	if s == "" {
		return "·"
	}
	return s
}

func (p *Audit) viewEntry(ctx PanelContext) []string {
	rows, _ := p.pageRows()
	e, ok := p.current(rows)
	if !ok {
		return p.viewLogs(ctx)
	}
	bodyW := maxInt(20, ctx.Cols-4)
	width := ctx.Cols - 2

	why := whyBlock(e.decision, e.reason, e.rule, e.dlp, e.burst, bodyW)
	whyN, whyFG := len(why), whyColor(e.decision, e.burst, e.dlp)
	content := why
	argsText := "(no arguments recorded)"
	if e.args != "" {
		argsText = prettyJson(e.args)
	} else if len(content) == 0 && e.reason != "" {
		argsText = e.reason
	}
	content = append(content, wrapLines(argsText, bodyW)...)

	bodyRows := maxInt(4, ctx.Rows-6-boolInt(p.frozen))
	maxScroll := maxInt(0, len(content)-bodyRows)
	off := minInt(p.detailScroll, maxScroll)

	head := []seg{
		{text: " ENTRY ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
		sgb("  "+e.decision, decisionColor(e.decision)),
		sgb("  "+e.tool, theme.Accent),
	}
	if len(e.dlp) > 0 {
		head = append(head, sg("  DLP!", theme.Bad))
	}
	if e.burst {
		head = append(head, sg("  BURST", theme.Warn))
	}
	head = append(head, sg("  ← back", theme.Dim))

	evalText, evalColor := ", ", lipgloss.TerminalColor(nil)
	if e.evalMs != nil {
		evalText = num(*e.evalMs) + "ms"
		if *e.evalMs > 500 {
			evalColor = theme.Warn
		}
	}
	rule, ruleColor := e.rule, lipgloss.TerminalColor(theme.Dim)
	if rule == "" {
		rule = ", "
	} else if e.decision != "ALLOW" {
		ruleColor = theme.Bad
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
		renderRow(width, head...),
		renderRow(width,
			sg("│ when ", theme.Dim), plain(time.UnixMilli(e.at).Format("2006-01-02 15:04:05")),
			sg(" │ perm ", theme.Dim), plain(orEmDash(e.permission)),
			sg(" │ trust ", theme.Dim), plain(orEmDash(e.trust)),
			sg(" │ eval ", theme.Dim), seg{text: evalText, fg: evalColor},
			sg(" │ agent ", theme.Dim), plain(orEmDash(e.agent)),
			sg(" │", theme.Dim)),
		renderRow(width,
			sg("│ session ", theme.Dim), sg(orEmDash(e.session), theme.Dim),
			sg(" │ rule ", theme.Dim), seg{text: rule, fg: ruleColor},
			sg(" │", theme.Dim)),
		paneTitle("FULL CONTENT", strconv.Itoa(len(content))+" lines"+scrollNote+
			" · space copy · ← back", width))
	for i := 0; i < bodyRows; i++ {
		idx := off + i
		if idx >= len(content) {
			lines = append(lines, "")
			continue
		}
		if idx < whyN {
			lines = append(lines, renderRow(width, seg{text: content[idx], fg: whyFG, bold: idx == 0}))
			continue
		}
		lines = append(lines, renderRow(width, plain(content[idx])))
	}
	return append(lines, renderRow(width,
		seg{text: " ENTRY ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
		seg{text: " " + e.id + " ", fg: theme.White, bg: lipgloss.Color(hexFooterBG)},
		seg{text: " ↑↓ scroll · space copy · ? all keys · ← back · esc menu ",
			fg: theme.White, bg: lipgloss.Color(hexPanelBG)}))
}

func (p *Audit) viewLogs(ctx PanelContext) []string {
	width := ctx.Cols
	rows, total := p.pageRows()
	pages := p.pages(total)

	headerRows := 6 + boolInt(p.editing != "") +
		boolInt(p.note != nil) + boolInt(p.frozen)
	listRows := maxInt(4, ctx.Rows-headerRows)
	sel := minInt(p.sel, maxInt(0, len(rows)-1))
	start := minInt(maxInt(0, sel-(listRows-1)/2), maxInt(0, len(rows)-listRows))
	end := minInt(start+listRows, len(rows))

	head := []seg{sgb("LOGS", theme.AccentBright), sg(" ", theme.Dim)}
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
	body = append(body, renderRow(width, head...), renderRow(width, sg(hint, theme.Dim)))
	if p.note != nil {
		color := theme.OK
		if p.note.level == "bad" {
			color = theme.Bad
		}
		body = append(body, renderRow(width, sg(truncate(p.note.text, width), color)))
	}
	if p.editing != "" {
		body = append(body, renderRow(width, sg(p.editing+": ", theme.Warn))+p.input.View())
	}

	counts := strconv.Itoa(total) + " matched · page " + strconv.Itoa(minInt(p.page+1, pages)) +
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
	body = append(body, renderRow(width, sg(counts, theme.Dim)))

	for i := start; i < end; i++ {
		body = append(body, streamLine(rows[i].stream(),
			i == sel && ctx.Focused, true, width))
	}
	if len(rows) == 0 {
		body = append(body, renderRow(width, sg("(no entries, c clears filters)", theme.Dim)))
	}
	return dataView(p.logsLoading() && !p.frozen, p.logsError(), false, "", width, body)
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