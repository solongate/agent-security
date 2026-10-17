// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func (p *Live) View(ctx PanelContext) string {
	now := ctx.Now.UnixMilli()
	innerW := ctx.Cols - 2
	if innerW < 20 {
		innerW = 20
	}
	spin := spinFrames[p.tick%len(spinFrames)]

	if p.stats == nil && p.localOn == nil {
		return renderRow(ctx.Cols, sg(spin+" connecting…", theme.Dim))
	}

	var lines []string
	switch {
	case p.help:
		lines = p.viewHelp(ctx, innerW, now)
	case p.mode == "inspect" && p.inspect != nil:
		lines = p.viewInspect(ctx, innerW, now)
	case p.mode == "layers":
		lines = p.viewLayers(ctx, innerW, now, spin)
	default:
		lines = p.viewMain(ctx, innerW, now, spin)
	}
	for i := range lines {
		lines[i] = " " + lines[i]
	}

	return clampBlock(strings.Join(lines, "\n"), ctx.Cols, ctx.Rows)
}

func (p *Live) titleBar(ctx PanelContext, width int, now int64, spin string) string {
	segs := []seg{
		{text: " SOLONGATE LIVE ", fg: lipgloss.Color("15"), bg: lipgloss.Color(hexTitleBG), bold: true},

		{text: " " + spin + " up " + fmtUp(now-p.start.UnixMilli()) + " · " + hhmmss(now) +
			" · guard " + strconv.Itoa(p.evalNow()) + "ms ", fg: theme.White, bg: lipgloss.Color(hexPanelBG)},
	}
	lastDeny := p.lastDeny()
	switch {
	case p.frozen:
		segs = append(segs, seg{text: " ⏵ COPY MODE, screen frozen, select & copy freely · space resume ",
			fg: lipgloss.Color(hexOKFG), bg: lipgloss.Color(hexOKBG), bold: true})
	case now < p.pausedUntil:
		segs = append(segs, seg{text: " RATE LIMITED · backing off ",
			fg: lipgloss.Color(hexWarnFG), bg: lipgloss.Color(hexWarnBG), bold: true})
	case lastDeny != nil:
		segs = append(segs, seg{text: " ⚠ " + hhmmss(lastDeny.At) + " " + lastDeny.Tool + " DENIED ",
			fg: lipgloss.Color(hexBadFG), bg: lipgloss.Color(hexBadBG), bold: true})
	default:
		segs = append(segs, seg{text: " ✓ clean ", fg: theme.White, bg: lipgloss.Color(hexPanelBG)})
	}
	return renderRow(width, segs...)
}

func (p *Live) evalNow() int {
	if len(p.eval) == 0 {
		return 0
	}
	return p.eval[len(p.eval)-1]
}

func (p *Live) evalMedian() int {
	if len(p.eval) == 0 {
		return 0
	}
	s := append([]int(nil), p.eval...)
	sort.Ints(s)
	return s[len(s)/2]
}

func (p *Live) lastDeny() *streamItem {
	for i := len(p.merged) - 1; i >= 0; i-- {
		if p.merged[i].Decision != "ALLOW" {
			return &p.merged[i]
		}
	}
	return nil
}

func (p *Live) searchRow(width, matchCount int) string {
	segs := []seg{{text: "⌕ search: ", fg: theme.Dim, bold: p.editingSearch}}
	if p.editingSearch {
		segs[0].fg = theme.Warn
		return renderRow(width, segs...) +
			p.input.View() +
			renderRow(0, sg("  "+strconv.Itoa(matchCount)+" match · enter// done · empty clears", theme.Dim))
	}
	if p.search != "" {
		segs = append(segs,
			sgb(p.search, theme.AccentBright),
			sg("  "+strconv.Itoa(matchCount)+" match · press / to edit · type to clear", theme.Dim))
		return renderRow(width, segs...)
	}
	segs = append(segs, sg("press / to filter the stream by tool, agent, command…", theme.Dim))
	return renderRow(width, segs...)
}

var liveHelp = []helpGroup{
	{"Stream", [][2]string{
		{"↑↓ / PgUp PgDn", "select a row (window follows)"},
		{"enter", "open the FULL entry content"},
		{"w", "whitelist the selected DENY (adds ALLOW rule)"},
		{"b", "block the selected ALLOW (adds DENY rule)"},
		{"d / x / r", "filter: denies / dlp hits / rate-limit bursts"},
		{"/", "live search (tool, agent, command…) · enter done"},
		{"s", "session picker"},
		{"l", "layers detail (rate limit · dlp · guard)"},
		{"e", "export visible rows → ~/.solongate/live-export.jsonl"},
		{"space", "copy mode: freeze screen for mouse selection"},
		{"esc", "back to menu"},
		{"q", "quit TUI"},
	}},
	{"Entry (full content)", [][2]string{
		{"↑↓ / PgUp PgDn", "scroll the content"},
		{"space", "copy mode (freeze, then select with mouse)"},
		{"←", "back to where you came from"},
	}},
	{"Anywhere", [][2]string{{"?", "this help"}, {"any key", "close this help"}}},
}

func (p *Live) viewHelp(ctx PanelContext, width int, now int64) []string {
	lines := []string{
		p.titleBar(ctx, width, now, spinFrames[p.tick%len(spinFrames)]),
		renderRow(width, sgb("LIVE, all keys", theme.AccentBright)),
		"",
	}
	lines = append(lines, helpBlock(liveHelp, 20, width)...)
	return append(lines, renderRow(width, sg("press any key to close", theme.Dim)))
}

func (p *Live) viewInspect(ctx PanelContext, width int, now int64) []string {
	e := *p.inspect
	bodyW := maxInt(20, ctx.Cols-4)

	why := whyBlock(e.Decision, e.Reason, e.Rule, e.DLPNames, e.Burst, bodyW)
	whyN, whyFG := len(why), whyColor(e.Decision, e.Burst, e.DLPNames)
	content := why
	argsText := "(no arguments recorded)"
	if len(e.Args) > 0 && string(e.Args) != "null" {
		argsText = prettyJson(string(e.Args))
	} else if len(content) == 0 && strings.TrimSpace(e.Detail) != "" {
		argsText = e.Detail
	}
	content = append(content, wrapLines(argsText, bodyW)...)
	bodyRows := maxInt(4, ctx.Rows-6)
	maxScroll := maxInt(0, len(content)-bodyRows)
	off := minInt(p.inspectScroll, maxScroll)

	head := []seg{
		{text: " ENTRY ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
		sgb("  "+e.Decision, decisionColor(e.Decision)),
		sgb("  "+e.Tool, theme.Accent),
	}
	if e.DLP {
		head = append(head, sg("  DLP!", theme.Bad))
	}
	if e.Burst {
		head = append(head, sg("  BURST", theme.Warn))
	}
	head = append(head, sg("  ← back", theme.Dim))

	evalText := ", "
	evalColor := lipgloss.TerminalColor(nil)
	if e.EvalMs != nil {
		evalText = num(*e.EvalMs) + "ms"
		if *e.EvalMs > 500 {
			evalColor = theme.Warn
		}
	}
	perm := e.Permission
	if perm == "" {
		perm = ", "
	}
	agent := e.Agent
	if agent == "" {
		agent = ", "
	}
	session := e.Session
	if session == "" {
		session = ", "
	}
	rule := e.Rule
	ruleColor := lipgloss.TerminalColor(theme.Dim)
	if rule == "" {
		rule = ", "
	} else if e.Decision != "ALLOW" {
		ruleColor = theme.Bad
	}

	scrollNote := ""
	if maxScroll > 0 {
		scrollNote = " · ▼" + strconv.Itoa(maxScroll-off) + " more · ↑↓ scroll"
	}

	lines := []string{
		p.titleBar(ctx, width, now, spinFrames[p.tick%len(spinFrames)]),
		renderRow(width, head...),
		renderRow(width,
			sg("│ when ", theme.Dim), plain(time.UnixMilli(e.At).Format("2006-01-02 15:04:05")),
			sg(" │ perm ", theme.Dim), plain(perm),
			sg(" │ eval ", theme.Dim), seg{text: evalText, fg: evalColor},
			sg(" │ agent ", theme.Dim), plain(agent),
			sg(" │", theme.Dim)),
		renderRow(width,
			sg("│ session ", theme.Dim), sg(session, theme.Dim),
			sg(" │ rule ", theme.Dim), seg{text: rule, fg: ruleColor},
			sg(" │", theme.Dim)),
		paneTitle("FULL CONTENT",
			strconv.Itoa(len(content))+" lines"+scrollNote+" · space copy · ← back", width),
	}
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
		seg{text: " " + e.ID + " ", fg: theme.White, bg: lipgloss.Color(hexFooterBG)},
		seg{text: " ↑↓ scroll · space copy · ? all keys · ← back · esc menu ",
			fg: theme.White, bg: lipgloss.Color(hexPanelBG)}))
}

func (p *Live) viewLayers(ctx PanelContext, width int, now int64, spin string) []string {
	rl := p.insights.Layers.RateLimit
	dl := p.insights.Layers.DLP
	barW := maxInt(10, minInt(40, width-30))

	var body []string
	push := func(s string) { body = append(body, s) }
	section := func(label, mode, note string) {
		m := mode
		if m == "" {
			m = "?"
		}
		segs := []seg{sgb("▎"+padEnd(label, 10), theme.AccentBright), sgb(padEnd(m, 8), modeColor(mode))}
		if note != "" {
			segs = append(segs, sg(note, theme.Dim))
		}
		push(renderRow(width, segs...))
	}
	kv := func(k string, value seg) {
		push(renderRow(width, sg(padEnd("  "+k, 16), theme.Dim), value))
	}

	burstsInBuf, dlpInBuf, minuteNow := 0, 0, 0
	for _, e := range p.merged {
		if e.Burst {
			burstsInBuf++
		}
		if e.DLP {
			dlpInBuf++
		}
		if now-e.At < 60_000 {
			minuteNow++
		}
	}

	rlMode, rlNote := "", "no limit enforcement"
	if rl != nil {
		rlMode = rl.Mode
		switch rl.Mode {
		case "block":
			rlNote = "over-limit calls are DENIED"
		case "detect":
			rlNote = "over-limit calls are observed & flagged rl:yes"
		}
	}
	section("RATELIMIT", rlMode, rlNote)
	limits := "none configured"
	if rl != nil && (rl.PerMinute != 0 || rl.PerHour != 0 || rl.PerDay != 0) {
		limits = orDash(rl.PerMinute) + "/min · " + orDash(rl.PerHour) + "/hour · " + orDash(rl.PerDay) + "/day"
	}
	kv("limits", plain(limits))
	kv("load now", plain(strconv.Itoa(minuteNow)+" calls in the last 60s"))
	if rl != nil && rl.PerMinute > 0 {
		color := lipgloss.TerminalColor(theme.Accent)
		if minuteNow > rl.PerMinute {
			color = theme.Bad
		}
		push(hbar("  load/min", minuteNow, rl.PerMinute, barW, color, width))
	}
	burstColor := lipgloss.TerminalColor(theme.Dim)
	if burstsInBuf > 0 {
		burstColor = theme.Warn
	}
	kv("bursts", seg{text: strconv.Itoa(burstsInBuf) + " flagged in the live buffer", fg: burstColor})
	push("")

	dlMode, dlNote := "", "no secret scanning"
	if dl != nil {
		dlMode = dl.Mode
		switch dl.Mode {
		case "block":
			dlNote = "secrets in arguments are DENIED + redacted"
		case "detect":
			dlNote = "secrets observed & flagged dlp:yes, output redacted"
		}
	}
	section("DLP", dlMode, dlNote)
	dlpColor := lipgloss.TerminalColor(theme.Dim)
	if dlpInBuf > 0 {
		dlpColor = theme.Bad
	}
	kv("hits", seg{text: strconv.Itoa(dlpInBuf) + " flagged in the live buffer", fg: dlpColor})
	var builtin []string
	if dl != nil {
		builtin = dl.Patterns
	}
	if len(builtin) > 0 {
		kv("builtin", plain(strconv.Itoa(len(builtin))+" patterns enabled"))
	} else {
		kv("builtin", plain("none enabled"))
	}
	for _, line := range wrapLines(strings.Join(builtin, " · "), maxInt(20, width-18)) {
		if line == "" {
			continue
		}
		push(renderRow(width, sg("                "+line, theme.Dim)))
	}
	customCount := 0
	if dl != nil {
		customCount = len(dl.Custom)
	}
	if customCount > 0 {
		kv("custom", plain(strconv.Itoa(customCount)+" patterns"))
		for _, c := range dl.Custom {
			name := c.Name
			if name == "" {
				name = "custom"
			}
			push(renderRow(width,
				sg("                ", theme.Dim),
				sg(padEnd(truncate(name, 24), 25), theme.Accent),
				sg(truncate(c.Re, maxInt(10, width-44)), theme.Dim)))
		}
	} else {
		kv("custom", plain("none"))
	}

	hits := p.insights.DLPByPattern
	total := 0
	for _, h := range hits {
		total += h.Count
	}
	if total > 0 {
		kv("pattern hits", seg{text: strconv.Itoa(total) + " in the last 7 days", fg: theme.Bad})
	} else {
		kv("pattern hits", sg("none in the last 7 days", theme.Dim))
	}
	push("")

	guardMode := "?"
	if p.guard != nil {
		guardMode = "stale"
		if p.guard.UpToDate {
			guardMode = "ok"
		}
	}
	section("GUARD", guardMode, "the PreToolUse hook enforcing all of the above")
	if p.guard != nil {
		installed := "?"
		if p.guard.Installed != nil {
			installed = strconv.Itoa(*p.guard.Installed)
		}
		state := " (latest)"
		color := lipgloss.TerminalColor(theme.OK)
		if !p.guard.UpToDate {
			state = " → v" + strconv.Itoa(p.guard.Latest) + " available"
			color = theme.Warn
		}
		devices := " device"
		if p.guard.DeviceCount != 1 {
			devices = " devices"
		}
		kv("hooks", seg{text: "v" + installed + state + " · " + strconv.Itoa(p.guard.DeviceCount) + devices, fg: color})
	} else {
		kv("hooks", sg("loading…", theme.Dim))
	}
	if p.ring != nil {
		kv("local eval", sg("avg "+strconv.Itoa(p.ring.avgMs)+"ms over "+strconv.Itoa(p.ring.count)+" recent calls", theme.OK))
	} else {
		kv("local eval", sg("no local ring in cwd", theme.Dim))
	}

	bodyRows := maxInt(4, ctx.Rows-4)
	maxScroll := maxInt(0, len(body)-bodyRows)
	off := minInt(p.layersScroll, maxScroll)

	extra := ""
	if !p.insightsLoaded {
		extra += spin + " loading · "
	}
	if maxScroll > 0 {
		extra += "▼" + strconv.Itoa(maxScroll-off) + " more · ↑↓ scroll · "
	}
	extra += "l or ← back"

	lines := []string{
		p.titleBar(ctx, width, now, spin),
		renderRow(width,
			seg{text: " LAYERS ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
			sg("  security layers, limits and patterns · insights window: last 7 days", theme.Dim),
			sg("  ← back", theme.Dim)),
		paneTitle("LAYERS", extra, width),
	}
	for i := 0; i < bodyRows; i++ {
		if off+i >= len(body) {
			lines = append(lines, "")
			continue
		}
		lines = append(lines, body[off+i])
	}
	return append(lines, renderRow(width,
		seg{text: " LAYERS ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
		seg{text: " rate limit · dlp · guard ", fg: theme.White, bg: lipgloss.Color(hexFooterBG)},
		seg{text: " ↑↓ scroll · ? all keys · ← back · esc menu ", fg: theme.White, bg: lipgloss.Color(hexPanelBG)}))
}

func orDash(n int) string {
	if n == 0 {
		return ", "
	}
	return strconv.Itoa(n)
}

func (p *Live) viewMain(ctx PanelContext, width int, now int64, spin string) []string {
	chartH := p.chartHeight(ctx)
	colH := p.colHeight(ctx)
	streamRows := p.streamRows(ctx)
	leftW := width * 55 / 100
	rightW := width - leftW - 2
	colW := maxInt(20, (width-3)/2)

	rl := p.insights.Layers.RateLimit
	dl := p.insights.Layers.DLP

	minuteNow := 0
	for _, e := range p.merged {
		if now-e.At < 60_000 {
			minuteNow++
		}
	}

	lines := []string{p.titleBar(ctx, width, now, spin)}

	counters := []seg{sg("│ calls ", theme.Dim)}
	if p.stats != nil {
		counters = append(counters,
			seg{text: strconv.Itoa(p.stats.TotalCalls), bold: true},
			sg(" │ allow ", theme.Dim), sg(strconv.Itoa(p.stats.Allowed), theme.OK),
			sg(" │ deny ", theme.Dim), sgb(strconv.Itoa(p.stats.Denied), theme.Bad))
	} else {
		counters = append(counters,
			seg{text: "····", bold: true},
			sg(" │ allow ", theme.Dim), sg("···", theme.OK),
			sg(" │ deny ", theme.Dim), sgb("··", theme.Bad))
	}
	counters = append(counters, sg(" │ local ", theme.Dim))
	if p.localOn != nil && *p.localOn {
		counters = append(counters, sg("✓", theme.OK))
	} else {
		counters = append(counters, sg("off", theme.Dim))
	}
	counters = append(counters,
		sg(" │ rl ", theme.Dim), sg(modeOr(rl.mode()), modeColor(rl.mode())),
		sg(" │ dlp ", theme.Dim), sg(modeOr(dl.mode()), modeColor(dl.mode())),
		sg(" │ hooks ", theme.Dim))
	if p.guard != nil {
		installed := "?"
		if p.guard.Installed != nil {
			installed = strconv.Itoa(*p.guard.Installed)
		}
		text := "v" + installed
		color := lipgloss.TerminalColor(theme.OK)

		if !p.guard.UpToDate && p.guard.Latest > 0 && p.guard.Installed != nil {
			text += "→v" + strconv.Itoa(p.guard.Latest)
			color = theme.Warn
		}
		text += " " + strconv.Itoa(p.guard.DeviceCount) + "dev"
		counters = append(counters, seg{text: text, fg: color})
	} else {
		counters = append(counters, sg("·", theme.Warn))
	}
	counters = append(counters, sg(" │", theme.Dim))
	lines = append(lines, renderRow(width, counters...))

	if a := p.activeAlert(now); a != nil {
		label, fg, bg := "⏸ IDLE", hexWarnFG, hexWarnBG
		if a.level == "bad" {
			label, fg, bg = "⛔ ALERT", hexBadFG, hexBadBG
		}
		lines = append(lines, renderRow(width, seg{
			text: " " + label + " · " + truncate(a.msg, width-14) + " ",
			fg:   lipgloss.Color(fg), bg: lipgloss.Color(bg), bold: true}))
	}
	if act := p.activeAction(now); act != nil {
		fg, bg := hexOKFG, hexOKBG
		if act.level == "bad" {
			fg, bg = hexBadFG, hexBadBG
		}
		lines = append(lines, renderRow(width, seg{
			text: " " + truncate(act.text, width-4) + " ",
			fg:   lipgloss.Color(fg), bg: lipgloss.Color(bg), bold: true}))
	}

	nowSlot := now / 10_000
	traffic := make([]int, 60)
	trafficHot := make([]bool, 60)
	peak := 0
	for _, e := range p.merged {
		idx := 59 - int(nowSlot-e.At/10_000)
		if idx >= 0 && idx < 60 {
			traffic[idx]++
			if traffic[idx] > peak {
				peak = traffic[idx]
			}
			if e.Decision != "ALLOW" {
				trafficHot[idx] = true
			}
		}
	}

	evalHotAt := maxFloat(50, float64(p.evalMedian())*2.5)

	trace := make([]int, len(p.pulse))
	evalHot := make([]bool, len(p.pulse))
	for i, v := range p.pulse {
		trace[i] = maxInt(1, v)
		evalHot[i] = float64(v) > evalHotAt
	}
	left := append([]string{paneTitle("TRAFFIC",
		"calls/10s · last 10m · live · peak "+strconv.Itoa(peak)+" · red = denials", leftW)},

		columnChart(traffic, trafficHot, chartH, leftW, 10, theme.Accent, theme.Bad)...)
	right := append([]string{paneTitle("HEARTBEAT",
		"live · ms per decision · now "+strconv.Itoa(p.evalNow())+" · med "+strconv.Itoa(p.evalMedian())+
			" · amber >"+strconv.Itoa(int(evalHotAt+0.5)), rightW)},

		columnChart(trace, evalHot, chartH, rightW, int(evalHotAt+0.5), theme.White, lipgloss.Color(hexWarnFG))...)
	lines = append(lines, joinColumns([][]string{left, right}, []int{leftW, rightW}, 1+chartH)...)

	layersCol := []string{paneTitle("LAYERS", "l = inspect", colW)}
	layersCol = append(layersCol, renderRow(colW,
		sg(padEnd("RATELIMIT ", 10), theme.Dim),
		sg(padEnd(modeOr(rl.mode()), 7), modeColor(rl.mode())),
		sg(rl.summary(minuteNow), theme.Dim)))
	if rl != nil && rl.PerMinute > 0 {
		color := lipgloss.TerminalColor(theme.Accent)
		if minuteNow > rl.PerMinute {
			color = theme.Bad
		}
		layersCol = append(layersCol, hbar("load/min", minuteNow, rl.PerMinute, maxInt(6, colW-16), color, colW))
	}
	builtinN, customN := 0, 0
	if dl != nil {
		builtinN, customN = len(dl.Patterns), len(dl.Custom)
	}
	layersCol = append(layersCol, renderRow(colW,
		sg(padEnd("DLP", 10), theme.Dim),
		sg(padEnd(modeOr(dl.mode()), 7), modeColor(dl.mode())),
		sg(strconv.Itoa(builtinN)+" builtin · "+strconv.Itoa(customN)+" custom", theme.Dim)))

	dlpTotal := 0
	for _, d2 := range p.insights.DLPByPattern {
		dlpTotal += d2.Count
	}
	if dlpTotal > 0 {
		layersCol = append(layersCol, renderRow(colW,
			sg(padEnd("", 10), theme.Dim),
			sgb(strconv.Itoa(dlpTotal), theme.Bad),
			sg(" hits in last 7 days", theme.Dim)))
	} else {

		layersCol = append(layersCol, renderRow(colW, sg("          no dlp hits in last 7 days", theme.Dim)))
	}
	guardSegs := []seg{sg(padEnd("GUARD", 10), theme.Dim)}
	if p.ring != nil {
		guardSegs = append(guardSegs, sg("local ✓ ", theme.OK),
			sg("eval avg "+strconv.Itoa(p.ring.avgMs)+"ms", theme.Dim))
	} else {
		guardSegs = append(guardSegs, sg("no local ring in cwd", theme.Dim))
	}
	layersCol = append(layersCol, renderRow(colW, guardSegs...))

	eventCol := []string{paneTitle("EVENT LOG", "system heartbeat", colW)}
	tail := p.events
	if len(tail) > colH-1 {
		tail = tail[len(tail)-(colH-1):]
	}
	for _, l := range tail {
		tickColor := lipgloss.TerminalColor(lipgloss.Color(hexEventTick))
		msgColor := lipgloss.TerminalColor(theme.Dim)
		mark := "▸ "
		switch l.level {
		case "bad":
			tickColor, msgColor = theme.Bad, theme.Bad
		case "warn":
			tickColor = theme.Warn
		case "beat":

			mark, tickColor = "• ", theme.OK
		}
		eventCol = append(eventCol, renderRow(colW,
			sg(hhmmss(l.ts)+" ", theme.Dim),
			seg{text: mark, fg: tickColor},
			seg{text: l.msg, fg: msgColor}))
	}
	lines = append(lines, joinColumns([][]string{layersCol, eventCol},
		[]int{colW, colW}, colH)...)

	visible := p.visibleDesc()
	sel := minInt(maxInt(0, p.sel), maxInt(0, len(visible)-1))
	streamBody := maxInt(3, streamRows-1)
	maxScroll := maxInt(0, len(visible)-streamBody)
	scroll := minInt(maxInt(0, sel-(streamBody-1)/2), maxScroll)

	extra := strconv.Itoa(sel+1) + "/" + strconv.Itoa(len(visible))
	if p.signal != "none" {
		extra += " · " + p.signal
	}
	if strings.TrimSpace(p.search) != "" {
		extra += " · search"
	}
	extra += " · enter full entry · ? all keys"
	lines = append(lines, paneTitle("TOOL STREAM", extra, width))

	body := []string{p.searchRow(width, len(visible))}
	switch {

	case p.localOn != nil && *p.localOn && !p.localSetting.UsableHere:

		body = append(body, renderRow(width,
			sg("local logs on", theme.Warn),
			sg(", "+p.localSetting.ConfiguredPath+" is not a folder on this device · writing to "+
				p.localSetting.File, theme.Dim)))
	case p.localOn != nil && *p.localOn && len(p.local) == 0:
		body = append(body, renderRow(width,
			sg("local logs on", theme.OK),
			sg(", no entries yet · hooks write "+p.localSetting.File, theme.Dim)))
	}
	if len(visible) == 0 {

		body = append(body, renderRow(width, sg(spin+" awaiting traffic…", theme.Dim)))
	}
	for i := 0; i < streamBody && scroll+i < len(visible); i++ {
		e := visible[scroll+i]
		body = append(body, streamLine(e.row(), scroll+i == sel, false, width))
	}
	for i := 0; i < streamRows; i++ {
		if i < len(body) {
			lines = append(lines, body[i])
		} else {
			lines = append(lines, "")
		}
	}

	localState := "off"
	if p.localOn != nil && *p.localOn {
		localState = "on"
	}
	toolCounts := newCounter()
	for _, e := range p.merged {
		toolCounts.add(e.Tool)
	}
	topTools := toolCounts.sorted()
	if len(topTools) > 3 {
		topTools = topTools[:3]
	}
	top := joinCounts(topTools, " ")
	if top == "" {
		top = ", "
	}
	return append(lines, renderRow(width,
		seg{text: " LIVE ", fg: theme.White, bg: lipgloss.Color(hexPanelBG), bold: true},
		seg{text: " local-log " + localState + " · " + strconv.Itoa(len(p.local)) +
			" entries · top " + top + " ",
			fg: theme.White, bg: lipgloss.Color(hexFooterBG)},
		seg{text: " ↑↓ select · enter full entry · / search · space copy · ? all keys · esc menu · q quit ",
			fg: theme.White, bg: lipgloss.Color(hexPanelBG)}))
}

func modeOr(m string) string {
	if m == "" {
		return "?"
	}
	return m
}

func columnChart(series []int, hot []bool, height, width, floor int, color, hotColor lipgloss.TerminalColor) []string {
	if width < 1 {
		width = 1
	}
	data := make([]int, width)
	hotData := make([]bool, width)
	pad := width - len(series)
	if pad < 0 {
		series = series[len(series)-width:]
		if len(hot) > width {
			hot = hot[len(hot)-width:]
		}
		pad = 0
	}
	for i := range series {
		data[pad+i] = series[i]
		if i < len(hot) {
			hotData[pad+i] = hot[i]
		}
	}

	max := floor
	if max < 1 {
		max = 1
	}
	for _, v := range data {
		if v > max {
			max = v
		}
	}
	lines := make([]string, 0, height)
	for r := height; r >= 1; r-- {
		segs := make([]seg, 0, 8)
		for i, v := range data {
			frac := float64(v) / float64(max)
			ch := " "
			switch {
			case frac >= float64(r)/float64(height):
				ch = "█"
			case frac >= (float64(r)-0.5)/float64(height):
				ch = "▄"
			case r == 1:
				ch = "▁"
			}
			c := color
			if r == 1 && v == 0 {
				c = lipgloss.Color(hexDimFloor)
			} else if hotData[i] {
				c = hotColor
			}
			if n := len(segs); n > 0 && segs[n-1].fg == c {
				segs[n-1].text += ch
			} else {
				segs = append(segs, seg{text: ch, fg: c})
			}
		}
		lines = append(lines, renderRow(width, segs...))
	}
	return lines
}

func hbar(label string, value, max, width int, color lipgloss.TerminalColor, maxw int) string {
	filled := 0
	if max > 0 {
		filled = int(float64(value)/float64(max)*float64(width) + 0.5)
	}
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	return renderRow(maxw,
		sg(padEnd(label, 10), theme.Dim),
		sg(strings.Repeat("█", filled), color),
		sg(strings.Repeat("░", width-filled), lipgloss.Color(hexDimFloor)),
		sg(" "+strconv.Itoa(value), theme.Dim))
}

func joinColumns(cols [][]string, widths []int, height int) []string {
	out := make([]string, 0, height)
	for r := 0; r < height; r++ {
		parts := make([]string, 0, len(cols))
		for c, block := range cols {
			line := ""
			if r < len(block) {
				line = block[r]
			}
			w := lipgloss.Width(line)
			if w < widths[c] {
				line += strings.Repeat(" ", widths[c]-w)
			}
			parts = append(parts, line)
		}
		out = append(out, strings.Join(parts, "  "))
	}
	return out
}

type counter struct {
	order []string
	n     map[string]int
}

func newCounter() *counter { return &counter{n: map[string]int{}} }

func (c *counter) add(k string) {
	if _, ok := c.n[k]; !ok {
		c.order = append(c.order, k)
	}
	c.n[k]++
}

type countEntry struct {
	key string
	n   int
}

func (c *counter) sorted() []countEntry {
	out := make([]countEntry, 0, len(c.order))
	for _, k := range c.order {
		out = append(out, countEntry{k, c.n[k]})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].n > out[j].n })
	return out
}

func joinCounts(entries []countEntry, sep string) string {
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		parts = append(parts, e.key+"×"+strconv.Itoa(e.n))
	}
	return strings.Join(parts, sep)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}