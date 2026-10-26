// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package live

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/solongate/agent-security/packages/tui"
)

func (p *Live) View(ctx tui.PanelContext) string {
	now := ctx.Now.UnixMilli()
	innerW := ctx.Cols - 2
	if innerW < 20 {
		innerW = 20
	}
	spin := tui.SpinFrames[p.tick%len(tui.SpinFrames)]

	if p.stats == nil && p.localOn == nil {
		return tui.RenderRow(ctx.Cols, tui.Sg(spin+" connecting…", tui.Theme.Dim))
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

	return tui.ClampBlock(strings.Join(lines, "\n"), ctx.Cols, ctx.Rows)
}

func (p *Live) titleBar(ctx tui.PanelContext, width int, now int64, spin string) string {
	segs := []tui.Seg{
		{Text: " SOLONGATE LIVE ", Fg: lipgloss.Color("15"), Bg: lipgloss.Color(tui.HexTitleBG), Bold: true},

		{Text: " " + spin + " up " + tui.FmtUp(now-p.start.UnixMilli()) + " · " + tui.Hhmmss(now) +
			" · guard " + strconv.Itoa(p.evalNow()) + "ms ", Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexPanelBG)},
	}
	lastDeny := p.lastDeny()
	switch {
	case p.frozen:
		segs = append(segs, tui.Seg{Text: " ⏵ COPY MODE, screen frozen, select & copy freely · space resume ",
			Fg: lipgloss.Color(tui.HexOKFG), Bg: lipgloss.Color(tui.HexOKBG), Bold: true})
	case now < p.pausedUntil:
		segs = append(segs, tui.Seg{Text: " RATE LIMITED · backing off ",
			Fg: lipgloss.Color(tui.HexWarnFG), Bg: lipgloss.Color(tui.HexWarnBG), Bold: true})
	case lastDeny != nil:
		segs = append(segs, tui.Seg{Text: " ⚠ " + tui.Hhmmss(lastDeny.At) + " " + lastDeny.Tool + " DENIED ",
			Fg: lipgloss.Color(tui.HexBadFG), Bg: lipgloss.Color(tui.HexBadBG), Bold: true})
	default:
		segs = append(segs, tui.Seg{Text: " ✓ clean ", Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexPanelBG)})
	}
	return tui.RenderRow(width, segs...)
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
	segs := []tui.Seg{{Text: "⌕ search: ", Fg: tui.Theme.Dim, Bold: p.editingSearch}}
	if p.editingSearch {
		segs[0].Fg = tui.Theme.Warn
		return tui.RenderRow(width, segs...) +
			p.input.View() +
			tui.RenderRow(0, tui.Sg("  "+strconv.Itoa(matchCount)+" match · enter// done · empty clears", tui.Theme.Dim))
	}
	if p.search != "" {
		segs = append(segs,
			tui.Sgb(p.search, tui.Theme.AccentBright),
			tui.Sg("  "+strconv.Itoa(matchCount)+" match · press / to edit · type to clear", tui.Theme.Dim))
		return tui.RenderRow(width, segs...)
	}
	segs = append(segs, tui.Sg("press / to filter the stream by tool, agent, command…", tui.Theme.Dim))
	return tui.RenderRow(width, segs...)
}

var liveHelp = []tui.HelpGroup{
	{Title: "Stream", Keys: [][2]string{
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
	{Title: "Entry (full content)", Keys: [][2]string{
		{"↑↓ / PgUp PgDn", "scroll the content"},
		{"space", "copy mode (freeze, then select with mouse)"},
		{"←", "back to where you came from"},
	}},
	{Title: "Anywhere", Keys: [][2]string{{"?", "this help"}, {"any key", "close this help"}}},
}

func (p *Live) viewHelp(ctx tui.PanelContext, width int, now int64) []string {
	lines := []string{
		p.titleBar(ctx, width, now, tui.SpinFrames[p.tick%len(tui.SpinFrames)]),
		tui.RenderRow(width, tui.Sgb("LIVE, all keys", tui.Theme.AccentBright)),
		"",
	}
	lines = append(lines, tui.HelpBlock(liveHelp, 20, width)...)
	return append(lines, tui.RenderRow(width, tui.Sg("press any key to close", tui.Theme.Dim)))
}

func (p *Live) viewInspect(ctx tui.PanelContext, width int, now int64) []string {
	e := *p.inspect
	bodyW := tui.MaxInt(20, ctx.Cols-4)

	why := tui.WhyBlock(e.Decision, e.Reason, e.Rule, e.DLPNames, e.Burst, bodyW)
	whyN, whyFG := len(why), tui.WhyColor(e.Decision, e.Burst, e.DLPNames)
	content := why
	argsText := "(no arguments recorded)"
	if len(e.Args) > 0 && string(e.Args) != "null" {
		argsText = tui.PrettyJson(string(e.Args))
	} else if len(content) == 0 && strings.TrimSpace(e.Detail) != "" {
		argsText = e.Detail
	}
	content = append(content, tui.WrapLines(argsText, bodyW)...)
	bodyRows := tui.MaxInt(4, ctx.Rows-6)
	maxScroll := tui.MaxInt(0, len(content)-bodyRows)
	off := tui.MinInt(p.inspectScroll, maxScroll)

	head := []tui.Seg{
		{Text: " ENTRY ", Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexPanelBG), Bold: true},
		tui.Sgb("  "+e.Decision, tui.DecisionColor(e.Decision)),
		tui.Sgb("  "+e.Tool, tui.Theme.Accent),
	}
	if e.DLP {
		head = append(head, tui.Sg("  DLP!", tui.Theme.Bad))
	}
	if e.Burst {
		head = append(head, tui.Sg("  BURST", tui.Theme.Warn))
	}
	head = append(head, tui.Sg("  ← back", tui.Theme.Dim))

	evalText := ", "
	evalColor := lipgloss.TerminalColor(nil)
	if e.EvalMs != nil {
		evalText = tui.Num(*e.EvalMs) + "ms"
		if *e.EvalMs > 500 {
			evalColor = tui.Theme.Warn
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
	ruleColor := lipgloss.TerminalColor(tui.Theme.Dim)
	if rule == "" {
		rule = ", "
	} else if e.Decision != "ALLOW" {
		ruleColor = tui.Theme.Bad
	}

	scrollNote := ""
	if maxScroll > 0 {
		scrollNote = " · ▼" + strconv.Itoa(maxScroll-off) + " more · ↑↓ scroll"
	}

	lines := []string{
		p.titleBar(ctx, width, now, tui.SpinFrames[p.tick%len(tui.SpinFrames)]),
		tui.RenderRow(width, head...),
		tui.RenderRow(width,
			tui.Sg("│ when ", tui.Theme.Dim), tui.Plain(time.UnixMilli(e.At).Format("2006-01-02 15:04:05")),
			tui.Sg(" │ perm ", tui.Theme.Dim), tui.Plain(perm),
			tui.Sg(" │ eval ", tui.Theme.Dim), tui.Seg{Text: evalText, Fg: evalColor},
			tui.Sg(" │ agent ", tui.Theme.Dim), tui.Plain(agent),
			tui.Sg(" │", tui.Theme.Dim)),
		tui.RenderRow(width,
			tui.Sg("│ session ", tui.Theme.Dim), tui.Sg(session, tui.Theme.Dim),
			tui.Sg(" │ rule ", tui.Theme.Dim), tui.Seg{Text: rule, Fg: ruleColor},
			tui.Sg(" │", tui.Theme.Dim)),
		tui.PaneTitle("FULL CONTENT",
			strconv.Itoa(len(content))+" lines"+scrollNote+" · space copy · ← back", width),
	}
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
		tui.Seg{Text: " " + e.ID + " ", Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexFooterBG)},
		tui.Seg{Text: " ↑↓ scroll · space copy · ? all keys · ← back · esc menu ",
			Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexPanelBG)}))
}

func (p *Live) viewLayers(ctx tui.PanelContext, width int, now int64, spin string) []string {
	rl := p.insights.Layers.RateLimit
	dl := p.insights.Layers.DLP
	barW := tui.MaxInt(10, tui.MinInt(40, width-30))

	var body []string
	push := func(s string) { body = append(body, s) }
	section := func(label, mode, note string) {
		m := mode
		if m == "" {
			m = "?"
		}
		segs := []tui.Seg{tui.Sgb("▎"+tui.PadEnd(label, 10), tui.Theme.AccentBright), tui.Sgb(tui.PadEnd(m, 8), tui.ModeColor(mode))}
		if note != "" {
			segs = append(segs, tui.Sg(note, tui.Theme.Dim))
		}
		push(tui.RenderRow(width, segs...))
	}
	kv := func(k string, value tui.Seg) {
		push(tui.RenderRow(width, tui.Sg(tui.PadEnd("  "+k, 16), tui.Theme.Dim), value))
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
	kv("limits", tui.Plain(limits))
	kv("load now", tui.Plain(strconv.Itoa(minuteNow)+" calls in the last 60s"))
	if rl != nil && rl.PerMinute > 0 {
		color := lipgloss.TerminalColor(tui.Theme.Accent)
		if minuteNow > rl.PerMinute {
			color = tui.Theme.Bad
		}
		push(hbar("  load/min", minuteNow, rl.PerMinute, barW, color, width))
	}
	burstColor := lipgloss.TerminalColor(tui.Theme.Dim)
	if burstsInBuf > 0 {
		burstColor = tui.Theme.Warn
	}
	kv("bursts", tui.Seg{Text: strconv.Itoa(burstsInBuf) + " flagged in the live buffer", Fg: burstColor})
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
	dlpColor := lipgloss.TerminalColor(tui.Theme.Dim)
	if dlpInBuf > 0 {
		dlpColor = tui.Theme.Bad
	}
	kv("hits", tui.Seg{Text: strconv.Itoa(dlpInBuf) + " flagged in the live buffer", Fg: dlpColor})
	var builtin []string
	if dl != nil {
		builtin = dl.Patterns
	}
	if len(builtin) > 0 {
		kv("builtin", tui.Plain(strconv.Itoa(len(builtin))+" patterns enabled"))
	} else {
		kv("builtin", tui.Plain("none enabled"))
	}
	for _, line := range tui.WrapLines(strings.Join(builtin, " · "), tui.MaxInt(20, width-18)) {
		if line == "" {
			continue
		}
		push(tui.RenderRow(width, tui.Sg("                "+line, tui.Theme.Dim)))
	}
	customCount := 0
	if dl != nil {
		customCount = len(dl.Custom)
	}
	if customCount > 0 {
		kv("custom", tui.Plain(strconv.Itoa(customCount)+" patterns"))
		for _, c := range dl.Custom {
			name := c.Name
			if name == "" {
				name = "custom"
			}
			push(tui.RenderRow(width,
				tui.Sg("                ", tui.Theme.Dim),
				tui.Sg(tui.PadEnd(tui.Truncate(name, 24), 25), tui.Theme.Accent),
				tui.Sg(tui.Truncate(c.Re, tui.MaxInt(10, width-44)), tui.Theme.Dim)))
		}
	} else {
		kv("custom", tui.Plain("none"))
	}

	hits := p.insights.DLPByPattern
	total := 0
	for _, h := range hits {
		total += h.Count
	}
	if total > 0 {
		kv("pattern hits", tui.Seg{Text: strconv.Itoa(total) + " in the last 7 days", Fg: tui.Theme.Bad})
	} else {
		kv("pattern hits", tui.Sg("none in the last 7 days", tui.Theme.Dim))
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
		color := lipgloss.TerminalColor(tui.Theme.OK)
		if !p.guard.UpToDate {
			state = " → v" + strconv.Itoa(p.guard.Latest) + " available"
			color = tui.Theme.Warn
		}
		devices := " device"
		if p.guard.DeviceCount != 1 {
			devices = " devices"
		}
		kv("hooks", tui.Seg{Text: "v" + installed + state + " · " + strconv.Itoa(p.guard.DeviceCount) + devices, Fg: color})
	} else {
		kv("hooks", tui.Sg("loading…", tui.Theme.Dim))
	}
	if p.ring != nil {
		kv("local eval", tui.Sg("avg "+strconv.Itoa(p.ring.avgMs)+"ms over "+strconv.Itoa(p.ring.count)+" recent calls", tui.Theme.OK))
	} else {
		kv("local eval", tui.Sg("no local ring in cwd", tui.Theme.Dim))
	}

	bodyRows := tui.MaxInt(4, ctx.Rows-4)
	maxScroll := tui.MaxInt(0, len(body)-bodyRows)
	off := tui.MinInt(p.layersScroll, maxScroll)

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
		tui.RenderRow(width,
			tui.Seg{Text: " LAYERS ", Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexPanelBG), Bold: true},
			tui.Sg("  security layers, limits and patterns · insights window: last 7 days", tui.Theme.Dim),
			tui.Sg("  ← back", tui.Theme.Dim)),
		tui.PaneTitle("LAYERS", extra, width),
	}
	for i := 0; i < bodyRows; i++ {
		if off+i >= len(body) {
			lines = append(lines, "")
			continue
		}
		lines = append(lines, body[off+i])
	}
	return append(lines, tui.RenderRow(width,
		tui.Seg{Text: " LAYERS ", Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexPanelBG), Bold: true},
		tui.Seg{Text: " rate limit · dlp · guard ", Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexFooterBG)},
		tui.Seg{Text: " ↑↓ scroll · ? all keys · ← back · esc menu ", Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexPanelBG)}))
}

func orDash(n int) string {
	if n == 0 {
		return "-"
	}
	return strconv.Itoa(n)
}

func (p *Live) viewMain(ctx tui.PanelContext, width int, now int64, spin string) []string {
	chartH := p.chartHeight(ctx)
	colH := p.colHeight(ctx)
	streamRows := p.streamRows(ctx)
	leftW := width * 55 / 100
	rightW := width - leftW - 2
	colW := tui.MaxInt(20, (width-3)/2)

	rl := p.insights.Layers.RateLimit
	dl := p.insights.Layers.DLP

	minuteNow := 0
	for _, e := range p.merged {
		if now-e.At < 60_000 {
			minuteNow++
		}
	}

	lines := []string{p.titleBar(ctx, width, now, spin)}

	counters := []tui.Seg{tui.Sg("│ calls ", tui.Theme.Dim)}
	if p.stats != nil {
		counters = append(counters,
			tui.Seg{Text: strconv.Itoa(p.stats.TotalCalls), Bold: true},
			tui.Sg(" │ allow ", tui.Theme.Dim), tui.Sg(strconv.Itoa(p.stats.Allowed), tui.Theme.OK),
			tui.Sg(" │ deny ", tui.Theme.Dim), tui.Sgb(strconv.Itoa(p.stats.Denied), tui.Theme.Bad))
	} else {
		counters = append(counters,
			tui.Seg{Text: "····", Bold: true},
			tui.Sg(" │ allow ", tui.Theme.Dim), tui.Sg("···", tui.Theme.OK),
			tui.Sg(" │ deny ", tui.Theme.Dim), tui.Sgb("··", tui.Theme.Bad))
	}
	counters = append(counters, tui.Sg(" │ local ", tui.Theme.Dim))
	if p.localOn != nil && *p.localOn {
		counters = append(counters, tui.Sg("✓", tui.Theme.OK))
	} else {
		counters = append(counters, tui.Sg("off", tui.Theme.Dim))
	}
	counters = append(counters,
		tui.Sg(" │ rl ", tui.Theme.Dim), tui.Sg(modeOr(rl.mode()), tui.ModeColor(rl.mode())),
		tui.Sg(" │ dlp ", tui.Theme.Dim), tui.Sg(modeOr(dl.mode()), tui.ModeColor(dl.mode())),
		tui.Sg(" │ hooks ", tui.Theme.Dim))
	if p.guard != nil {
		installed := "?"
		if p.guard.Installed != nil {
			installed = strconv.Itoa(*p.guard.Installed)
		}
		text := "v" + installed
		color := lipgloss.TerminalColor(tui.Theme.OK)

		if !p.guard.UpToDate && p.guard.Latest > 0 && p.guard.Installed != nil {
			text += "→v" + strconv.Itoa(p.guard.Latest)
			color = tui.Theme.Warn
		}
		text += " " + strconv.Itoa(p.guard.DeviceCount) + "dev"
		counters = append(counters, tui.Seg{Text: text, Fg: color})
	} else {
		counters = append(counters, tui.Sg("·", tui.Theme.Warn))
	}
	counters = append(counters, tui.Sg(" │", tui.Theme.Dim))
	lines = append(lines, tui.RenderRow(width, counters...))

	if a := p.activeAlert(now); a != nil {
		label, fg, bg := "⏸ IDLE", tui.HexWarnFG, tui.HexWarnBG
		if a.level == "bad" {
			label, fg, bg = "⛔ ALERT", tui.HexBadFG, tui.HexBadBG
		}
		lines = append(lines, tui.RenderRow(width, tui.Seg{
			Text: " " + label + " · " + tui.Truncate(a.msg, width-14) + " ",
			Fg:   lipgloss.Color(fg), Bg: lipgloss.Color(bg), Bold: true}))
	}
	if act := p.activeAction(now); act != nil {
		fg, bg := tui.HexOKFG, tui.HexOKBG
		if act.level == "bad" {
			fg, bg = tui.HexBadFG, tui.HexBadBG
		}
		lines = append(lines, tui.RenderRow(width, tui.Seg{
			Text: " " + tui.Truncate(act.text, width-4) + " ",
			Fg:   lipgloss.Color(fg), Bg: lipgloss.Color(bg), Bold: true}))
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
		trace[i] = tui.MaxInt(1, v)
		evalHot[i] = float64(v) > evalHotAt
	}
	left := append([]string{tui.PaneTitle("TRAFFIC",
		"calls/10s · last 10m · live · peak "+strconv.Itoa(peak)+" · red = denials", leftW)},

		columnChart(traffic, trafficHot, chartH, leftW, 10, tui.Theme.Accent, tui.Theme.Bad)...)
	right := append([]string{tui.PaneTitle("HEARTBEAT",
		"live · ms per decision · now "+strconv.Itoa(p.evalNow())+" · med "+strconv.Itoa(p.evalMedian())+
			" · amber >"+strconv.Itoa(int(evalHotAt+0.5)), rightW)},

		columnChart(trace, evalHot, chartH, rightW, int(evalHotAt+0.5), tui.Theme.White, lipgloss.Color(tui.HexWarnFG))...)
	lines = append(lines, tui.JoinColumns([][]string{left, right}, []int{leftW, rightW}, 1+chartH)...)

	layersCol := []string{tui.PaneTitle("LAYERS", "l = inspect", colW)}
	layersCol = append(layersCol, tui.RenderRow(colW,
		tui.Sg(tui.PadEnd("RATELIMIT ", 10), tui.Theme.Dim),
		tui.Sg(tui.PadEnd(modeOr(rl.mode()), 7), tui.ModeColor(rl.mode())),
		tui.Sg(rl.summary(minuteNow), tui.Theme.Dim)))
	if rl != nil && rl.PerMinute > 0 {
		color := lipgloss.TerminalColor(tui.Theme.Accent)
		if minuteNow > rl.PerMinute {
			color = tui.Theme.Bad
		}
		layersCol = append(layersCol, hbar("load/min", minuteNow, rl.PerMinute, tui.MaxInt(6, colW-16), color, colW))
	}
	builtinN, customN := 0, 0
	if dl != nil {
		builtinN, customN = len(dl.Patterns), len(dl.Custom)
	}
	layersCol = append(layersCol, tui.RenderRow(colW,
		tui.Sg(tui.PadEnd("DLP", 10), tui.Theme.Dim),
		tui.Sg(tui.PadEnd(modeOr(dl.mode()), 7), tui.ModeColor(dl.mode())),
		tui.Sg(strconv.Itoa(builtinN)+" builtin · "+strconv.Itoa(customN)+" custom", tui.Theme.Dim)))

	dlpTotal := 0
	for _, d2 := range p.insights.DLPByPattern {
		dlpTotal += d2.Count
	}
	if dlpTotal > 0 {
		layersCol = append(layersCol, tui.RenderRow(colW,
			tui.Sg(tui.PadEnd("", 10), tui.Theme.Dim),
			tui.Sgb(strconv.Itoa(dlpTotal), tui.Theme.Bad),
			tui.Sg(" hits in last 7 days", tui.Theme.Dim)))
	} else {

		layersCol = append(layersCol, tui.RenderRow(colW, tui.Sg("          no dlp hits in last 7 days", tui.Theme.Dim)))
	}
	guardSegs := []tui.Seg{tui.Sg(tui.PadEnd("GUARD", 10), tui.Theme.Dim)}
	if p.ring != nil {
		guardSegs = append(guardSegs, tui.Sg("local ✓ ", tui.Theme.OK),
			tui.Sg("eval avg "+strconv.Itoa(p.ring.avgMs)+"ms", tui.Theme.Dim))
	} else {
		guardSegs = append(guardSegs, tui.Sg("no local ring in cwd", tui.Theme.Dim))
	}
	layersCol = append(layersCol, tui.RenderRow(colW, guardSegs...))

	eventCol := []string{tui.PaneTitle("EVENT LOG", "system heartbeat", colW)}
	tail := p.events
	if len(tail) > colH-1 {
		tail = tail[len(tail)-(colH-1):]
	}
	for _, l := range tail {
		tickColor := lipgloss.TerminalColor(lipgloss.Color(tui.HexEventTick))
		msgColor := lipgloss.TerminalColor(tui.Theme.Dim)
		mark := "▸ "
		switch l.level {
		case "bad":
			tickColor, msgColor = tui.Theme.Bad, tui.Theme.Bad
		case "warn":
			tickColor = tui.Theme.Warn
		case "beat":

			mark, tickColor = "• ", tui.Theme.OK
		}
		eventCol = append(eventCol, tui.RenderRow(colW,
			tui.Sg(tui.Hhmmss(l.ts)+" ", tui.Theme.Dim),
			tui.Seg{Text: mark, Fg: tickColor},
			tui.Seg{Text: l.msg, Fg: msgColor}))
	}
	lines = append(lines, tui.JoinColumns([][]string{layersCol, eventCol},
		[]int{colW, colW}, colH)...)

	visible := p.visibleDesc()
	sel := tui.MinInt(tui.MaxInt(0, p.sel), tui.MaxInt(0, len(visible)-1))
	streamBody := tui.MaxInt(3, streamRows-1)
	maxScroll := tui.MaxInt(0, len(visible)-streamBody)
	scroll := tui.MinInt(tui.MaxInt(0, sel-(streamBody-1)/2), maxScroll)

	extra := strconv.Itoa(sel+1) + "/" + strconv.Itoa(len(visible))
	if p.signal != "none" {
		extra += " · " + p.signal
	}
	if strings.TrimSpace(p.search) != "" {
		extra += " · search"
	}
	extra += " · enter full entry · ? all keys"
	lines = append(lines, tui.PaneTitle("TOOL STREAM", extra, width))

	body := []string{p.searchRow(width, len(visible))}
	switch {

	case p.localOn != nil && *p.localOn && !p.localSetting.UsableHere:

		body = append(body, tui.RenderRow(width,
			tui.Sg("local logs on", tui.Theme.Warn),
			tui.Sg(", "+p.localSetting.ConfiguredPath+" is not a folder on this device · writing to "+
				p.localSetting.File, tui.Theme.Dim)))
	case p.localOn != nil && *p.localOn && len(p.local) == 0:
		body = append(body, tui.RenderRow(width,
			tui.Sg("local logs on", tui.Theme.OK),
			tui.Sg(", no entries yet · hooks write "+p.localSetting.File, tui.Theme.Dim)))
	}
	if len(visible) == 0 {

		body = append(body, tui.RenderRow(width, tui.Sg(spin+" awaiting traffic…", tui.Theme.Dim)))
	}
	for i := 0; i < streamBody && scroll+i < len(visible); i++ {
		e := visible[scroll+i]
		body = append(body, tui.StreamLine(e.row(), scroll+i == sel, false, width))
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
	return append(lines, tui.RenderRow(width,
		tui.Seg{Text: " LIVE ", Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexPanelBG), Bold: true},
		tui.Seg{Text: " local-log " + localState + " · " + strconv.Itoa(len(p.local)) +
			" entries · top " + top + " ",
			Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexFooterBG)},
		tui.Seg{Text: " ↑↓ select · enter full entry · / search · space copy · ? all keys · esc menu · q quit ",
			Fg: tui.Theme.White, Bg: lipgloss.Color(tui.HexPanelBG)}))
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
		segs := make([]tui.Seg, 0, 8)
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
				c = lipgloss.Color(tui.HexDimFloor)
			} else if hotData[i] {
				c = hotColor
			}
			if n := len(segs); n > 0 && segs[n-1].Fg == c {
				segs[n-1].Text += ch
			} else {
				segs = append(segs, tui.Seg{Text: ch, Fg: c})
			}
		}
		lines = append(lines, tui.RenderRow(width, segs...))
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
	return tui.RenderRow(maxw,
		tui.Sg(tui.PadEnd(label, 10), tui.Theme.Dim),
		tui.Sg(strings.Repeat("█", filled), color),
		tui.Sg(strings.Repeat("░", width-filled), lipgloss.Color(tui.HexDimFloor)),
		tui.Sg(" "+strconv.Itoa(value), tui.Theme.Dim))
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

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}