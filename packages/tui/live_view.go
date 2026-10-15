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

// ── rendering ──────────────────────────────────────────────────────────────

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
		lines[i] = " " + lines[i] // paddingX = 1
	}
	// The console clips itself rather than trusting the shell to do it. Two
	// places genuinely round UP: the three lower columns have a 20-column floor
	// each, and the stream has a four-row floor, so on a small terminal the
	// budget cannot be met and something has to go. Losing the footer is what
	// Ink's overflow hidden did; growing the frame is what costs the render
	// path.
	return clampBlock(strings.Join(lines, "\n"), ctx.Cols, ctx.Rows)
}

func (p *Live) titleBar(ctx PanelContext, width int, now int64, spin string) string {
	segs := []seg{
		{text: " SOLONGATE LIVE ", fg: lipgloss.Color("15"), bg: lipgloss.Color(hexTitleBG), bold: true},
		// `· api <n>ms` stood here, the round trip of the audit fetch. What is worth a
		// place in the title is what ENFORCEMENT costs, which is measured per call and
		// recorded in every entry, see the GUARD COST pane.
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

// WHAT ENFORCEMENT COSTS, in milliseconds per decision.
//
// These were latNow and latMedian over p.lat, which held the round-trip time of the
// audit fetch, a read of a file on this machine, so the number was a measure of the
// local disk and was labelled "API LATENCY". It charted nothing anybody could act on.
//
// The guard measures its own decision time and writes it into every entry, which is the
// number a person tuning a policy actually wants: a rule set that costs 40ms per tool
// call is a different thing to live with than one that costs 4ms. Same charts, same
// shape, a real subject.
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

// searchRow is ALWAYS the first line under a stream or timeline title, never
// hidden, so it is obvious where to type. `/` focuses it; while focused the
// text input takes over, otherwise it shows the query or the hint.
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

// viewInspect is the FULL content of one log line.
func (p *Live) viewInspect(ctx PanelContext, width int, now int64) []string {
	e := *p.inspect
	bodyW := maxInt(20, ctx.Cols-4)
	// WHY FIRST, arguments second. On a big call the arguments are a screen of
	// JSON, and the one thing somebody opened this view to find is the sentence
	// explaining why it was refused.
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
	bodyRows := maxInt(4, ctx.Rows-6) // title + 3 header rows + pane title + footer
	maxScroll := maxInt(0, len(content)-bodyRows)
	off := minInt(p.inspectScroll, maxScroll)

	// A LOC/CLD segment sat at the end of this header. Every entry is from this
	// machine's own log, so the label distinguished nothing.
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
		// The why block is coloured; the arguments under it are not. The first of
		// its lines names the layer, so it is the one that carries the weight.
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

// viewLayers is the full security-layer configuration.
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
	// ONE LINE, AND NO BAR.
	//
	// This drew a bar per pattern, each scaled against the busiest, which makes
	// the busiest full width by construction: a single pattern became a
	// full-width red bar across the panel for seven hits. It read as an
	// emergency and measured nothing, because a bar compares and there was
	// nothing to compare against. Naming the pattern beside it did not help
	// either, with one pattern the name sat next to what was really the total,
	// so the row said "AWS access key" where it meant "all of them".
	//
	// The panel is a summary of the layers. How many hits, over what window, is
	// the summary; which pattern fired is on the entry that fired it, where it
	// belongs to one call and means something.
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

// viewDetail is one session, dashboard style: a summary and the full timeline.

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

	// counters
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
		// Only when there is a real newer version to name. Latest is 0 when this build
		// cannot find its own packaged hook to compare against, and rendering that
		// turned "I cannot tell" into "yours is out of date, upgrade to v0".
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

	// TRAFFIC is always the LIVE window: 10-second buckets over the last 10
	// minutes, anchored to wall-clock slots. Bars slide left as real time passes
	// and age out naturally, so an hours-old deny can never paint a giant red
	// column. There is no historical fallback, an idle window is an honest flat
	// floor, not a rescaled 24h chart.
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
	// Amber above 2.5x the median, with a floor so a quiet machine whose median is 2ms
	// does not paint every ordinary call hot. The floor was 2000ms for a network round
	// trip; for a local policy decision 50ms is already slow.
	evalHotAt := maxFloat(50, float64(p.evalMedian())*2.5)
	// A BASELINE UNDER THE IDLE SAMPLES. A zero column draws nothing, and a trace of
	// nothing is the frozen picture this pane was replaced for. One unit is below the
	// chart's floor of 50, so it moves the scale by nothing and reads as a flatline.
	trace := make([]int, len(p.pulse))
	evalHot := make([]bool, len(p.pulse))
	for i, v := range p.pulse {
		trace[i] = maxInt(1, v)
		evalHot[i] = float64(v) > evalHotAt
	}
	left := append([]string{paneTitle("TRAFFIC",
		"calls/10s · last 10m · live · peak "+strconv.Itoa(peak)+" · red = denials", leftW)},
		// Ten calls in ten seconds is a busy machine; below that the bars stay short.
		columnChart(traffic, trafficHot, chartH, leftW, 10, theme.Accent, theme.Bad)...)
	right := append([]string{paneTitle("HEARTBEAT",
		"live · ms per decision · now "+strconv.Itoa(p.evalNow())+" · med "+strconv.Itoa(p.evalMedian())+
			" · amber >"+strconv.Itoa(int(evalHotAt+0.5)), rightW)},
		// The amber threshold is the top of the scale: an ordinary decision sits well
		// under it, and a bar that reaches up there is one worth looking at.
		columnChart(trace, evalHot, chartH, rightW, int(evalHotAt+0.5), theme.White, lipgloss.Color(hexWarnFG))...)
	lines = append(lines, joinColumns([][]string{left, right}, []int{leftW, rightW}, 1+chartH)...)

	// LAYERS · SESSIONS · EVENT LOG
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
	// ONE LINE, AND NO BAR. Each pattern was drawn as a bar scaled against the
	// busiest, which makes the busiest full width by construction, so a single
	// pattern was a full-width red bar across the panel for seven hits, reading
	// as an emergency and measuring nothing, because a bar compares and there was
	// nothing to compare against. Ten columns of label cut "AWS access key" to
	// "AWS acces…" as well, so the name beside it named nothing, and with one
	// pattern that name sat next to what was really the total.
	//
	// This column is a summary of the layers. How many hits over what window is
	// the summary; WHICH pattern fired belongs on the entry that fired it.
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
		// 36 characters against a colW of about 31 at cols=100: without the
		// truncation this wrapped onto a second line and pushed the column past
		// its height.
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
			// A beat is a different KIND of line from an event: it says the console is
			// alive, not that something happened. Marked and dimmed so a denial still
			// stands out in a column that now has one of these every second.
			mark, tickColor = "• ", theme.OK
		}
		eventCol = append(eventCol, renderRow(colW,
			sg(hhmmss(l.ts)+" ", theme.Dim),
			seg{text: mark, fg: tickColor},
			seg{text: l.msg, fg: msgColor}))
	}
	lines = append(lines, joinColumns([][]string{layersCol, eventCol},
		[]int{colW, colW}, colH)...)

	// TOOL STREAM
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
	// A "local logs off, enable: TUI → Settings or dashboard → Settings" row stood
	// first here. Recording is unconditional: the setting chooses the folder and nothing
	// else, so `off` is a state the writers cannot be in and the row could not appear.
	case p.localOn != nil && *p.localOn && !p.localSetting.UsableHere:
		// The folder is a PROJECT setting, so it can name a path that exists on
		// another machine. Saying so beats showing a path nothing writes to.
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
		// A source filter used to make this ambiguous, "awaiting traffic" reads as
		// "nothing is happening" when the stream is merely filtered, so it said which
		// source was selected. There is one source. The signal and search filters can
		// still empty the view, and they are visible in the status bar.
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

	// A source indicator stood here, with the `f` key that cycled it, because the
	// filter was otherwise discoverable only through the ? overlay, the stream looked
	// like it merged local and cloud with no way to separate them. It merged one file
	// with itself.
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

// modeOr is the "?" a layer shows before its configuration has loaded.
func modeOr(m string) string {
	if m == "" {
		return "?"
	}
	return m
}

// ── small renderers ────────────────────────────────────────────────────────

// columnChart draws `height` rows of block columns, newest on the right.
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
	// A FLOOR UNDER THE SCALE, so a quiet machine looks quiet.
	//
	// The top of the chart was whatever the tallest sample happened to be, so on an idle
	// console ONE call drew a full-height bar. Technically a 100% increase over nothing,
	// and useless: every reading looked like a spike, and a real spike looked the same.
	//
	// The floor is what the caller considers a normal maximum, the amber threshold for
	// decision cost, a busy second's traffic for call counts, so a bar only approaches
	// the top when it is genuinely near that. Above the floor the scale still grows, so
	// nothing is ever clipped.
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

// hbar is the compact labelled bar used inside the Live columns.
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

// joinColumns lays blocks side by side with a two-column gutter, clipped to
// `height` lines.
//
// The height and the clipping have to happen HERE, on the row, not on the
// individual columns. They used to be split, a fixed height on the row and
// hidden overflow on the columns, which clips nothing: a column with no height
// of its own sizes to its content, so there was no boundary to clip against and
// a column taller than the budget simply grew the whole frame past its limit.
// That is the full repaint the budget exists to avoid, and it is why LAYERS
// made the lower half of the console flicker exactly when it had something to
// show.
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

// ── counters ───────────────────────────────────────────────────────────────

// counter counts by key and remembers the order keys were first seen.
//
// Go map iteration is random where JavaScript's Map is insertion-ordered, so
// without the order slice two tools with the same count would swap places
// between renders and the column would flicker.
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