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

func (m *setupModel) View() string {
	w := m.cols - 8
	if w < 44 {
		w = 44
	}
	if w > 74 {
		w = 74
	}

	var body []string
	push := func(s string) { body = append(body, s) }

	push(sgb("Welcome to SolonGate.", theme.AccentBright).render())
	push(sg("Your agent asks this machine before it acts. Three things to set", theme.Dim).render())
	push(sg("up, and the last one needs the agent itself.", theme.Dim).render())
	push("")
	body = append(body, m.rail(w)...)
	push("")

	switch m.step {
	case stepGuard:
		body = append(body, m.viewGuard(w)...)
	case stepPolicy:
		body = append(body, m.viewPolicy(w)...)
	case stepFirstCall:
		body = append(body, m.viewWaiting(w)...)
	case stepFinished:
		body = append(body, m.viewDone(w)...)
	}

	push("")
	push(m.footer())
	return centreBlock(body, m.cols, m.rows)
}

func centreBlock(lines []string, cols, rows int) string {
	width := 0
	for _, l := range lines {
		if n := lipgloss.Width(l); n > width {
			width = n
		}
	}
	left := (cols - width) / 2
	if left < 2 {
		left = 2
	}
	pad := strings.Repeat(" ", left)

	out := make([]string, 0, rows)
	top := (rows - len(lines)) / 3
	for i := 0; i < top; i++ {
		out = append(out, "")
	}
	for _, l := range lines {
		if l == "" {
			out = append(out, "")
			continue
		}
		out = append(out, pad+l)
	}
	return clampBlock(strings.Join(out, "\n"), cols, rows)
}

func (m *setupModel) rail(w int) []string {
	names := []string{
		"the guard is registered and firing",
		"this machine has a policy",
		"the guard has judged a real tool call",
	}
	out := make([]string, 0, len(names))
	for i, name := range names {
		var mark seg
		switch {
		case setupStep(i) < m.step:
			mark = sg("✓", theme.OK)
		case setupStep(i) == m.step:
			mark = sg(spinFrames[m.frame%len(spinFrames)], theme.Warn)
		default:
			mark = sg("·", theme.Dim)
		}
		fg := theme.Dim
		if setupStep(i) <= m.step {
			fg = theme.White
		}
		out = append(out, renderRow(w, mark, plain("  "), sg(name, fg)))
	}
	return out
}

func (m *setupModel) viewGuard(w int) []string {
	var out []string
	push := func(segs ...seg) { out = append(out, renderRow(w, segs...)) }

	if m.guardReady {
		push(sgb("Step 1 of 3 · the guard is in place", theme.AccentBright))
		push(plain(""))
		push(sg("Registered with your agent. "+m.guardDetail, theme.OK))
		return out
	}
	push(sgb("Step 1 of 3 · nothing is guarding this machine yet", theme.Bad))
	push(plain(""))
	push(sg("No client has the guard registered, so no tool call is being", theme.Dim))
	push(sg("checked by anything.", theme.Dim))
	push(plain(""))
	push(sg("Run the installer from the checkout, in your own terminal. This", theme.Dim))
	push(sg("screen notices on its own when it is done:", theme.Dim))
	push(plain(""))
	push(sg("    ./scripts/install.sh", theme.AccentBright))
	if m.guardDetail != "" {
		push(plain(""))
		push(sg("what this screen can see: "+m.guardDetail, theme.Dim))
	}
	return out
}

func (m *setupModel) viewPolicy(w int) []string {
	var out []string
	push := func(segs ...seg) { out = append(out, renderRow(w, segs...)) }

	push(sgb("Step 2 of 3 · choose what this machine refuses", theme.AccentBright))
	push(plain(""))
	push(sg("There is no policy yet, so every tool call your agent makes is", theme.Dim))
	push(sg("allowed. It is recorded, and it is not refused. Pick a starting", theme.Dim))
	push(sg("point below with ↑↓ and press enter. You can change it later.", theme.Dim))
	push(plain(""))

	postures := setupPostures()
	for i, p := range postures {
		marker, fg := "  ", theme.White
		if i == m.choice {
			marker, fg = "▸ ", theme.AccentBright
		}
		push(sg(marker, theme.AccentBright), sgb(p.title, fg))
		if i == m.choice {
			for _, line := range p.blurb {
				push(sg("    "+line, theme.Dim))
			}
		}
	}

	if m.askingPath {
		push(plain(""))
		out = append(out, sgb("the path: ", theme.Warn).render()+m.input.View())
		push(sg("enter writes it · esc goes back", theme.Dim))
	}
	if m.writing {
		push(plain(""))
		push(sg(spinFrames[m.frame%len(spinFrames)]+" writing "+config.PolicyFilePath(), theme.Warn))
	}
	if m.writeErr != "" {
		push(plain(""))
		push(sg("✗ "+m.writeErr, theme.Bad))
	}
	return out
}

func listenBar(width, frame int) seg {
	if width < 8 {
		width = 8
	}
	span := width - 1
	pos := frame % (2 * span)
	if pos > span {
		pos = 2*span - pos
	}
	runes := make([]rune, width)
	for i := range runes {
		switch {
		case i == pos:
			runes[i] = '●'
		case i == pos-1 || i == pos+1:
			runes[i] = '·'
		default:
			runes[i] = ' '
		}
	}
	return sg(string(runes), theme.AccentBright)
}

func (m *setupModel) viewWaiting(w int) []string {
	var out []string
	push := func(segs ...seg) { out = append(out, renderRow(w, segs...)) }

	if m.wrote != "" {
		push(sg("✓ wrote "+m.wrote+" to "+config.PolicyFilePath(), theme.OK))
		push(plain(""))
	}
	push(sgb("Step 3 of 3 · make your agent do something", theme.AccentBright))
	push(plain(""))
	push(sg("Everything above is a claim about what happens when your agent", theme.Dim))
	push(sg("acts, and none of it is proven on this machine until one has.", theme.Dim))
	push(sg("So this screen waits. Leave it open.", theme.Dim))
	push(plain(""))
	push(sg("  1. ", theme.Dim), sg("open a second terminal and start your agent", theme.White))
	push(sg("       claude", theme.AccentBright),
		sg("    or codex, opencode, antigravity", theme.Dim))
	push(plain(""))
	push(sg("  2. ", theme.Dim), sg("type this to it, word for word:", theme.White))
	push(plain(""))
	push(sg("       "+setupPrompt, theme.AccentBright))
	push(plain(""))
	push(sg("The agent will run it as a tool call, SolonGate will judge that", theme.Dim))
	push(sg("call, and this screen will say so within a second.", theme.Dim))
	push(plain(""))
	push(listenBar(min(w, 34), m.frame))
	push(sg("waiting · "+elapsed(m.started), theme.Dim))
	return out
}

func elapsed(since time.Time) string {
	if since.IsZero() {
		return "0:00"
	}
	d := int(time.Since(since).Seconds())
	return strconv.Itoa(d/60) + ":" + pad2(d%60)
}

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func (m *setupModel) viewDone(w int) []string {
	var out []string
	push := func(segs ...seg) { out = append(out, renderRow(w, segs...)) }
	c := m.call
	if c == nil {
		push(sg("done", theme.OK))
		return out
	}

	shown := 99
	if !m.arrived.IsZero() {
		shown = int(time.Since(m.arrived)/(110*time.Millisecond)) + 1
	}
	line := 0
	step := func(fn func()) {
		line++
		if line <= shown {
			fn()
		}
	}

	push(sgb("✓ The guard judged a real tool call.", theme.OK))
	push(plain(""))

	kv := func(k, v string) {
		step(func() { push(sg("  "+padEnd(k, 10), theme.Dim), sg(v, theme.White)) })
	}
	kv("tool", orSetupDash(c.Tool))
	kv("client", orSetupDash(c.Client))
	kv("where", orSetupDash(c.Cwd))
	kv("asked for", setupSaw(c))
	kv("took", strconv.FormatFloat(c.Ms, 'f', 1, 64)+" ms")

	if shown > 5 {
		push(plain(""))
		push(sg("That is the whole product: a decision, on this machine, before", theme.Dim))
		push(sg("the call ran. Nothing left it.", theme.Dim))
	}
	if shown > 6 {
		push(plain(""))
		push(sg("A policy rule matches STRINGS, which is worth knowing before", theme.Dim))
		push(sg("you rely on one. `solongate doctor` says what is in force.", theme.Dim))
	}
	return out
}

func setupSaw(c *setupCall) string {
	var parts []string
	add := func(n int, one, many string) {
		switch {
		case n == 1:
			parts = append(parts, "1 "+one)
		case n > 1:
			parts = append(parts, strconv.Itoa(n)+" "+many)
		}
	}
	add(c.Paths, "path", "paths")
	add(c.Cmds, "command", "commands")
	add(c.URLs, "url", "urls")
	if len(parts) == 0 {
		return "no paths, commands or urls"
	}
	if c.Perm != "" {
		return strings.Join(parts, ", ") + "  (" + strings.ToLower(c.Perm) + ")"
	}
	return strings.Join(parts, ", ")
}

func orSetupDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func (m *setupModel) footer() string {
	seg2 := func(k, meaning string) string {
		return sg(k, theme.AccentBright).render() + sg(" "+meaning, theme.Dim).render()
	}
	switch m.step {
	case stepPolicy:
		if m.askingPath {
			return seg2("enter", "write  ") + seg2("esc", "back")
		}
		return seg2("↑↓", "choose  ") + seg2("enter", "write it  ") + seg2("q", "leave")
	case stepFinished:
		return seg2("enter", "open the TUI")
	default:
		return seg2("q", "leave  (the first run starts here again next time)")
	}
}

func (s seg) render() string {
	st := lipgloss.NewStyle()
	if s.fg != nil {
		st = st.Foreground(s.fg)
	}
	if s.bg != nil {
		st = st.Background(s.bg)
	}
	if s.bold {
		st = st.Bold(true)
	}
	return st.Render(s.text)
}