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

	push(Sgb("Welcome to SolonGate.", Theme.AccentBright).Render())
	push(Sg("Your agent asks this machine before it acts. Three things to set", Theme.Dim).Render())
	push(Sg("up, and the last one needs the agent itself.", Theme.Dim).Render())
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
	return ClampBlock(strings.Join(out, "\n"), cols, rows)
}

func (m *setupModel) rail(w int) []string {
	names := []string{
		"the guard is registered and firing",
		"this machine has a policy",
		"the guard has judged a real tool call",
	}
	out := make([]string, 0, len(names))
	for i, name := range names {
		var mark Seg
		switch {
		case setupStep(i) < m.step:
			mark = Sg("✓", Theme.OK)
		case setupStep(i) == m.step:
			mark = Sg(SpinFrames[m.frame%len(SpinFrames)], Theme.Warn)
		default:
			mark = Sg("·", Theme.Dim)
		}
		fg := Theme.Dim
		if setupStep(i) <= m.step {
			fg = Theme.White
		}
		out = append(out, RenderRow(w, mark, Plain("  "), Sg(name, fg)))
	}
	return out
}

func (m *setupModel) viewGuard(w int) []string {
	var out []string
	push := func(segs ...Seg) { out = append(out, RenderRow(w, segs...)) }

	if m.guardReady {
		push(Sgb("Step 1 of 3 · the guard is in place", Theme.AccentBright))
		push(Plain(""))
		push(Sg("Registered with your agent. "+m.guardDetail, Theme.OK))
		return out
	}
	push(Sgb("Step 1 of 3 · nothing is guarding this machine yet", Theme.Bad))
	push(Plain(""))
	push(Sg("No client has the guard registered, so no tool call is being", Theme.Dim))
	push(Sg("checked by anything.", Theme.Dim))
	push(Plain(""))
	push(Sg("Run the installer from the checkout, in your own terminal. This", Theme.Dim))
	push(Sg("screen notices on its own when it is done:", Theme.Dim))
	push(Plain(""))
	push(Sg("    ./scripts/install.sh", Theme.AccentBright))
	if m.guardDetail != "" {
		push(Plain(""))
		push(Sg("what this screen can see: "+m.guardDetail, Theme.Dim))
	}
	return out
}

func (m *setupModel) viewPolicy(w int) []string {
	var out []string
	push := func(segs ...Seg) { out = append(out, RenderRow(w, segs...)) }

	push(Sgb("Step 2 of 3 · choose what this machine refuses", Theme.AccentBright))
	push(Plain(""))
	push(Sg("There is no policy yet, so every tool call your agent makes is", Theme.Dim))
	push(Sg("allowed. It is recorded, and it is not refused. Pick a starting", Theme.Dim))
	push(Sg("point below with ↑↓ and press enter. You can change it later.", Theme.Dim))
	push(Plain(""))

	postures := setupPostures()
	for i, p := range postures {
		marker, fg := "  ", Theme.White
		if i == m.choice {
			marker, fg = "▸ ", Theme.AccentBright
		}
		push(Sg(marker, Theme.AccentBright), Sgb(p.title, fg))
		if i == m.choice {
			for _, line := range p.blurb {
				push(Sg("    "+line, Theme.Dim))
			}
		}
	}

	if m.askingPath {
		push(Plain(""))
		out = append(out, Sgb("the path: ", Theme.Warn).Render()+m.input.View())
		push(Sg("enter writes it · esc goes back", Theme.Dim))
	}
	if m.writing {
		push(Plain(""))
		push(Sg(SpinFrames[m.frame%len(SpinFrames)]+" writing "+config.PolicyFilePath(), Theme.Warn))
	}
	if m.writeErr != "" {
		push(Plain(""))
		push(Sg("✗ "+m.writeErr, Theme.Bad))
	}
	return out
}

func listenBar(width, frame int) Seg {
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
	return Sg(string(runes), Theme.AccentBright)
}

func (m *setupModel) viewWaiting(w int) []string {
	var out []string
	push := func(segs ...Seg) { out = append(out, RenderRow(w, segs...)) }

	if m.wrote != "" {
		push(Sg("✓ wrote "+m.wrote+" to "+config.PolicyFilePath(), Theme.OK))
		push(Plain(""))
	}
	push(Sgb("Step 3 of 3 · make your agent do something", Theme.AccentBright))
	push(Plain(""))
	push(Sg("Everything above is a claim about what happens when your agent", Theme.Dim))
	push(Sg("acts, and none of it is proven on this machine until one has.", Theme.Dim))
	push(Sg("So this screen waits. Leave it open.", Theme.Dim))
	push(Plain(""))
	push(Sg("  1. ", Theme.Dim), Sg("open a second terminal and start your agent", Theme.White))
	push(Sg("       claude", Theme.AccentBright),
		Sg("    or codex, opencode, antigravity", Theme.Dim))
	push(Plain(""))
	push(Sg("  2. ", Theme.Dim), Sg("type this to it, word for word:", Theme.White))
	push(Plain(""))
	push(Sg("       "+setupPrompt, Theme.AccentBright))
	push(Plain(""))
	push(Sg("The agent will run it as a tool call, SolonGate will judge that", Theme.Dim))
	push(Sg("call, and this screen will say so within a second.", Theme.Dim))
	push(Plain(""))
	push(listenBar(min(w, 34), m.frame))
	push(Sg("waiting · "+elapsed(m.started), Theme.Dim))
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
	push := func(segs ...Seg) { out = append(out, RenderRow(w, segs...)) }
	c := m.call
	if c == nil {
		push(Sg("done", Theme.OK))
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

	push(Sgb("✓ The guard judged a real tool call.", Theme.OK))
	push(Plain(""))

	kv := func(k, v string) {
		step(func() { push(Sg("  "+PadEnd(k, 10), Theme.Dim), Sg(v, Theme.White)) })
	}
	kv("tool", orSetupDash(c.Tool))
	kv("client", orSetupDash(c.Client))
	kv("where", orSetupDash(c.Cwd))
	kv("asked for", setupSaw(c))
	kv("took", strconv.FormatFloat(c.Ms, 'f', 1, 64)+" ms")

	if shown > 5 {
		push(Plain(""))
		push(Sg("That is the whole product: a decision, on this machine, before", Theme.Dim))
		push(Sg("the call ran. Nothing left it.", Theme.Dim))
	}
	if shown > 6 {
		push(Plain(""))
		push(Sg("A policy rule matches STRINGS, which is worth knowing before", Theme.Dim))
		push(Sg("you rely on one. `solongate doctor` says what is in force.", Theme.Dim))
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
		return Sg(k, Theme.AccentBright).Render() + Sg(" "+meaning, Theme.Dim).Render()
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