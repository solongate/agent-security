// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/tui"
)

// Split from dlp.go: the built-in/custom pattern renderers and the panel view.

// wcParts splits a glob into its leading/trailing wildcard state and its core,
// so a row can show whether the `*` on either side is ON. It is the same
// clarity the policy editor's Match field gives.
func wcParts(pat string) (left bool, core string, right bool) {
	s := pat
	left = strings.HasPrefix(s, "*")
	right = len(s) > 1 && strings.HasSuffix(s, "*")
	core = s
	if left {
		core = strings.TrimLeft(core, "*")
	}
	if right {
		core = strings.TrimRight(core, "*")
	}
	if core == "" {
		core = s
	}
	return left, core, right
}

func starLeft(on bool) (string, lipgloss.Style) {
	if on {
		return "✱ ", stOK
	}
	return "· ", stDim
}

func starRight(on bool) (string, lipgloss.Style) {
	if on {
		return " ✱", stOK
	}
	return " ·", stDim
}

// dlpLine is one rendered row plus the entries it selects: `entry` is the first
// of them and `span` is how many it holds, one for a custom row, up to dlpCols
// for a row of the built-in grid. `entry` is -1 for headers and help notes,
// which the cursor skips.
type dlpLine struct {
	text  string
	entry int
	span  int
}

func (p *DLP) View(ctx tui.PanelContext) string {
	p.apply(ctx)
	if !p.hasDraft {
		return clip(dataView(p.loading, p.loadErr, false, "", ""), p.cols, p.rows)
	}

	enabled := map[string]bool{}
	for _, s := range p.dlp.DLP.Patterns {
		enabled[s] = true
	}
	selC := p.selClamped()

	var lines []dlpLine
	header := func(label, extra string) {
		l := newLine(false)
		l.put(label, stAccentB)
		if extra != "" {
			l.put("  "+extra, stDim)
		}
		lines = append(lines, dlpLine{l.String(), -1, 0})
	}
	note := func(text string) { lines = append(lines, dlpLine{stDim.Render(text), -1, 0}) }

	onCount := 0
	for _, name := range p.available {
		if enabled[name] {
			onCount++
		}
	}
	header("built-in secret patterns", fmt.Sprintf("%d/%d on · space toggles · A all · U none", onCount, len(p.available)))
	// The cell is sized from the panel and floored, so a narrow terminal
	// truncates names rather than wrapping a row, a wrapped row would push its
	// last cells past the clip, where they are unreachable but still selectable.
	cellW := max(12, (p.cols-1)/dlpCols)
	for r := 0; r < len(p.available); r += dlpCols {
		end := min(r+dlpCols, len(p.available))
		// newLine(false): the highlight is per CELL here, not per row, so each
		// run carries its own background instead of the builder adding one.
		l := newLine(false)
		for i := r; i < end; i++ {
			name := p.available[i]
			on := enabled[name]
			isCur := p.focused && i == selC
			cursor, cursorStyle := " ", stDim
			if isCur {
				cursor, cursorStyle = "▸", stAccent
			}
			mark, markStyle := "○", stDim
			nameStyle := stDim
			if on {
				mark, markStyle, nameStyle = "●", stOK, stPlain
			}
			if isCur {
				cursorStyle = cursorStyle.Background(selColor).Bold(true)
				markStyle = markStyle.Background(selColor).Bold(true)
				nameStyle = nameStyle.Background(selColor).Bold(true)
			}
			l.put(cursor, cursorStyle)
			l.put(mark, markStyle)
			l.put(" "+pad(truncate(name, cellW-4), cellW-3), nameStyle)
		}
		lines = append(lines, dlpLine{l.String(), r, end - r})
	}
	ei := len(p.available)

	header("custom patterns", "a add · d remove")
	note("  * = any chars · green ✱ on a side = wildcard active there · e.g.  sk-*   *PRIVATE KEY*")
	if len(p.dlp.DLP.Custom) == 0 {
		note("  (none, press a to add a name + pattern)")
	}
	for _, c := range p.dlp.DLP.Custom {
		isCur := p.focused && ei == selC
		left, core, right := wcParts(c.Re)
		l := newLine(isCur)
		cursorStyle, cursor := stDim, "  "
		if isCur {
			cursorStyle, cursor = stAccent, "▸ "
		}
		l.put(cursor, cursorStyle.Bold(isCur))
		l.put(c.Name, stAccent.Bold(isCur))
		l.put("  ", stDim)
		txt, st := starLeft(left)
		l.put(txt, st.Bold(isCur))
		l.put(truncate(core, max(6, p.cols-len([]rune(c.Name))-14)), stDim.Bold(isCur))
		txt, st = starRight(right)
		l.put(txt, st.Bold(isCur))
		lines = append(lines, dlpLine{l.String(), ei, 1})
		ei++
	}

	// ── header block (always visible) + windowed list ──────────────────────
	editRows := 0
	if p.adding != dlpAddNone {
		editRows = 1
	}
	statusRows := 0
	if p.status != "" {
		statusRows = 1
	}
	headerRows := 2 + editRows + statusRows
	budget := max(3, p.rows-headerRows-1)

	selLine := 0
	for i, l := range lines {
		if l.entry >= 0 && selC >= l.entry && selC < l.entry+l.span {
			selLine = i
			break
		}
	}
	texts := make([]string, len(lines))
	for i, l := range lines {
		texts[i] = l.text
	}
	win, above, below := window(texts, selLine, budget)

	var out []string

	modeLine := newLine(false)
	modeLine.put("mode: ", stPlain)
	modeLine.put(string(p.dlp.DLP.Mode), modeStyle(string(p.dlp.DLP.Mode)).Bold(true))
	switch p.dlp.DLP.Mode {
	case client.LayerOff:
		modeLine.put("  (nothing is scanned)", stDim)
	case client.LayerDetect:
		modeLine.put("  (record the hit, change nothing)", stDim)
	case client.LayerRedact:
		modeLine.put("  (mask the secret, let the call through)", stDim)
	default:
		modeLine.put("  (refuse the call)", stDim)
	}
	if p.dirty {
		modeLine.put("   ● unsaved (s save · x discard)", stWarn)
	}
	out = append(out, modeLine.String())

	hint := "press → to edit"
	if p.focused {
		tail := " · s save · x discard · ^R refresh"
		if p.bound {
			tail = " · s save · x discard · esc back"
		}
		hint = "↑↓←→ move · space on/off · A all · U none · m mode · a add · e edit · d remove" +
			tail + scrollTag(above, below)
	}
	out = append(out, stDim.Render(hint))

	if p.adding != dlpAddNone {
		l := newLine(false)
		switch p.adding {
		case dlpAddName:
			l.put("new pattern name: ", stWarn)
		default:
			verb := "new"
			if p.editIdx >= 0 {
				verb = "edit"
			}
			l.put(verb+` pattern for "`+p.newName+`" (glob, * = any chars): `, stWarn)
		}
		v := p.input.Value()
		if p.adding != dlpAddName {
			txt, st := starLeft(strings.HasPrefix(v, "*"))
			l.put(txt, st)
		}
		l.put(p.input.View(), stPlain)
		if p.adding != dlpAddName {
			txt, st := starRight(len(v) > 1 && strings.HasSuffix(v, "*"))
			l.put(txt, st)
		}
		out = append(out, l.String())
	}

	out = append(out, "")
	out = append(out, win...)
	if p.status != "" {
		out = append(out, statusLine(p.status))
	}

	return clip(joinLines(out), p.cols, p.rows)
}