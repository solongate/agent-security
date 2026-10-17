// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"context"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/solongate/agent-security/packages/core/config"
)

var Version = "dev"

func bg() context.Context { return context.Background() }

type genTag struct {
	gen int
	tok int
}

func (g genTag) Generation() int { return g.gen }

var tokens int

func nextToken() int { tokens++; return tokens }

var (
	accentColor = lipgloss.Color(accentFromConfig())
	okColor     = lipgloss.Color("2")
	warnColor   = lipgloss.Color("3")
	badColor    = lipgloss.Color("1")
	dimColor    = lipgloss.Color("8")

	selColor = lipgloss.Color("#1c2f63")
)

var (
	stPlain   = lipgloss.NewStyle()
	stAccent  = lipgloss.NewStyle().Foreground(accentColor)
	stAccentB = lipgloss.NewStyle().Foreground(accentColor).Bold(true)
	stOK      = lipgloss.NewStyle().Foreground(okColor)
	stOKB     = lipgloss.NewStyle().Foreground(okColor).Bold(true)
	stWarn    = lipgloss.NewStyle().Foreground(warnColor)
	stBad     = lipgloss.NewStyle().Foreground(badColor)
	stBadB    = lipgloss.NewStyle().Foreground(badColor).Bold(true)
	stDim     = lipgloss.NewStyle().Foreground(dimColor)
	stBold    = lipgloss.NewStyle().Bold(true)
)

func accentFromConfig() string {
	named := map[string]string{
		"black": "0", "red": "1", "green": "2", "yellow": "3",
		"blue": "4", "magenta": "5", "cyan": "6", "white": "7",
		"gray": "8", "grey": "8", "blackBright": "8",
		"redBright": "9", "greenBright": "10", "yellowBright": "11",
		"blueBright": "12", "magentaBright": "13", "cyanBright": "14", "whiteBright": "15",
	}
	a := strings.TrimSpace(config.LoadTUIConfig().Accent)
	if a == "" {
		return "7"
	}
	if v, ok := named[a]; ok {
		return v
	}
	if strings.HasPrefix(a, "#") {
		return a
	}
	return "7"
}

func modeStyle(m string) lipgloss.Style {
	switch m {
	case "block", "active", "on":
		return stOK
	case "detect", "idle":
		return stWarn
	}
	return stDim
}

type lineBuf struct {
	sb  strings.Builder
	sel bool
	w   int
}

func newLine(selected bool) *lineBuf { return &lineBuf{sel: selected} }

func (l *lineBuf) put(text string, st lipgloss.Style) *lineBuf {
	if l.sel {
		st = st.Background(selColor)
	}
	l.sb.WriteString(st.Render(text))
	l.w += lipgloss.Width(text)
	return l
}

func (l *lineBuf) String() string { return l.sb.String() }

func truncate(s string, n int) string {
	if s == "" {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

func pad(s string, w int) string {
	if d := w - lipgloss.Width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

func padLeft(s string, w int) string {
	if d := w - lipgloss.Width(s); d > 0 {
		return strings.Repeat(" ", d) + s
	}
	return s
}

func fit(s string, w int) string { return pad(truncate(s, w), w) }

func window(lines []string, cursorLine, budget int) (win []string, above, below int) {
	if budget < 1 {
		budget = 1
	}
	if len(lines) <= budget {
		return lines, 0, 0
	}
	maxStart := len(lines) - budget
	start := min(max(0, cursorLine-budget/2), maxStart)
	end := min(len(lines), start+budget)
	return lines[start:end], start, len(lines) - end
}

func scrollTag(above, below int) string {
	out := ""
	if above > 0 {
		out += " · ▲" + itoa(above)
	}
	if below > 0 {
		out += " · ▼" + itoa(below)
	}
	return out
}

func clip(body string, cols, rows int) string {
	if cols < 1 {
		cols = 1
	}
	if rows < 1 {
		rows = 1
	}
	return lipgloss.NewStyle().MaxWidth(cols).MaxHeight(rows).Render(body)
}

func joinLines(lines []string) string { return strings.Join(lines, "\n") }

func dataView(loading bool, err error, empty bool, emptyText string, body string) string {
	if err != nil {
		return stBad.Render("✗ " + err.Error())
	}
	if loading {
		return stWarn.Render("⟳ loading…")
	}
	if empty {
		if emptyText == "" {
			emptyText = "No data."
		}
		return stDim.Render(emptyText)
	}
	return body
}

func statusLine(s string) string {
	if strings.HasPrefix(s, "✗") {
		return stBad.Render(s)
	}
	return stOK.Render(s)
}

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}