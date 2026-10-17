// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

var ansiNames = map[string]string{
	"black": "0", "red": "1", "green": "2", "yellow": "3",
	"blue": "4", "magenta": "5", "cyan": "6", "white": "7",
	"gray": "8", "grey": "8", "blackBright": "8",
	"redBright": "9", "greenBright": "10", "yellowBright": "11",
	"blueBright": "12", "magentaBright": "13", "cyanBright": "14", "whiteBright": "15",
}

func colorOf(name, fallback string) lipgloss.Color {
	n := strings.TrimSpace(name)
	if strings.HasPrefix(n, "#") {
		return lipgloss.Color(n)
	}
	if v, ok := ansiNames[n]; ok {
		return lipgloss.Color(v)
	}
	return lipgloss.Color(fallback)
}

type palette struct {
	Accent       lipgloss.Color
	AccentBright lipgloss.Color
	OK           lipgloss.Color
	Warn         lipgloss.Color
	Bad          lipgloss.Color
	Dim          lipgloss.Color
	White        lipgloss.Color
}

var theme = palette{
	Accent:       lipgloss.Color("7"),
	AccentBright: lipgloss.Color("7"),
	OK:           lipgloss.Color("2"),
	Warn:         lipgloss.Color("3"),
	Bad:          lipgloss.Color("1"),
	Dim:          lipgloss.Color("8"),
	White:        lipgloss.Color("7"),
}

func setAccent(accent string) {
	if noColor() {
		return
	}
	c := colorOf(accent, "7")
	theme.Accent = c
	theme.AccentBright = c
}

func noColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return true
	}
	return os.Getenv("CLICOLOR") == "0"
}

func flatten() {
	if !noColor() {
		return
	}

	var none lipgloss.Color
	theme.Accent, theme.AccentBright = none, none
	theme.OK, theme.Warn, theme.Bad = none, none, none
	theme.Dim, theme.White = none, none
}

const (
	hexPanelBG   = "#12234f"
	hexTitleBG   = "#1432A0"
	hexFooterBG  = "#0b1530"
	hexSelectBG  = "#1c2f63"
	hexDimFloor  = "#233457"
	hexOKBG      = "#123d1f"
	hexOKFG      = "#7bd88f"
	hexWarnBG    = "#3d2a12"
	hexWarnFG    = "#ffb454"
	hexBadBG     = "#3d1220"
	hexBadFG     = "#ff6b6b"
	hexEventTick = "#4f8f6b"
)

func decisionColor(decision string) lipgloss.Color {
	switch strings.ToUpper(strings.TrimSpace(decision)) {
	case "ALLOW":
		return theme.OK
	case "DENY", "DENIED":
		return theme.Bad
	}
	return theme.Dim
}

func modeColor(m string) lipgloss.Color {
	switch m {
	case "block", "active", "on":
		return theme.OK

	case "redact":
		return theme.Accent
	case "detect", "idle":
		return theme.Warn
	}
	return theme.Dim
}

type seg struct {
	text string
	fg   lipgloss.TerminalColor
	bg   lipgloss.TerminalColor
	bold bool
}

func sg(text string, fg lipgloss.TerminalColor) seg { return seg{text: text, fg: fg} }

func sgb(text string, fg lipgloss.TerminalColor) seg {
	return seg{text: text, fg: fg, bold: true}
}

func plain(text string) seg { return seg{text: text} }

func onBG(bg lipgloss.TerminalColor, segs []seg) []seg {
	out := make([]seg, len(segs))
	for i, s := range segs {
		s.bg = bg
		out[i] = s
	}
	return out
}

func renderRow(width int, segs ...seg) string {
	var b strings.Builder
	used := 0
	for _, s := range segs {
		if s.text == "" {
			continue
		}
		text := s.text
		if width > 0 {
			room := width - used
			if room <= 0 {
				break
			}
			if lipgloss.Width(text) > room {
				text = cutWidth(text, room)
			}
		}
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
		b.WriteString(st.Render(text))
		used += lipgloss.Width(text)
	}
	return b.String()
}

func cutWidth(s string, n int) string {
	if n <= 0 {
		return ""
	}
	w := 0
	for i, r := range s {
		rw := lipgloss.Width(string(r))
		if w+rw > n {
			return s[:i]
		}
		w += rw
	}
	return s
}

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

func padEnd(s string, n int) string {
	w := lipgloss.Width(s)
	if w >= n {
		return s
	}
	return s + strings.Repeat(" ", n-w)
}

func padStart(s string, n int) string {
	w := lipgloss.Width(s)
	if w >= n {
		return s
	}
	return strings.Repeat(" ", n-w) + s
}

func fit(s string, n int) string {
	if lipgloss.Width(s) > n {
		return truncate(s, n)
	}
	return padEnd(s, n)
}

func wrapLines(s string, width int) []string {
	w := width
	if w < 8 {
		w = 8
	}
	var out []string
	for _, raw := range strings.Split(s, "\n") {
		r := []rune(raw)
		if len(r) <= w {
			out = append(out, raw)
			continue
		}
		for i := 0; i < len(r); i += w {
			end := i + w
			if end > len(r) {
				end = len(r)
			}
			out = append(out, string(r[i:end]))
		}
	}
	return out
}

func prettyJson(s string) string {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || !json.Valid([]byte(trimmed)) {
		return s
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(trimmed), "", "  "); err != nil {
		return s
	}
	return buf.String()
}

func ago(atMs int64) string {
	return agoAt(atMs, time.Now())
}

func agoAt(atMs int64, now time.Time) string {
	if atMs <= 0 {
		return ""
	}
	s := float64(now.UnixMilli()-atMs) / 1000
	if s < 0 {
		s = 0
	}
	switch {
	case s < 60:
		return strconv.Itoa(int(s)) + "s"
	case s < 3600:
		return strconv.Itoa(int(s/60)) + "m"
	case s < 86400:
		return strconv.Itoa(int(s/3600)) + "h"
	default:
		return strconv.Itoa(int(s/86400)) + "d"
	}
}

func parseMillis(s string) (int64, bool) {
	v := strings.TrimSpace(s)
	if v == "" {
		return 0, false
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UnixMilli(), true
		}
	}
	for _, layout := range []string{"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, v, time.Local); err == nil {
			return t.UnixMilli(), true
		}
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n, true
	}
	return 0, false
}

func fmtUp(ms int64) string {
	if ms < 0 {
		ms = 0
	}
	s := ms / 1000
	p := func(n int64) string {
		if n < 10 {
			return "0" + strconv.FormatInt(n, 10)
		}
		return strconv.FormatInt(n, 10)
	}
	return p(s/3600) + ":" + p((s%3600)/60) + ":" + p(s%60)
}

func num(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }