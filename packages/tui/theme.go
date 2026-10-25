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

type Palette struct {
	Accent       lipgloss.Color
	AccentBright lipgloss.Color
	OK           lipgloss.Color
	Warn         lipgloss.Color
	Bad          lipgloss.Color
	Dim          lipgloss.Color
	White        lipgloss.Color
}

var Theme = Palette{
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
	Theme.Accent = c
	Theme.AccentBright = c
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
	Theme.Accent, Theme.AccentBright = none, none
	Theme.OK, Theme.Warn, Theme.Bad = none, none, none
	Theme.Dim, Theme.White = none, none
}

const (
	HexPanelBG   = "#12234f"
	HexTitleBG   = "#1432A0"
	HexFooterBG  = "#0b1530"
	HexSelectBG  = "#1c2f63"
	HexDimFloor  = "#233457"
	HexOKBG      = "#123d1f"
	HexOKFG      = "#7bd88f"
	HexWarnBG    = "#3d2a12"
	HexWarnFG    = "#ffb454"
	HexBadBG     = "#3d1220"
	HexBadFG     = "#ff6b6b"
	HexEventTick = "#4f8f6b"
)

func DecisionColor(decision string) lipgloss.Color {
	switch strings.ToUpper(strings.TrimSpace(decision)) {
	case "ALLOW":
		return Theme.OK
	case "DENY", "DENIED":
		return Theme.Bad
	}
	return Theme.Dim
}

func ModeColor(m string) lipgloss.Color {
	switch m {
	case "block", "active", "on":
		return Theme.OK

	case "redact":
		return Theme.Accent
	case "detect", "idle":
		return Theme.Warn
	}
	return Theme.Dim
}

type Seg struct {
	Text string
	Fg   lipgloss.TerminalColor
	Bg   lipgloss.TerminalColor
	Bold bool
}

func Sg(text string, fg lipgloss.TerminalColor) Seg { return Seg{Text: text, Fg: fg} }

func Sgb(text string, fg lipgloss.TerminalColor) Seg {
	return Seg{Text: text, Fg: fg, Bold: true}
}

func Plain(text string) Seg { return Seg{Text: text} }

func onBG(bg lipgloss.TerminalColor, segs []Seg) []Seg {
	out := make([]Seg, len(segs))
	for i, s := range segs {
		s.Bg = bg
		out[i] = s
	}
	return out
}

func RenderRow(width int, segs ...Seg) string {
	var b strings.Builder
	used := 0
	for _, s := range segs {
		if s.Text == "" {
			continue
		}
		text := s.Text
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
		if s.Fg != nil {
			st = st.Foreground(s.Fg)
		}
		if s.Bg != nil {
			st = st.Background(s.Bg)
		}
		if s.Bold {
			st = st.Bold(true)
		}
		b.WriteString(st.Render(text))
		used += lipgloss.Width(text)
	}
	return b.String()
}

func (s Seg) Render() string {
	st := lipgloss.NewStyle()
	if s.Fg != nil {
		st = st.Foreground(s.Fg)
	}
	if s.Bg != nil {
		st = st.Background(s.Bg)
	}
	if s.Bold {
		st = st.Bold(true)
	}
	return st.Render(s.Text)
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

func Truncate(s string, n int) string {
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

func PadEnd(s string, n int) string {
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
		return Truncate(s, n)
	}
	return PadEnd(s, n)
}

func WrapLines(s string, width int) []string {
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

func PrettyJson(s string) string {
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
	return AgoAt(atMs, time.Now())
}

func AgoAt(atMs int64, now time.Time) string {
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

func ParseMillis(s string) (int64, bool) {
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

func FmtUp(ms int64) string {
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

func Num(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }