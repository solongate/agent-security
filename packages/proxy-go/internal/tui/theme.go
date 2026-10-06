package tui

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// The palette and the text helpers from packages/proxy/src/tui/theme.ts.
//
// Ink took colour NAMES and resolved them itself; lipgloss takes a colour. The
// mapping below is the one chalk uses, because the two implementations render
// the same screens on the same terminals and a dataroom that is grey in one and
// bright white in the other reads as a rendering bug rather than a port.

// Named ANSI colours, in chalk's numbering: `gray` is bright black (90), and
// `white` is the NORMAL white (37) rather than the bright one, which is what
// makes the CLD label sit a shade under the LOC label beside it.
var ansiNames = map[string]string{
	"black": "0", "red": "1", "green": "2", "yellow": "3",
	"blue": "4", "magenta": "5", "cyan": "6", "white": "7",
	"gray": "8", "grey": "8", "blackBright": "8",
	"redBright": "9", "greenBright": "10", "yellowBright": "11",
	"blueBright": "12", "magentaBright": "13", "cyanBright": "14", "whiteBright": "15",
}

// colorOf accepts what tui-config.json's `accent` may hold: a chalk colour name
// or a hex string. Anything else falls back rather than erroring — an accent is
// decoration, and a typo in it must not stop the dataroom from opening.
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

// palette is the theme object, field for field.
//
// Accent and AccentBright are the same colour and both are kept: the TypeScript
// draws a distinction it does not currently implement, and collapsing them here
// would silently decide that question for whoever revisits it.
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

// setAccent applies the user's accent once, at start-up. Package-level state
// because there is exactly one dataroom per process and every renderer below
// would otherwise have to thread a palette it never varies.
func setAccent(accent string) {
	c := colorOf(accent, "7")
	theme.Accent = c
	theme.AccentBright = c
}

// The fixed hexes the Live and Audit consoles paint their chrome with. Named
// rather than inlined so the two panels cannot drift apart.
const (
	hexPanelBG   = "#12234f" // ENTRY / LAYERS / SESSION chrome
	hexTitleBG   = "#1432A0" // the SOLONGATE LIVE badge
	hexFooterBG  = "#0b1530" // the middle segment of a footer bar
	hexSelectBG  = "#1c2f63" // selected stream row
	hexDimFloor  = "#233457" // the zero line of a column chart
	hexOKBG      = "#123d1f"
	hexOKFG      = "#7bd88f"
	hexWarnBG    = "#3d2a12"
	hexWarnFG    = "#ffb454"
	hexBadBG     = "#3d1220"
	hexBadFG     = "#ff6b6b"
	hexEventTick = "#4f8f6b"
)

// decisionColor is the colour of a decision string.
func decisionColor(decision string) lipgloss.Color {
	switch strings.ToUpper(strings.TrimSpace(decision)) {
	case "ALLOW":
		return theme.OK
	case "DENY", "DENIED":
		return theme.Bad
	}
	return theme.Dim
}

// modeColor is the colour of a layer mode or an agent status.
func modeColor(m string) lipgloss.Color {
	switch m {
	case "block", "active", "on":
		return theme.OK
	// redact acts, detect only watches, so they are not the same amber.
	case "redact":
		return theme.Accent
	case "detect", "idle":
		return theme.Warn
	}
	return theme.Dim
}

// ── segment rendering ──────────────────────────────────────────────────────

// seg is one styled run inside a single-line row.
//
// Rows are composed from segments rather than from nested styles because a
// lipgloss style emits a reset at the end of what it renders, and a reset
// inside a background-coloured row ends the background half way along the
// line. Every segment therefore carries its own background, which is how Ink's
// inherited backgroundColor looked on screen.
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

// plain is a segment in the terminal's own foreground colour.
func plain(text string) seg { return seg{text: text} }

// onBG stamps a background onto every segment of a row, for the selected-row
// highlight.
func onBG(bg lipgloss.TerminalColor, segs []seg) []seg {
	out := make([]seg, len(segs))
	for i, s := range segs {
		s.bg = bg
		out[i] = s
	}
	return out
}

// renderRow renders one line, truncating at `width` display columns.
//
// Truncation happens while building rather than over the finished string: the
// finished string carries ANSI codes, and cutting those by column count is how
// a row ends up with a background that never closes. width <= 0 means do not
// truncate.
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

// cutWidth cuts a plain string to at most n display columns.
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

// ── text helpers ───────────────────────────────────────────────────────────

// truncate cuts to n characters with an ellipsis, matching theme.ts.
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

// padEnd pads to n columns and never truncates, matching String.padEnd.
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

// fit pads or ellipsises to exactly n columns, for table cells.
func fit(s string, n int) string {
	if lipgloss.Width(s) > n {
		return truncate(s, n)
	}
	return padEnd(s, n)
}

// wrapLines hard-wraps to width columns, preserving existing newlines.
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

// prettyJson re-indents a JSON string; anything that is not JSON comes back
// unchanged.
//
// json.Indent rather than a decode-and-re-encode round trip, because Go sorts
// object keys when it marshals a map and the arguments of a tool call are read
// by a human looking for a specific field where they last saw it.
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

// ago is the short relative age used all over the consoles.
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

// parseMillis is Date.parse: a timestamp string to epoch milliseconds, with a
// flag for "that was not a time".
//
// The formats are the ones that actually arrive. ISO with a zone comes from the
// hooks and from the API; the space-separated form is what SQLite hands back on
// some routes and JavaScript reads it as LOCAL time, so it is parsed local here
// too — reading it as UTC would slide every such row by the machine's offset
// and the two implementations would disagree about when a call happened.
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

// fmtUp is the HH:MM:SS uptime in the Live title bar.
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

// num formats a float the way JavaScript prints one: no trailing zeros, and no
// decimal point when the value is whole. An eval time of 3 must read "3ms",
// not "3.000000ms".
func num(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }
