package tui

import (
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// The reusable building blocks from packages/proxy/src/tui/components.tsx.
//
// Everything here returns lines of text rather than a widget: a Bubble Tea view
// is one string, and a panel that has to guarantee its own height (see the
// frame budget in app.go) can only do that if it can count what it is about to
// emit.

// hhmmss is HH:MM:SS in local time; `--:--:--` when the timestamp is not one.
func hhmmss(atMs int64) string {
	if atMs <= 0 {
		return "--:--:--"
	}
	return time.UnixMilli(atMs).Format("15:04:05")
}

// ymd is the local calendar date; `----------` when the timestamp is not one.
func ymd(atMs int64) string {
	if atMs <= 0 {
		return "----------"
	}
	return time.UnixMilli(atMs).Format("2006-01-02")
}

// paneTitle is the section divider used across the Live and Audit consoles.
func paneTitle(label, extra string, width int) string {
	tail := " "
	if extra != "" {
		tail = " " + extra + " "
	}
	used := 2 + 1 + len([]rune(label)) + len([]rune(tail))
	fill := 0
	if width > used {
		fill = width - used
	}
	return renderRow(width,
		sg("─ ", theme.Dim),
		sgb("▎"+label, theme.AccentBright),
		sg(tail+strings.Repeat("─", fill), theme.Dim),
	)
}

// StreamRow is one tool-call row, shared verbatim by Live (the rolling buffer)
// and Audit (the full history).
//
// EvalMs is a pointer because "not recorded" and "0ms" are different answers
// and the row prints an em dash for the first.
type StreamRow struct {
	At         int64
	Tool       string
	Decision   string
	Permission string
	Detail     string
	DLP        bool
	Burst      bool
	Agent      string
	EvalMs     *float64
	Rule       string
}

// streamLine renders one row.
//
// `loc` tags where the record IS: LOC (a line in this machine's local log)
// against CLD (the cloud audit log). With local storage off nothing is LOC,
// which is the whole point of the setting — the label answers "where is this
// stored", never "where did this happen". It was changed to the second reading
// once and changed back.
//
// The columns are fixed-width and never conditional, so scrolling cannot
// reshuffle a line and glitch the frame.
func streamLine(e StreamRow, selected, date bool, width int) string {
	cursor, cursorColor := " ", theme.Dim
	if selected {
		cursor, cursorColor = "▸", theme.AccentBright
	}
	stamp := "[" + hhmmss(e.At) + " "
	if date {
		stamp = "[" + ymd(e.At) + " " + hhmmss(e.At) + " "
	}
	// A LOC/CLD column stood here, from a `loc bool` parameter. Every entry on every
	// surface comes from this machine's own audit file, so the column distinguished
	// nothing — and labelled some of them "cloud".
	evalText, evalColor := "—", theme.Dim
	if e.EvalMs != nil {
		evalText = num(*e.EvalMs) + "ms"
		if *e.EvalMs > 500 {
			evalColor = theme.Warn
		}
	}
	agent := e.Agent
	if agent == "" {
		agent = "-"
	}
	dlpColor := theme.Dim
	dlpText := "dlp:no"
	if e.DLP {
		dlpColor, dlpText = theme.Bad, "dlp:yes"
	}
	burstColor := theme.Dim
	burstText := "rl:no"
	if e.Burst {
		burstColor, burstText = theme.Warn, "rl:yes"
	}

	segs := []seg{
		sg(cursor, cursorColor),
		sg(stamp, theme.Dim),
		sg("] ", theme.Dim),
		seg{text: padEnd(e.Decision, 6), fg: decisionColor(e.Decision), bold: e.Decision != "ALLOW"},
		sg(padEnd(truncate(e.Tool, 12), 13), theme.Accent),
		sg(padEnd(e.Permission, 5), theme.Dim),
		sg(padEnd(evalText, 7), evalColor),
		sg(padEnd(truncate(agent, 11), 12), theme.Dim),
		seg{text: padEnd(dlpText, 8), fg: dlpColor, bold: e.DLP},
		seg{text: padEnd(burstText, 7), fg: burstColor, bold: e.Burst},
	}
	if e.Rule != "" && e.Decision != "ALLOW" {
		segs = append(segs, sg(truncate(e.Rule, 14)+" ", theme.Bad))
	}
	segs = append(segs, sg(e.Detail, theme.Dim))
	if selected {
		segs = onBG(lipgloss.Color(hexSelectBG), segs)
	}
	return renderRow(width, segs...)
}

// panelHeading is the boxed-panel title and the blank line under it.
func panelHeading(title, subtitle string, width int) []string {
	segs := []seg{sgb(title, theme.AccentBright)}
	if subtitle != "" {
		segs = append(segs, sg("  "+subtitle, theme.Dim))
	}
	return []string{renderRow(width, segs...), ""}
}

// dataView wraps panel content with the loading / error / empty handling every
// panel shares. An error wins over a spinner: a panel that shows "loading…"
// forever because the request failed is the worst of the three states.
func dataView(loading bool, err error, empty bool, emptyText string, width int, body []string) []string {
	if err != nil {
		return []string{renderRow(width, sg("✗ "+err.Error(), theme.Bad))}
	}
	if loading {
		return []string{renderRow(width, sg("⟳ loading…", theme.Warn))}
	}
	if empty {
		if emptyText == "" {
			emptyText = "No data."
		}
		return []string{renderRow(width, sg(emptyText, theme.Dim))}
	}
	return body
}

// Column and Cell describe a fixed-width table.
type Column struct {
	Header string
	Width  int
}

type Cell struct {
	Value string
	Color lipgloss.TerminalColor
	Dim   bool
	Bold  bool
}

// table renders a fixed-width aligned table: the header row followed by the
// data rows, each cell padded or ellipsised to its column width.
func table(columns []Column, rows [][]Cell, width int) []string {
	out := make([]string, 0, len(rows)+1)
	head := make([]seg, 0, len(columns))
	for _, c := range columns {
		head = append(head, sg(fit(c.Header, c.Width)+"  ", theme.Dim))
	}
	out = append(out, renderRow(width, head...))
	for _, row := range rows {
		segs := make([]seg, 0, len(row))
		for i, cell := range row {
			w := 10
			if i < len(columns) {
				w = columns[i].Width
			}
			s := seg{text: fit(cell.Value, w) + "  ", fg: cell.Color, bold: cell.Bold}
			if cell.Dim && s.fg == nil {
				s.fg = theme.Dim
			}
			segs = append(segs, s)
		}
		out = append(out, renderRow(width, segs...))
	}
	return out
}

// bar is a labelled horizontal bar scaled to max.
func bar(label string, value, max, width int, color lipgloss.TerminalColor) string {
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
	return renderRow(0,
		plain(padEnd(label, 16)),
		sg(strings.Repeat("█", filled), color),
		sg(strings.Repeat("░", width-filled), theme.Dim),
		sg("  "+strconv.Itoa(value), theme.Dim),
	)
}

// keyHints is the footer legend: the key in the accent colour, its meaning dim.
func keyHints(hints [][2]string, width int) string {
	segs := make([]seg, 0, len(hints)*3)
	for i, h := range hints {
		segs = append(segs, sg(h[0], theme.Accent), sg(" "+h[1], theme.Dim))
		if i < len(hints)-1 {
			segs = append(segs, sg("   ", theme.Dim))
		}
	}
	return renderRow(width, segs...)
}

// helpGroup is one section of a `?` overlay.
type helpGroup struct {
	title string
	keys  [][2]string
}

// helpBlock renders help groups: a heading per group, then one line per key
// with its description.
func helpBlock(groups []helpGroup, keyWidth, width int) []string {
	var out []string
	for _, g := range groups {
		out = append(out, renderRow(width, sgb(g.title, theme.Accent)))
		for _, k := range g.keys {
			out = append(out,
				renderRow(width,
					sg(padEnd("  "+k[0], keyWidth), theme.AccentBright),
					sg(k[1], theme.Dim)))
		}
		out = append(out, "")
	}
	return out
}
