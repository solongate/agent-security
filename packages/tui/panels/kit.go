// SPDX-License-Identifier: Apache-2.0

// Package panels is the TUI's section panels in Bubble Tea: Policies,
// Fleet and Settings, plus the two editors — DLP and Rate Limit — that are no
// longer sections of their own but folds of a policy variant, mounted BOUND by
// the Policies panel.
//
// The panels own no terminal state. The shell (tui) decides what is on
// screen, hands each panel the box it may draw in through a PanelContext, and
// routes keys to whichever one has focus; a panel only ever returns a string it
// promises fits.
//
// THE FRAME-HEIGHT RULE. Every View ends in clip(), which hard-truncates to the
// rows the shell allowed. Ink stopped diffing and repainted the whole terminal
// on every render as soon as a frame reached the terminal height, and it read as
// a glitch rather than as a layout bug; Bubble Tea does the same thing. A panel
// that miscounts its own budget therefore loses a line instead of costing the
// shell its render path.
//
// The panels live in their own package, and the direction of the import is why:
// the shell must not import them, or the registry below could not be in the
// shell. Each file registers its section from init(), so the section table stays
// one line per panel and several people can port different sections without
// editing the same file. Something has to IMPORT this package for those init
// functions to run — see the note on Version.
//
// The theme and the small layout helpers here are a second copy of the shell's,
// because the shell's are unexported. They should collapse into one exported set
// rather than drift; see the port notes.
package panels

import (
	"context"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/solongate/agent-security/packages/core/config"
)

// Version is the CLI's own version, shown in the Settings UPDATES section.
//
// It is a variable rather than a field on tui.Deps because the version is
// stamped into main at build time and the shell does not carry it. main sets it
// on the way into the TUI; left unset the row says "dev", which is what a
// developer build is.
var Version = "dev"

// bg is the context every panel request runs under. The api client puts its own
// deadline on each attempt, so a panel does not impose a second one; what this
// does NOT do is tie a request to a mount, which is what the generation tag
// below is for.
func bg() context.Context { return context.Background() }

// genTag rides on every asynchronous answer and every tick.
//
// gen is the shell's mount generation: the shell drops any message whose
// generation is not current, so an answer that was in flight when the viewed
// account changed cannot land in the panel that replaced it and show the
// previous account's data.
//
// tok is finer than that and the shell knows nothing about it. Leaving a section
// and coming back builds a NEW panel of the same generation while the old one's
// ticker is still armed; without the token the new panel would re-arm that
// chain as well and end up polling twice as often for every visit.
type genTag struct {
	gen int
	tok int
}

func (g genTag) Generation() int { return g.gen }

// tokens hands each mounted panel its own token. Not atomic on purpose: Bubble
// Tea builds and updates models on one goroutine.
var tokens int

func nextToken() int { tokens++; return tokens }

// ── theme ──────────────────────────────────────────────────────────────────

// The palette from tui/theme.ts, in the same ANSI colours Ink resolved those
// names to: green 2, yellow 3, red 1, gray 8. Keeping the numbers rather than
// hexes means a user's terminal theme still applies, which is what the Ink
// version did.
var (
	accentColor = lipgloss.Color(accentFromConfig())
	okColor     = lipgloss.Color("2")
	warnColor   = lipgloss.Color("3")
	badColor    = lipgloss.Color("1")
	dimColor    = lipgloss.Color("8")
	// The selection background, byte for byte the one the Ink panels used.
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

// accentFromConfig reads ~/.solongate/tui-config.json the way theme.ts does.
//
// Ink took CSS-ish colour NAMES; lipgloss takes an ANSI index or a hex, so the
// handful of names anyone actually sets are mapped and anything else is passed
// through — a hex works unchanged, and an unrecognised name falls back to white
// rather than rendering as a literal.
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

// modeColor is theme.ts's modeColor: a layer that BLOCKS is green because it is
// doing its job, detect is yellow because it is only watching, off is dim.
func modeStyle(m string) lipgloss.Style {
	switch m {
	case "block", "active", "on":
		return stOK
	case "detect", "idle":
		return stWarn
	}
	return stDim
}

// ── one line of a panel ────────────────────────────────────────────────────

// lineBuf builds one rendered row out of styled runs.
//
// It exists for the selection highlight. Ink put a backgroundColor on the whole
// row and every coloured span inside it kept its foreground; lipgloss renders
// each run separately and each run's reset would drop a background applied
// around it, so the background has to travel with every run instead.
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

// ── text helpers, ported from theme.ts / components.tsx ────────────────────

// truncate is theme.ts's truncate: an ellipsis replaces the last character
// rather than being added after it, so the result never exceeds n columns.
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

// pad right-pads to w without ever truncating.
func pad(s string, w int) string {
	if d := w - lipgloss.Width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// padLeft is padStart.
func padLeft(s string, w int) string {
	if d := w - lipgloss.Width(s); d > 0 {
		return strings.Repeat(" ", d) + s
	}
	return s
}

// fit is the Table cell rule from components.tsx: truncate to the column width,
// then pad to it, so a row can never reflow the columns to its right.
func fit(s string, w int) string { return pad(truncate(s, w), w) }

// ── layout ─────────────────────────────────────────────────────────────────

// window slices a list of rendered lines to a budget, keeping cursorLine in
// view, and reports how many lines are off-screen either way so the hint line
// can say ▲n / ▼n.
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

// scrollTag renders the ` · ▲n · ▼m` suffix the panels put on their hint lines.
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

// clip is the frame-height guarantee. See the package comment: this is the
// difference between a panel that overflows by one line and a terminal that
// repaints itself on every keystroke.
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

// dataView is components.tsx's DataView: the load / error / empty states every
// panel shares, so none of them invents its own wording for "nothing here yet".
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

// statusLine colours a one-line status the way every panel does: anything
// starting with ✗ is a failure, everything else is a confirmation.
func statusLine(s string) string {
	if strings.HasPrefix(s, "✗") {
		return stBad.Render(s)
	}
	return stOK.Render(s)
}

// spinFrames is the Settings spinner. A frozen glyph during an npm install or a
// device login reads as a hang, which is the whole reason it is animated.
var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// orDash is the dash a table cell shows instead of an empty column, so a row
// with nothing in one field still reads as a row.
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

// errText is the message a failed command shows. It is never the raw error for
// a nil error, because "<nil>" in a status line has read as a real failure
// before.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
