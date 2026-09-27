// Package commands is the scriptable CLI: everything `solongate <verb>` does
// outside the dataroom, ported from packages/proxy/src/commands.
//
// Two audiences, and the split between them is the contract:
//
//   - humans get coloured, aligned tables on STDERR;
//   - machines get `--json`, and then STDOUT carries one JSON document and
//     nothing else.
//
// That is why every status line, table and heading below goes to stderr. A
// progress line on stdout would make `solongate audit --json | jq` fail on a
// document it could otherwise parse, and the whole point of `--json` is that it
// survives being piped.
package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/codeyevsky/solongate/proxy/internal/term"
)

// The two streams, as variables so a test can prove the separation rather than
// assume it. The `--json` contract is exactly "stdout carries one document and
// nothing else", and that is only worth having if something checks it.
var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

// out is command OUTPUT — the thing a user pipes into jq.
func out(s string) { fmt.Fprintln(stdout, s) }

// errln is everything a human reads: headings, tables, confirmations, errors.
// Named errln rather than err so it cannot be shadowed by the error variable
// that exists in nearly every function here.
func errln(s string) { fmt.Fprintln(stderr, s) }

// printJSON writes a value as pretty JSON to stdout: the machine contract.
//
// Two deviations from a plain json.MarshalIndent, both of which would otherwise
// show up in output the Node CLI does not produce:
//
//   - HTML escaping is off. By default encoding/json rewrites ampersand, less
//     than and greater than as their six-character unicode escapes, so a
//     webhook URL with a query string came back unreadable where
//     JSON.stringify leaves it alone. The document still parses; it just no
//     longer looks like what the API said.
//   - raw JSON is re-indented rather than decoded and re-encoded, so a
//     passthrough payload keeps the API's key order. Decoding into map[string]any
//     would sort the keys and silently reorder every response this version does
//     not have a struct for.
func printJSON(v any) {
	if raw, ok := v.(json.RawMessage); ok {
		var buf bytes.Buffer
		if json.Indent(&buf, raw, "", "  ") == nil {
			out(buf.String())
			return
		}
		out(string(raw))
		return
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		errln(red("  ✗ ") + "could not encode the response as JSON: " + err.Error())
		return
	}
	fmt.Fprint(stdout, buf.String())
}

func dim(s string) string    { return term.Dim + s + term.Reset }
func bold(s string) string   { return term.Bold + s + term.Reset }
func green(s string) string  { return term.Green + s + term.Reset }
func red(s string) string    { return term.Red + s + term.Reset }
func yellow(s string) string { return term.Yellow + s + term.Reset }
func cyan(s string) string   { return term.Cyan + s + term.Reset }

// usageRow is one line of a usage block. A row with no description prints on
// its own (used for long or continuation lines); a row with no syntax at all is
// a blank separator line.
type usageRow struct {
	syntax  string
	desc    string
	hasDesc bool
}

func row(syntax, desc string) usageRow { return usageRow{syntax: syntax, desc: desc, hasDesc: true} }
func line(syntax string) usageRow      { return usageRow{syntax: syntax} }

// usageColumn is where descriptions start. Syntax longer than this drops the
// description onto its own indented line rather than pushing it off an
// 80-column terminal.
const usageColumn = 40

// defaultUsageFooter is the last line of a usage block when the command has not
// asked for its own.
const defaultUsageFooter = "Add --json for machine-readable output."

func usage(title, tagline string, rows []usageRow) string {
	return usageWith(title, tagline, rows, defaultUsageFooter)
}

// usageWith renders the same block with an explicit footer; an empty footer
// omits the trailing section entirely.
func usageWith(title, tagline string, rows []usageRow, footer string) string {
	lines := []string{"", "  " + term.Bold + term.Blue4 + title + term.Reset + "  " + dim(tagline), ""}
	for _, r := range rows {
		switch {
		case r.syntax == "":
			lines = append(lines, "")
		case !r.hasDesc:
			lines = append(lines, "    "+cyan(r.syntax))
		case displayWidth(r.syntax) <= usageColumn:
			pad := strings.Repeat(" ", usageColumn-displayWidth(r.syntax))
			lines = append(lines, "    "+cyan(r.syntax)+pad+dim(r.desc))
		default:
			lines = append(lines, "    "+cyan(r.syntax))
			lines = append(lines, "    "+strings.Repeat(" ", usageColumn)+dim(r.desc))
		}
	}
	if footer != "" {
		lines = append(lines, "", "  "+dim(footer))
	}
	return strings.Join(lines, "\n")
}

// unknownSub is what a command's switch falls through to when the first
// positional is not one of its subcommands.
//
// Printing the usage block on its own was the old behaviour everywhere, and it
// reads as though the command simply has no default: a correct-looking help
// screen appears, and finding the mistake means diffing it against what you
// typed. Naming the token first costs one line and removes that step.
//
// `solongate ghost -g` is the case that made it obvious. parse() treats only
// `--x` as a flag, so a single-dash token arrives as a SUBCOMMAND, and the
// result was a help screen that looked like a successful command.
//
// The empty case still happens: a command invoked with a flag and no
// subcommand at all has nothing to name, and a line reading `Unknown
// subcommand: ""` would be worse than none.
func unknownSub(command, sub, usageText string) (int, error) {
	if sub != "" {
		errln(red("  ✗ ") + "Unknown " + command + " subcommand: " + cyan(sub))
	}
	errln(usageText)
	return 1, nil
}

// decisionColor colours a decision string: ALLOW green, DENY/DENIED red.
func decisionColor(decision string) string {
	d := strings.ToUpper(decision)
	switch d {
	case "ALLOW":
		return green(d)
	case "DENY", "DENIED":
		return red(d)
	}
	return dim(d)
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// displayWidth measures a cell for alignment, ignoring the colour codes in it —
// otherwise every coloured cell pads nine characters too narrow and the table
// shears.
//
// The count is UTF-16 code units, which is what JavaScript's String.length
// returns, so a table renders identically under both implementations. It is not
// the terminal's idea of width either way (a CJK glyph occupies two columns and
// counts as one here) but matching the existing behaviour matters more than
// fixing it in one of the two CLIs.
func displayWidth(s string) int {
	n := 0
	for _, r := range ansi.ReplaceAllString(s, "") {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// table renders an aligned table to stderr. Headers are dimmed; each cell may
// already be coloured. Columns size to their widest cell.
func table(headers []string, rows [][]string) {
	cols := len(headers)
	w := make([]int, cols)
	for i := 0; i < cols; i++ {
		w[i] = displayWidth(headers[i])
	}
	for _, r := range rows {
		for i := 0; i < cols; i++ {
			w[i] = max(w[i], displayWidth(cell(r, i)))
		}
	}
	pad := func(s string, i int) string {
		n := w[i] - displayWidth(s)
		if n < 0 {
			n = 0
		}
		return s + strings.Repeat(" ", n)
	}

	head := make([]string, cols)
	for i, h := range headers {
		head[i] = dim(pad(h, i))
	}
	errln("  " + strings.Join(head, "  "))
	for _, r := range rows {
		cells := make([]string, cols)
		for i := 0; i < cols; i++ {
			cells[i] = pad(cell(r, i), i)
		}
		errln("  " + strings.Join(cells, "  "))
	}
}

// cell tolerates a short row rather than panicking on it. A response with a
// field this version does not know about should print a gap, not take the whole
// command down.
func cell(r []string, i int) string {
	if i < len(r) {
		return r[i]
	}
	return ""
}

// truncate shortens to n characters with an ellipsis.
//
// It cuts on rune boundaries even though it measures in UTF-16 units, because
// the alternative — reproducing JavaScript's ability to slice a surrogate pair
// in half — writes a broken character into the terminal to be faithful to a bug.
func truncate(s string, n int) string {
	if displayWidth(s) <= n {
		return s
	}
	limit := max(0, n-1)
	var b strings.Builder
	used := 0
	for _, r := range s {
		w := 1
		if r > 0xFFFF {
			w = 2
		}
		if used+w > limit {
			break
		}
		b.WriteRune(r)
		used += w
	}
	return b.String() + "…"
}

var sparkBlocks = []string{"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"}

// sparkline renders a numeric series as one line of block characters. An empty
// series renders as nothing at all rather than as a flat line, so a caller can
// tell "no data" from "no traffic".
func sparkline(values []int) string {
	if len(values) == 0 {
		return ""
	}
	maxV := 0
	for _, v := range values {
		maxV = max(maxV, v)
	}
	if maxV == 0 {
		return strings.Repeat(sparkBlocks[0], len(values))
	}
	var b strings.Builder
	top := len(sparkBlocks) - 1
	for _, v := range values {
		idx := int(math.Round(float64(v) / float64(maxV) * float64(top)))
		b.WriteString(sparkBlocks[min(top, max(0, idx))])
	}
	return b.String()
}

// fixed0 rounds to a whole number the way JavaScript's toFixed(0) does — half
// away from zero. Go's %.0f rounds half to even, so a 0.5 KB log file printed
// as 0KB there and 1KB in the CLI this replaces.
func fixed0(v float64) string { return fmt.Sprintf("%d", int64(math.Round(v))) }

// num formats a float the way JavaScript prints one: the shortest decimal that
// round-trips, and never an exponent at the magnitudes these fields carry. A
// trust score of 75 has to read as 75, not 75.000000 and not 7.5e+01.
func num(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }
