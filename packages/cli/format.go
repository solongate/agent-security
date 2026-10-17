// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/solongate/agent-security/packages/core/term"
)

var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

func out(s string) { fmt.Fprintln(stdout, s) }

func errln(s string) { fmt.Fprintln(stderr, s) }

func errPrint(s string) { fmt.Fprint(stderr, s) }

func runInteractive(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stderr, stderr
	return cmd.Run()
}

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

type usageRow struct {
	syntax  string
	desc    string
	hasDesc bool
}

func row(syntax, desc string) usageRow { return usageRow{syntax: syntax, desc: desc, hasDesc: true} }
func line(syntax string) usageRow      { return usageRow{syntax: syntax} }

const usageColumn = 40

const defaultUsageFooter = "Add --json for machine-readable output."

func usage(title, tagline string, rows []usageRow) string {
	return usageWith(title, tagline, rows, defaultUsageFooter)
}

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

func unknownSub(command, sub, usageText string) (int, error) {
	if sub != "" {
		errln(red("  ✗ ") + "Unknown " + command + " subcommand: " + cyan(sub))
	}
	errln(usageText)
	return 1, nil
}

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

func cell(r []string, i int) string {
	if i < len(r) {
		return r[i]
	}
	return ""
}

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

func fixed0(v float64) string { return fmt.Sprintf("%d", int64(math.Round(v))) }

func num(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

const markIndent = "         "

func termWidth() int {
	if v := os.Getenv("COLUMNS"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}

	f, ok := stderr.(*os.File)
	if !ok || !isTerminal(f) {
		return 0
	}
	return terminalColumns(f)
}

func wrapIndented(text string) []string {
	width := termWidth()
	avail := width - len(markIndent)

	if width == 0 || avail < 20 {
		return []string{markIndent + text}
	}

	var out []string
	line := ""
	for _, word := range strings.Fields(text) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= avail:
			line += " " + word
		default:
			out = append(out, markIndent+line)
			line = word
		}
	}
	if line != "" {
		out = append(out, markIndent+line)
	}
	return out
}

func noteln(text string) {
	for _, l := range wrapIndented(text) {
		errln(l)
	}
}