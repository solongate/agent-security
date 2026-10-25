// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cliutil

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

func Out(s string) { fmt.Fprintln(stdout, s) }

func Errln(s string) { fmt.Fprintln(stderr, s) }

func ErrPrint(s string) { fmt.Fprint(stderr, s) }

func RunInteractive(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, stderr, stderr
	return cmd.Run()
}

func PrintJSON(v any) {
	if raw, ok := v.(json.RawMessage); ok {
		var buf bytes.Buffer
		if json.Indent(&buf, raw, "", "  ") == nil {
			Out(buf.String())
			return
		}
		Out(string(raw))
		return
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		Errln(Red("  ✗ ") + "could not encode the response as JSON: " + err.Error())
		return
	}
	fmt.Fprint(stdout, buf.String())
}

func Dim(s string) string    { return term.Dim + s + term.Reset }
func Bold(s string) string   { return term.Bold + s + term.Reset }
func Green(s string) string  { return term.Green + s + term.Reset }
func Red(s string) string    { return term.Red + s + term.Reset }
func Yellow(s string) string { return term.Yellow + s + term.Reset }
func Cyan(s string) string   { return term.Cyan + s + term.Reset }

type UsageRow struct {
	syntax  string
	desc    string
	hasDesc bool
}

func Row(syntax, desc string) UsageRow { return UsageRow{syntax: syntax, desc: desc, hasDesc: true} }
func Line(syntax string) UsageRow      { return UsageRow{syntax: syntax} }

const usageColumn = 40

const defaultUsageFooter = "Add --json for machine-readable output."

func Usage(title, tagline string, rows []UsageRow) string {
	return UsageWith(title, tagline, rows, defaultUsageFooter)
}

func UsageWith(title, tagline string, rows []UsageRow, footer string) string {
	lines := []string{"", "  " + term.Bold + term.Blue4 + title + term.Reset + "  " + Dim(tagline), ""}
	for _, r := range rows {
		switch {
		case r.syntax == "":
			lines = append(lines, "")
		case !r.hasDesc:
			lines = append(lines, "    "+Cyan(r.syntax))
		case DisplayWidth(r.syntax) <= usageColumn:
			pad := strings.Repeat(" ", usageColumn-DisplayWidth(r.syntax))
			lines = append(lines, "    "+Cyan(r.syntax)+pad+Dim(r.desc))
		default:
			lines = append(lines, "    "+Cyan(r.syntax))
			lines = append(lines, "    "+strings.Repeat(" ", usageColumn)+Dim(r.desc))
		}
	}
	if footer != "" {
		lines = append(lines, "", "  "+Dim(footer))
	}
	return strings.Join(lines, "\n")
}

func UnknownSub(command, sub, usageText string) (int, error) {
	if sub != "" {
		Errln(Red("  ✗ ") + "Unknown " + command + " subcommand: " + Cyan(sub))
	}
	Errln(usageText)
	return 1, nil
}

func DecisionColor(decision string) string {
	d := strings.ToUpper(decision)
	switch d {
	case "ALLOW":
		return Green(d)
	case "DENY", "DENIED":
		return Red(d)
	}
	return Dim(d)
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func DisplayWidth(s string) int {
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

func PadRight(s string, n int) string {
	if DisplayWidth(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-DisplayWidth(s))
}

func Table(headers []string, rows [][]string) {
	cols := len(headers)
	w := make([]int, cols)
	for i := 0; i < cols; i++ {
		w[i] = DisplayWidth(headers[i])
	}
	for _, r := range rows {
		for i := 0; i < cols; i++ {
			w[i] = max(w[i], DisplayWidth(Cell(r, i)))
		}
	}
	pad := func(s string, i int) string {
		n := w[i] - DisplayWidth(s)
		if n < 0 {
			n = 0
		}
		return s + strings.Repeat(" ", n)
	}

	head := make([]string, cols)
	for i, h := range headers {
		head[i] = Dim(pad(h, i))
	}
	Errln("  " + strings.Join(head, "  "))
	for _, r := range rows {
		cells := make([]string, cols)
		for i := 0; i < cols; i++ {
			cells[i] = pad(Cell(r, i), i)
		}
		Errln("  " + strings.Join(cells, "  "))
	}
}

func Cell(r []string, i int) string {
	if i < len(r) {
		return r[i]
	}
	return ""
}

func Truncate(s string, n int) string {
	if DisplayWidth(s) <= n {
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

func Sparkline(values []int) string {
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

func Num(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

const markIndent = "         "

func TermWidth() int {
	if v := os.Getenv("COLUMNS"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
			return n
		}
	}

	f, ok := stderr.(*os.File)
	if !ok || !IsTerminal(f) {
		return 0
	}
	return TerminalColumns(f)
}

func WrapIndented(text string) []string {
	width := TermWidth()
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

func Noteln(text string) {
	for _, l := range WrapIndented(text) {
		Errln(l)
	}
}
