// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cliutil

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/core/term"
)

func withStdout(t *testing.T) *bytes.Buffer {
	t.Helper()
	orig := stdout
	var buf bytes.Buffer
	stdout = &buf
	t.Cleanup(func() { stdout = orig })
	return &buf
}

func withStderr(t *testing.T) *bytes.Buffer {
	t.Helper()
	orig := stderr
	var buf bytes.Buffer
	stderr = &buf
	t.Cleanup(func() { stderr = orig })
	return &buf
}

func TestOut(t *testing.T) {
	buf := withStdout(t)
	Out("hello")
	if got := buf.String(); got != "hello\n" {
		t.Errorf("Out wrote %q, want %q", got, "hello\n")
	}
}

func TestErrln(t *testing.T) {
	buf := withStderr(t)
	Errln("hello")
	if got := buf.String(); got != "hello\n" {
		t.Errorf("Errln wrote %q, want %q", got, "hello\n")
	}
}

func TestErrPrint(t *testing.T) {
	buf := withStderr(t)
	ErrPrint("hello")
	if got := buf.String(); got != "hello" {
		t.Errorf("ErrPrint wrote %q, want %q", got, "hello")
	}
}

func TestRunInteractiveSuccess(t *testing.T) {
	withStderr(t)
	if err := RunInteractive("true"); err != nil {
		t.Errorf("RunInteractive(true) = %v, want nil", err)
	}
}

func TestRunInteractiveMissingBinary(t *testing.T) {
	withStderr(t)
	if err := RunInteractive("this-binary-does-not-exist-cliutil-test"); err == nil {
		t.Error("RunInteractive with a nonexistent binary = nil error, want an error")
	}
}

func TestPrintJSONStruct(t *testing.T) {
	buf := withStdout(t)
	type payload struct {
		Name string `json:"name"`
	}
	PrintJSON(payload{Name: "alice"})
	if !strings.Contains(buf.String(), `"name": "alice"`) {
		t.Errorf("PrintJSON struct output = %q, want it to contain an indented name field", buf.String())
	}
}

func TestPrintJSONRawMessage(t *testing.T) {
	buf := withStdout(t)
	PrintJSON(json.RawMessage(`{"a":1}`))
	got := buf.String()
	if !strings.Contains(got, "\"a\": 1") {
		t.Errorf("PrintJSON(RawMessage) = %q, want pretty-printed JSON", got)
	}
}

func TestPrintJSONEncodeError(t *testing.T) {
	outBuf := withStdout(t)
	errBuf := withStderr(t)
	type bad struct {
		C chan int
	}
	PrintJSON(bad{C: make(chan int)})
	if outBuf.Len() != 0 {
		t.Errorf("PrintJSON on an unencodable value wrote to stdout: %q", outBuf.String())
	}
	if !strings.Contains(errBuf.String(), "could not encode the response as JSON") {
		t.Errorf("PrintJSON on an unencodable value wrote %q to stderr, want the encode error message", errBuf.String())
	}
}

func TestColorWrappers(t *testing.T) {
	cases := []struct {
		name  string
		fn    func(string) string
		color string
	}{
		{"Dim", Dim, term.Dim},
		{"Bold", Bold, term.Bold},
		{"Green", Green, term.Green},
		{"Red", Red, term.Red},
		{"Yellow", Yellow, term.Yellow},
		{"Cyan", Cyan, term.Cyan},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.color + "x" + term.Reset
			if got := tc.fn("x"); got != want {
				t.Errorf("%s(x) = %q, want %q", tc.name, got, want)
			}
		})
	}
}

func TestRow(t *testing.T) {
	r := Row("syntax", "desc")
	if r.syntax != "syntax" || r.desc != "desc" || !r.hasDesc {
		t.Errorf("Row() = %+v, want syntax=syntax desc=desc hasDesc=true", r)
	}
}

func TestLine(t *testing.T) {
	r := Line("syntax")
	if r.syntax != "syntax" || r.hasDesc {
		t.Errorf("Line() = %+v, want syntax=syntax hasDesc=false", r)
	}
}

func TestUsage(t *testing.T) {
	longSyntax := "this-is-a-very-long-command-syntax-string-that-exceeds-usage-column"
	rows := []UsageRow{
		Row("short", "a short description"),
		Line("bare line"),
		Line(""),
		Row(longSyntax, "wrapped description"),
	}
	got := Usage("Title", "tagline", rows)

	for _, want := range []string{"Title", "tagline", "short", "a short description", "bare line", longSyntax, "wrapped description", defaultUsageFooter} {
		if !strings.Contains(got, want) {
			t.Errorf("Usage output missing %q:\n%s", want, got)
		}
	}

	lines := strings.Split(got, "\n")
	syntaxIdx := -1
	for i, l := range lines {
		if strings.Contains(l, longSyntax) {
			syntaxIdx = i
			break
		}
	}
	if syntaxIdx == -1 {
		t.Fatalf("long syntax line not found in:\n%s", got)
	}
	if syntaxIdx+1 >= len(lines) || !strings.Contains(lines[syntaxIdx+1], "wrapped description") {
		t.Errorf("expected the description of a long syntax row on the following line, got: %q", lines[syntaxIdx+1])
	}
	if strings.Contains(lines[syntaxIdx], "wrapped description") {
		t.Errorf("long syntax row should not have its description on the same line: %q", lines[syntaxIdx])
	}
}

func TestUsageWithCustomFooter(t *testing.T) {
	got := UsageWith("T", "tag", nil, "custom footer")
	if !strings.Contains(got, "custom footer") {
		t.Errorf("UsageWith output missing custom footer:\n%s", got)
	}
	if strings.Contains(got, defaultUsageFooter) {
		t.Errorf("UsageWith with a custom footer should not include the default footer:\n%s", got)
	}
}

func TestUsageWithEmptyFooterOmitsFooterLines(t *testing.T) {
	got := UsageWith("T", "tag", nil, "")
	if strings.Contains(got, defaultUsageFooter) {
		t.Errorf("UsageWith with empty footer should not include the default footer:\n%s", got)
	}
}

func TestUnknownSubWithSub(t *testing.T) {
	buf := withStderr(t)
	code, err := UnknownSub("mycmd", "badsub", "usage text here")
	if code != 1 || err != nil {
		t.Errorf("UnknownSub = %d, %v, want 1, nil", code, err)
	}
	got := buf.String()
	if !strings.Contains(got, "Unknown") || !strings.Contains(got, "mycmd") || !strings.Contains(got, "badsub") {
		t.Errorf("UnknownSub output = %q, want it to mention the unknown subcommand", got)
	}
	if !strings.Contains(got, "usage text here") {
		t.Errorf("UnknownSub output = %q, want the usage text", got)
	}
}

func TestUnknownSubWithoutSub(t *testing.T) {
	buf := withStderr(t)
	code, err := UnknownSub("mycmd", "", "usage text here")
	if code != 1 || err != nil {
		t.Errorf("UnknownSub = %d, %v, want 1, nil", code, err)
	}
	got := buf.String()
	if strings.Contains(got, "Unknown") {
		t.Errorf("UnknownSub with no sub should not print an Unknown line: %q", got)
	}
	if !strings.Contains(got, "usage text here") {
		t.Errorf("UnknownSub output = %q, want the usage text", got)
	}
}

func TestDecisionColor(t *testing.T) {
	cases := []struct {
		name     string
		decision string
		want     string
	}{
		{"allow upper", "ALLOW", Green("ALLOW")},
		{"allow lower", "allow", Green("ALLOW")},
		{"deny", "DENY", Red("DENY")},
		{"denied", "DENIED", Red("DENIED")},
		{"other", "pending", Dim("PENDING")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecisionColor(tc.decision); got != tc.want {
				t.Errorf("DecisionColor(%q) = %q, want %q", tc.decision, got, tc.want)
			}
		})
	}
}

func TestDisplayWidthPlainASCII(t *testing.T) {
	if got := DisplayWidth("hello"); got != 5 {
		t.Errorf("DisplayWidth(hello) = %d, want 5", got)
	}
}

func TestDisplayWidthStripsANSI(t *testing.T) {
	colored := Red("x")
	if got := DisplayWidth(colored); got != 1 {
		t.Errorf("DisplayWidth(%q) = %d, want 1 (ANSI escapes stripped)", colored, got)
	}
}

func TestDisplayWidthWideRune(t *testing.T) {
	if got := DisplayWidth("😀"); got != 2 {
		t.Errorf("DisplayWidth(emoji) = %d, want 2", got)
	}
}

func TestTable(t *testing.T) {
	buf := withStderr(t)
	Table([]string{"Name", "Age"}, [][]string{
		{"Alice", "30"},
		{"Bob", "7"},
	})
	got := buf.String()
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("Table produced %d lines, want 3 (header + 2 rows): %q", len(lines), got)
	}
	if !strings.Contains(lines[0], "Name") || !strings.Contains(lines[0], "Age") {
		t.Errorf("header line = %q, want it to contain Name and Age", lines[0])
	}
	if !strings.Contains(lines[1], "Alice") || !strings.Contains(lines[2], "Bob") {
		t.Errorf("table rows = %q, %q, want Alice and Bob", lines[1], lines[2])
	}
}

func TestCell(t *testing.T) {
	row := []string{"a", "b"}
	if got := Cell(row, 0); got != "a" {
		t.Errorf("Cell(row, 0) = %q, want a", got)
	}
	if got := Cell(row, 5); got != "" {
		t.Errorf("Cell(row, 5) = %q, want \"\"", got)
	}
}

func TestTruncateShorterThanLimit(t *testing.T) {
	if got := Truncate("hi", 10); got != "hi" {
		t.Errorf("Truncate(hi, 10) = %q, want hi", got)
	}
}

func TestTruncateLonger(t *testing.T) {
	got := Truncate("hello world", 5)
	if !strings.HasSuffix(got, "…") {
		t.Errorf("Truncate(hello world, 5) = %q, want it to end in an ellipsis", got)
	}
	if DisplayWidth(got) != 5 {
		t.Errorf("Truncate(hello world, 5) = %q, display width %d, want 5", got, DisplayWidth(got))
	}
}

func TestTruncateWithWideRuneNearBoundary(t *testing.T) {
	got := Truncate("a😀😀😀😀", 4)
	if DisplayWidth(got) > 4 {
		t.Errorf("Truncate with wide runes = %q, display width %d, want <= 4", got, DisplayWidth(got))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("Truncate with wide runes = %q, want it to end in an ellipsis", got)
	}
}

func TestSparklineEmpty(t *testing.T) {
	if got := Sparkline(nil); got != "" {
		t.Errorf("Sparkline(nil) = %q, want \"\"", got)
	}
}

func TestSparklineAllZero(t *testing.T) {
	got := Sparkline([]int{0, 0, 0})
	want := strings.Repeat(sparkBlocks[0], 3)
	if got != want {
		t.Errorf("Sparkline([0,0,0]) = %q, want %q", got, want)
	}
}

func TestSparklineMixedValues(t *testing.T) {
	values := []int{1, 5, 3, 9, 0, 7}
	got := Sparkline(values)
	if got == "" {
		t.Fatal("Sparkline with mixed values returned empty string")
	}
	if n := len([]rune(got)); n != len(values) {
		t.Errorf("Sparkline produced %d blocks, want %d", n, len(values))
	}
}

func TestSparklineSingleValue(t *testing.T) {
	got := Sparkline([]int{42})
	if n := len([]rune(got)); n != 1 {
		t.Errorf("Sparkline([42]) produced %d blocks, want 1", n)
	}
}

func TestNum(t *testing.T) {
	if got := Num(3.0); got != "3" {
		t.Errorf("Num(3.0) = %q, want 3", got)
	}
	if got := Num(3.5); got != "3.5" {
		t.Errorf("Num(3.5) = %q, want 3.5", got)
	}
}

func TestTermWidthFromEnv(t *testing.T) {
	t.Setenv("COLUMNS", "100")
	if got := TermWidth(); got != 100 {
		t.Errorf("TermWidth() with COLUMNS=100 = %d, want 100", got)
	}
}

func TestTermWidthInvalidEnvFallsThrough(t *testing.T) {
	withStderr(t)
	cases := []string{"garbage", "0", "-5"}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			t.Setenv("COLUMNS", v)
			if got := TermWidth(); got != 0 {
				t.Errorf("TermWidth() with COLUMNS=%q = %d, want 0 (stderr swapped to a non-*os.File)", v, got)
			}
		})
	}
}

func TestTermWidthUnsetWithNonFileStderr(t *testing.T) {
	t.Setenv("COLUMNS", "")
	withStderr(t)
	if got := TermWidth(); got != 0 {
		t.Errorf("TermWidth() with no COLUMNS and a non-*os.File stderr = %d, want 0", got)
	}
}

func TestNoteln(t *testing.T) {
	t.Setenv("COLUMNS", "80")
	buf := withStderr(t)
	Noteln("a short note")
	if !strings.Contains(buf.String(), "a short note") {
		t.Errorf("Noteln output = %q, want it to contain the note text", buf.String())
	}

	buf.Reset()
	long := strings.Repeat("word ", 40)
	Noteln(long)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) < 2 {
		t.Errorf("Noteln with long text produced %d line(s), want more than one", len(lines))
	}
}