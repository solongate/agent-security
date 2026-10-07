// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// capture redirects both streams for one call and hands back what each got.
// Nearly every assertion in this package is about WHICH stream something landed
// on, not only about its text.
func capture(t *testing.T, fn func()) (outStr, errStr string) {
	t.Helper()
	var o, e bytes.Buffer
	prevOut, prevErr := stdout, stderr
	stdout, stderr = &o, &e
	t.Cleanup(func() { stdout, stderr = prevOut, prevErr })
	fn()
	return o.String(), e.String()
}

func TestTableAlignsAroundColourCodes(t *testing.T) {
	_, e := capture(t, func() {
		table([]string{"ID", "NAME"}, [][]string{
			{cyan("a"), "short"},
			{cyan("a-much-longer-id"), "x"},
		})
	})
	lines := strings.Split(strings.TrimRight(e, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header + 2 rows, got %d lines: %q", len(lines), lines)
	}
	// The NAME column has to start at the same visible offset on both rows. A
	// width measured with the escape codes included would push the first row's
	// second column nine characters right.
	col := func(s string) int { return strings.Index(ansi.ReplaceAllString(s, ""), "short") }
	want := col(lines[1])
	if got := strings.Index(ansi.ReplaceAllString(lines[2], ""), "x"); got != want {
		t.Fatalf("columns sheared: %q starts at %d, %q at %d", "short", want, "x", got)
	}
}

func TestTruncateAddsEllipsisAndKeepsRunesWhole(t *testing.T) {
	if got := truncate("abcdef", 10); got != "abcdef" {
		t.Fatalf("short strings pass through, got %q", got)
	}
	if got := truncate("abcdef", 4); got != "abc…" {
		t.Fatalf("want abc…, got %q", got)
	}
	// A multi-byte rune must not be cut in half: a broken UTF-8 sequence in a
	// table cell corrupts the rest of the line on most terminals.
	if got := truncate("ünïcödé-name", 5); !isValidUTF8(got) {
		t.Fatalf("truncate produced invalid UTF-8: %q", got)
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == 0xFFFD {
			return false
		}
	}
	return true
}

func TestSparklineDistinguishesNoDataFromNoTraffic(t *testing.T) {
	if got := sparkline(nil); got != "" {
		t.Fatalf("no data must render as nothing, got %q", got)
	}
	if got := sparkline([]int{0, 0, 0}); got != "▁▁▁" {
		t.Fatalf("no traffic must render as a flat line, got %q", got)
	}
	if got := sparkline([]int{0, 8}); !strings.HasSuffix(got, "█") {
		t.Fatalf("the peak must be the tallest block, got %q", got)
	}
}

func TestPrintJSONLeavesURLsReadable(t *testing.T) {
	o, e := capture(t, func() {
		printJSON(map[string]string{"url": "https://hooks.example.com/x?a=1&b=2"})
	})
	if e != "" {
		t.Fatalf("--json output must not touch stderr, got %q", e)
	}
	if !strings.Contains(o, "a=1&b=2") {
		t.Fatalf("the ampersand was escaped away: %q", o)
	}
	var back map[string]string
	if err := json.Unmarshal([]byte(o), &back); err != nil {
		t.Fatalf("stdout is not a JSON document: %v", err)
	}
}

func TestPrintJSONKeepsRawKeyOrder(t *testing.T) {
	// The agent detail endpoint is passed through raw. Decoding it into a map
	// would sort these keys and quietly reorder every field the CLI has no
	// struct for.
	raw := json.RawMessage(`{"zebra":1,"apple":2}`)
	o, _ := capture(t, func() { printJSON(raw) })
	if strings.Index(o, "zebra") > strings.Index(o, "apple") {
		t.Fatalf("raw JSON was reordered: %q", o)
	}
}

func TestUsageWrapsLongSyntaxOntoItsOwnLine(t *testing.T) {
	short := "policy list"
	long := "policy dry-run <id|file.json> [--limit N] [--mode denylist|whitelist]"
	block := usage("solongate policy", "manage cloud policies", []usageRow{
		row(short, "list all policies"),
		row(long, "replay recent traffic"),
	})
	plain := ansi.ReplaceAllString(block, "")
	for _, l := range strings.Split(plain, "\n") {
		if strings.Contains(l, short) && !strings.Contains(l, "list all policies") {
			t.Fatalf("a short syntax keeps its description on the same line: %q", l)
		}
		if strings.Contains(l, long) && strings.Contains(l, "replay recent traffic") {
			t.Fatalf("a syntax past the column must drop its description to the next line: %q", l)
		}
	}
}

func TestDecisionColorTreatsDeniedAsADenial(t *testing.T) {
	// The guard writes DENY and the audit trail DENIED. Both are refusals and
	// both have to read as one.
	if decisionColor("DENIED") == dim("DENIED") {
		t.Fatal("DENIED rendered as neither allow nor deny")
	}
	if decisionColor("deny") != red("DENY") {
		t.Fatal("a lower-case decision must still colour as a denial")
	}
}

func TestFixed0RoundsHalvesAwayFromZero(t *testing.T) {
	// Go's %.0f rounds half to even, which printed a 0.5 KB log file as 0KB.
	if got := fixed0(0.5); got != "1" {
		t.Fatalf("want 1, got %s", got)
	}
	if got := fixed0(2.5); got != "3" {
		t.Fatalf("want 3, got %s", got)
	}
}

func TestNumPrintsWholeNumbersWithoutADecimalPoint(t *testing.T) {
	if got := num(75); got != "75" {
		t.Fatalf("a trust score of 75 must read as 75, got %q", got)
	}
	if got := num(12.5); got != "12.5" {
		t.Fatalf("want 12.5, got %q", got)
	}
	if got := num(1000000); got != "1000000" {
		t.Fatalf("no exponent notation in a table cell, got %q", got)
	}
}
