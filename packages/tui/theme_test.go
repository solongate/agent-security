// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func TestColorOf(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		fallback string
		want     lipgloss.Color
	}{
		{"hex passthrough", "#abcdef", "7", lipgloss.Color("#abcdef")},
		{"known ansi name", "red", "7", lipgloss.Color("1")},
		{"trims whitespace", "  blue  ", "7", lipgloss.Color("4")},
		{"unknown name uses fallback", "not-a-color", "9", lipgloss.Color("9")},
		{"empty uses fallback", "", "3", lipgloss.Color("3")},
		{"ansi names are case-sensitive", "RED", "9", lipgloss.Color("9")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := colorOf(tc.in, tc.fallback); got != tc.want {
				t.Errorf("colorOf(%q, %q) = %v, want %v", tc.in, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestNoColor(t *testing.T) {
	cases := []struct {
		name     string
		noColor  string
		clicolor string
		want     bool
	}{
		{"neither set", "", "", false},
		{"NO_COLOR set", "1", "", true},
		{"CLICOLOR=0", "", "0", true},
		{"CLICOLOR=1 is not a no-color signal", "", "1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", tc.noColor)
			t.Setenv("CLICOLOR", tc.clicolor)
			if got := noColor(); got != tc.want {
				t.Errorf("noColor() = %v, want %v", got, tc.want)
			}
		})
	}
}

func withThemeSnapshot(t *testing.T) {
	t.Helper()
	orig := Theme
	t.Cleanup(func() { Theme = orig })
}

func TestSetAccentNoopsUnderNoColor(t *testing.T) {
	withThemeSnapshot(t)
	t.Setenv("NO_COLOR", "1")
	t.Setenv("CLICOLOR", "")
	before := Theme
	setAccent("red")
	if Theme != before {
		t.Error("setAccent() changed the theme under NO_COLOR, want it left untouched")
	}
}

func TestSetAccentAppliesColor(t *testing.T) {
	withThemeSnapshot(t)
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR", "")
	setAccent("red")
	want := lipgloss.Color("1")
	if Theme.Accent != want || Theme.AccentBright != want {
		t.Errorf("setAccent(\"red\") Accent/AccentBright = %v/%v, want %v", Theme.Accent, Theme.AccentBright, want)
	}
}

func TestFlattenNoopsWithColor(t *testing.T) {
	withThemeSnapshot(t)
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR", "")
	before := Theme
	flatten()
	if Theme != before {
		t.Error("flatten() changed the theme while color is enabled, want it left untouched")
	}
}

func TestFlattenClearsThemeUnderNoColor(t *testing.T) {
	withThemeSnapshot(t)
	t.Setenv("NO_COLOR", "1")
	t.Setenv("CLICOLOR", "")
	flatten()
	var none lipgloss.Color
	if Theme.Accent != none || Theme.OK != none || Theme.Warn != none || Theme.Bad != none || Theme.Dim != none || Theme.White != none {
		t.Errorf("flatten() under NO_COLOR left colors set: %+v", Theme)
	}
}

func TestDecisionColor(t *testing.T) {
	cases := []struct {
		decision string
		want     lipgloss.TerminalColor
	}{
		{"ALLOW", Theme.OK},
		{"allow", Theme.OK},
		{" allow ", Theme.OK},
		{"DENY", Theme.Bad},
		{"DENIED", Theme.Bad},
		{"denied", Theme.Bad},
		{"PENDING", Theme.Dim},
		{"", Theme.Dim},
	}
	for _, tc := range cases {
		if got := DecisionColor(tc.decision); got != tc.want {
			t.Errorf("DecisionColor(%q) = %v, want %v", tc.decision, got, tc.want)
		}
	}
}

func TestModeColor(t *testing.T) {
	cases := []struct {
		mode string
		want lipgloss.TerminalColor
	}{
		{"block", Theme.OK},
		{"active", Theme.OK},
		{"on", Theme.OK},
		{"redact", Theme.Accent},
		{"detect", Theme.Warn},
		{"idle", Theme.Warn},
		{"off", Theme.Dim},
		{"Block", Theme.Dim}, // exact-match only, no case folding
	}
	for _, tc := range cases {
		if got := ModeColor(tc.mode); got != tc.want {
			t.Errorf("ModeColor(%q) = %v, want %v", tc.mode, got, tc.want)
		}
	}
}

func TestOnBGSetsBackgroundWithoutMutatingInput(t *testing.T) {
	in := []Seg{{Text: "a"}, {Text: "b", Fg: Theme.Accent}}
	bg := lipgloss.Color("#112233")
	out := onBG(bg, in)
	for i, s := range out {
		if s.Bg != bg {
			t.Errorf("onBG() out[%d].Bg = %v, want %v", i, s.Bg, bg)
		}
	}
	if in[0].Bg != nil || in[1].Bg != nil {
		t.Error("onBG() mutated its input slice, want the originals left alone")
	}
}

func TestRenderRowConcatenatesSegments(t *testing.T) {
	out := RenderRow(0, Sg("hello ", Theme.Dim), Sg("world", Theme.Accent))
	if !strings.Contains(out, "hello ") || !strings.Contains(out, "world") {
		t.Errorf("RenderRow() = %q, want both segments present", out)
	}
}

func TestRenderRowSkipsEmptySegments(t *testing.T) {
	out := RenderRow(80, Sg("", Theme.Dim), Sg("visible", Theme.Dim))
	if !strings.Contains(out, "visible") {
		t.Errorf("RenderRow() = %q, want the non-empty segment rendered", out)
	}
}

func TestRenderRowTruncatesToWidth(t *testing.T) {
	out := RenderRow(5, Sg("Hello World", Theme.Dim))
	if w := lipgloss.Width(out); w > 5 {
		t.Errorf("RenderRow() width = %d, want <= 5", w)
	}
	if !strings.Contains(out, "Hello") {
		t.Errorf("RenderRow() = %q, want the first 5 characters preserved", out)
	}
	if strings.Contains(out, "World") {
		t.Errorf("RenderRow() = %q, want text beyond the width cut off", out)
	}
}

func TestRenderRowStopsOnceWidthIsExhausted(t *testing.T) {
	out := RenderRow(5, Sg("Hello", Theme.Dim), Sg(" World", Theme.Accent))
	if strings.Contains(out, "World") {
		t.Errorf("RenderRow() = %q, want the second segment dropped once width is used up", out)
	}
}

func TestCutWidth(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"Hello World", 5, "Hello"},
		{"Hello", 0, ""},
		{"Hello", -1, ""},
		{"Hi", 10, "Hi"},
	}
	for _, tc := range cases {
		if got := cutWidth(tc.in, tc.n); got != tc.want {
			t.Errorf("cutWidth(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		in   string
		n    int
		want string
	}{
		{"", 5, ""},
		{"hello", 10, "hello"},
		{"hello world", 5, "hell…"},
		{"hello", 1, "…"},
		{"hello", 0, "…"},
	}
	for _, tc := range cases {
		if got := Truncate(tc.in, tc.n); got != tc.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

func TestPadEnd(t *testing.T) {
	if got := PadEnd("ab", 5); got != "ab   " {
		t.Errorf("PadEnd(\"ab\", 5) = %q, want \"ab   \"", got)
	}
	if got := PadEnd("abcdef", 3); got != "abcdef" {
		t.Errorf("PadEnd(\"abcdef\", 3) = %q, want it left unchanged when already wider", got)
	}
}

func TestPadStart(t *testing.T) {
	if got := padStart("ab", 5); got != "   ab" {
		t.Errorf("padStart(\"ab\", 5) = %q, want \"   ab\"", got)
	}
	if got := padStart("abcdef", 3); got != "abcdef" {
		t.Errorf("padStart(\"abcdef\", 3) = %q, want it left unchanged when already wider", got)
	}
}

func TestFit(t *testing.T) {
	if got := fit("hello world", 5); got != "hell…" {
		t.Errorf("fit(\"hello world\", 5) = %q, want truncated to \"hell…\"", got)
	}
	if got := fit("ab", 5); got != "ab   " {
		t.Errorf("fit(\"ab\", 5) = %q, want padded to \"ab   \"", got)
	}
}

func TestWrapLines(t *testing.T) {
	// width=9 avoids the width<8 floor (covered separately below) so this
	// exercises ordinary mid-range wrapping.
	out := WrapLines("hello\nworldwideabc", 9)
	want := []string{"hello", "worldwide", "abc"}
	if !slicesEqual(out, want) {
		t.Errorf("WrapLines() = %v, want %v", out, want)
	}
}

func TestWrapLinesClampsMinimumWidth(t *testing.T) {
	out := WrapLines("abcdefghij", 2)
	want := []string{"abcdefgh", "ij"}
	if !slicesEqual(out, want) {
		t.Errorf("WrapLines() with width below the floor = %v, want %v (floored to 8)", out, want)
	}
}

func TestPrettyJson(t *testing.T) {
	got := PrettyJson(`{"a":1}`)
	want := "{\n  \"a\": 1\n}"
	if got != want {
		t.Errorf("PrettyJson(valid) = %q, want %q", got, want)
	}
	if got := PrettyJson("not json"); got != "not json" {
		t.Errorf("PrettyJson(invalid) = %q, want it returned unchanged", got)
	}
	if got := PrettyJson("   "); got != "   " {
		t.Errorf("PrettyJson(blank) = %q, want it returned unchanged", got)
	}
}

func TestAgoAt(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	cases := []struct {
		name string
		ago  time.Duration
		want string
	}{
		{"zero timestamp", 0, ""},
		{"seconds", 30 * time.Second, "30s"},
		{"minutes", 90 * time.Second, "1m"},
		{"hours", 2 * time.Hour, "2h"},
		{"days", 50 * time.Hour, "2d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var atMs int64
			if tc.name != "zero timestamp" {
				atMs = now.Add(-tc.ago).UnixMilli()
			}
			if got := AgoAt(atMs, now); got != tc.want {
				t.Errorf("AgoAt() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAgoAtClampsFutureTimestamps(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	future := now.Add(5 * time.Second).UnixMilli()
	if got := AgoAt(future, now); got != "0s" {
		t.Errorf("AgoAt() with a future timestamp = %q, want \"0s\"", got)
	}
}

func TestParseMillisInvalidAndEmpty(t *testing.T) {
	if _, ok := ParseMillis(""); ok {
		t.Error("ParseMillis(\"\") ok = true, want false")
	}
	if _, ok := ParseMillis("   "); ok {
		t.Error("ParseMillis(whitespace) ok = true, want false")
	}
	if _, ok := ParseMillis("not a timestamp"); ok {
		t.Error("ParseMillis(garbage) ok = true, want false")
	}
}

func TestParseMillisRFC3339(t *testing.T) {
	ms, ok := ParseMillis("2024-01-02T03:04:05Z")
	if !ok {
		t.Fatal("ParseMillis(RFC3339) ok = false, want true")
	}
	want := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC).UnixMilli()
	if ms != want {
		t.Errorf("ParseMillis(RFC3339) = %d, want %d", ms, want)
	}
}

func TestParseMillisRFC3339Nano(t *testing.T) {
	ms, ok := ParseMillis("2024-01-02T03:04:05.123456789Z")
	if !ok {
		t.Fatal("ParseMillis(RFC3339Nano) ok = false, want true")
	}
	want := time.Date(2024, 1, 2, 3, 4, 5, 123000000, time.UTC).UnixMilli()
	if ms != want {
		t.Errorf("ParseMillis(RFC3339Nano) = %d, want %d", ms, want)
	}
}

func TestParseMillisNoZoneTLayoutsDefaultToUTC(t *testing.T) {
	// ParseMillis tries these "T"-separated layouts with time.Parse, which
	// assumes UTC when the layout carries no zone — pinning that so a
	// well-meaning switch to ParseInLocation doesn't silently shift times.
	cases := []struct {
		in     string
		layout string
	}{
		{"2024-01-02T03:04:05.123", "2006-01-02T15:04:05.999999999"},
		{"2024-01-02T03:04:05", "2006-01-02T15:04:05"},
	}
	for _, tc := range cases {
		want, err := time.Parse(tc.layout, tc.in)
		if err != nil {
			t.Fatalf("test setup: time.Parse(%q) failed: %v", tc.in, err)
		}
		ms, ok := ParseMillis(tc.in)
		if !ok {
			t.Errorf("ParseMillis(%q) ok = false, want true", tc.in)
			continue
		}
		if ms != want.UnixMilli() {
			t.Errorf("ParseMillis(%q) = %d, want %d", tc.in, ms, want.UnixMilli())
		}
	}
}

func TestParseMillisSpaceLayoutsUseLocalZone(t *testing.T) {
	cases := []struct {
		in     string
		layout string
	}{
		{"2024-01-02 03:04:05.123", "2006-01-02 15:04:05.999999999"},
		{"2024-01-02 03:04:05", "2006-01-02 15:04:05"},
		{"2024-01-02", "2006-01-02"},
	}
	for _, tc := range cases {
		want, err := time.ParseInLocation(tc.layout, tc.in, time.Local)
		if err != nil {
			t.Fatalf("test setup: time.ParseInLocation(%q) failed: %v", tc.in, err)
		}
		ms, ok := ParseMillis(tc.in)
		if !ok {
			t.Errorf("ParseMillis(%q) ok = false, want true", tc.in)
			continue
		}
		if ms != want.UnixMilli() {
			t.Errorf("ParseMillis(%q) = %d, want %d", tc.in, ms, want.UnixMilli())
		}
	}
}

func TestParseMillisNumericEpoch(t *testing.T) {
	ms, ok := ParseMillis("1700000000000")
	if !ok || ms != 1700000000000 {
		t.Errorf("ParseMillis(numeric) = %d,%v, want 1700000000000,true", ms, ok)
	}
}

func TestFmtUp(t *testing.T) {
	cases := []struct {
		ms   int64
		want string
	}{
		{0, "00:00:00"},
		{-500, "00:00:00"},
		{1000, "00:00:01"},
		{61_000, "00:01:01"},
		{3_661_000, "01:01:01"},
		{90_000_000, "25:00:00"},
	}
	for _, tc := range cases {
		if got := FmtUp(tc.ms); got != tc.want {
			t.Errorf("FmtUp(%d) = %q, want %q", tc.ms, got, tc.want)
		}
	}
}