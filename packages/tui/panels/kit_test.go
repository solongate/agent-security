// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeTUIConfig(t *testing.T, accent string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".solongate")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"accent":"` + accent + `"}`
	if err := os.WriteFile(filepath.Join(dir, "tui-config.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAccentFromConfig(t *testing.T) {
	cases := []struct {
		name   string
		accent string
		want   string
	}{
		{"empty", "", "7"},
		{"named red", "red", "1"},
		{"named cyan", "cyan", "6"},
		{"named greyAlias", "grey", "8"},
		{"named blackBright", "blackBright", "8"},
		{"hex passthrough", "#ff00aa", "#ff00aa"},
		{"unknown name", "mauve", "7"},
		{"whitespace trimmed", "  green  ", "2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeTUIConfig(t, tc.accent)
			if got := accentFromConfig(); got != tc.want {
				t.Errorf("accentFromConfig()=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestAccentFromConfigNoFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if got := accentFromConfig(); got != "7" {
		t.Errorf("accentFromConfig() with no config file = %q, want %q", got, "7")
	}
}

func TestModeStyle(t *testing.T) {
	cases := []struct {
		mode string
		want interface{}
	}{
		{"block", stOK},
		{"active", stOK},
		{"on", stOK},
		{"detect", stWarn},
		{"idle", stWarn},
		{"", stDim},
		{"unknown", stDim},
	}
	for _, tc := range cases {
		if got := modeStyle(tc.mode); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("modeStyle(%q) did not match expected style", tc.mode)
		}
	}
}

func TestLineBufPutAccumulatesTextAndWidth(t *testing.T) {
	l := newLine(false)
	l.put("ab", stPlain).put("cd", stAccent)
	if got := l.String(); got != "abcd" {
		t.Errorf("String()=%q, want %q", got, "abcd")
	}
	if l.w != 4 {
		t.Errorf("w=%d, want 4", l.w)
	}
}

func TestLineBufSelectedStillRendersText(t *testing.T) {
	l := newLine(true)
	l.put("x", stOK)
	if got := l.String(); got != "x" {
		t.Errorf("String()=%q, want %q", got, "x")
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"empty", "", 5, ""},
		{"shorter than n", "abc", 10, "abc"},
		{"exact fit", "abcde", 5, "abcde"},
		{"longer than n", "abcdef", 5, "abcd…"},
		{"n is one", "abcdef", 1, "…"},
		{"n is zero", "abcdef", 0, "…"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := truncate(tc.s, tc.n); got != tc.want {
				t.Errorf("truncate(%q, %d)=%q, want %q", tc.s, tc.n, got, tc.want)
			}
		})
	}
}

func TestPad(t *testing.T) {
	if got := pad("ab", 5); got != "ab   " {
		t.Errorf("pad=%q", got)
	}
	if got := pad("abcdef", 3); got != "abcdef" {
		t.Errorf("pad should not shrink longer strings, got %q", got)
	}
}

func TestPadLeft(t *testing.T) {
	if got := padLeft("ab", 5); got != "   ab" {
		t.Errorf("padLeft=%q", got)
	}
	if got := padLeft("abcdef", 3); got != "abcdef" {
		t.Errorf("padLeft should not shrink longer strings, got %q", got)
	}
}

func TestFit(t *testing.T) {
	if got := fit("abcdefgh", 5); got != "abcd…" {
		t.Errorf("fit truncation=%q", got)
	}
	if got := fit("ab", 5); got != "ab   " {
		t.Errorf("fit padding=%q", got)
	}
}

func TestWindow(t *testing.T) {
	lines := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
	cases := []struct {
		name       string
		cursorLine int
		budget     int
		wantStart  int
		wantEnd    int
		wantAbove  int
		wantBelow  int
	}{
		{"budget clamps to 1", 0, 0, 0, 1, 0, 9},
		{"fits entirely", 3, 20, 0, 10, 0, 0},
		{"cursor near start", 0, 4, 0, 4, 0, 6},
		{"cursor near end", 9, 4, 6, 10, 6, 0},
		{"cursor in middle", 5, 4, 3, 7, 3, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			win, above, below := window(lines, tc.cursorLine, tc.budget)
			wantWin := lines[tc.wantStart:tc.wantEnd]
			if !reflect.DeepEqual(win, wantWin) {
				t.Errorf("win=%v, want %v", win, wantWin)
			}
			if above != tc.wantAbove || below != tc.wantBelow {
				t.Errorf("above=%d below=%d, want above=%d below=%d", above, below, tc.wantAbove, tc.wantBelow)
			}
		})
	}
}

func TestScrollTag(t *testing.T) {
	cases := []struct {
		above, below int
		want         string
	}{
		{0, 0, ""},
		{3, 0, " · ▲3"},
		{0, 5, " · ▼5"},
		{2, 7, " · ▲2 · ▼7"},
	}
	for _, tc := range cases {
		if got := scrollTag(tc.above, tc.below); got != tc.want {
			t.Errorf("scrollTag(%d,%d)=%q, want %q", tc.above, tc.below, got, tc.want)
		}
	}
}

func TestClip(t *testing.T) {
	if got := clip("hi", 10, 2); got != "hi" {
		t.Errorf("clip within bounds=%q, want %q", got, "hi")
	}
	if got := clip("hello", 3, 1); got != "hel" {
		t.Errorf("clip truncates width, got %q", got)
	}
	if got := clip("a\nb\nc", 1, 2); got != "a\nb" {
		t.Errorf("clip truncates height, got %q", got)
	}
	// cols/rows below 1 are clamped to 1 rather than passed through unmodified.
	if got := clip("abc", 0, 0); got != "a" {
		t.Errorf("clip with non-positive cols/rows should clamp to 1x1, got %q", got)
	}
}

func TestJoinLines(t *testing.T) {
	if got := joinLines([]string{"a", "b", "c"}); got != "a\nb\nc" {
		t.Errorf("joinLines=%q", got)
	}
	if got := joinLines(nil); got != "" {
		t.Errorf("joinLines(nil)=%q, want empty", got)
	}
}

func TestDataView(t *testing.T) {
	err := errors.New("boom")
	if got := dataView(false, err, false, "", "body"); got != "✗ boom" {
		t.Errorf("error branch=%q", got)
	}
	if got := dataView(true, nil, false, "", "body"); got != "⟳ loading…" {
		t.Errorf("loading branch=%q", got)
	}
	if got := dataView(false, nil, true, "", "body"); got != "No data." {
		t.Errorf("empty default text branch=%q", got)
	}
	if got := dataView(false, nil, true, "nothing here", "body"); got != "nothing here" {
		t.Errorf("empty custom text branch=%q", got)
	}
	if got := dataView(false, nil, false, "", "body"); got != "body" {
		t.Errorf("body passthrough branch=%q", got)
	}
}

func TestStatusLine(t *testing.T) {
	if got := statusLine("✗ failed"); got != "✗ failed" {
		t.Errorf("bad status=%q", got)
	}
	if got := statusLine("✓ ok"); got != "✓ ok" {
		t.Errorf("ok status=%q", got)
	}
}

func TestOrDash(t *testing.T) {
	if got := orDash(""); got != "-" {
		t.Errorf("orDash empty=%q, want -", got)
	}
	if got := orDash("x"); got != "x" {
		t.Errorf("orDash non-empty=%q, want x", got)
	}
}

func TestItoa(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{9, "9"},
		{10, "10"},
		{42, "42"},
		{-1, "-1"},
		{-42, "-42"},
		{1234567890, "1234567890"},
	}
	for _, tc := range cases {
		if got := itoa(tc.n); got != tc.want {
			t.Errorf("itoa(%d)=%q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestErrText(t *testing.T) {
	if got := errText(nil); got != "" {
		t.Errorf("errText(nil)=%q, want empty", got)
	}
	if got := errText(errors.New("oops")); got != "oops" {
		t.Errorf("errText=%q, want oops", got)
	}
}

func TestNextTokenIsMonotonic(t *testing.T) {
	a := nextToken()
	b := nextToken()
	if b != a+1 {
		t.Errorf("nextToken() not monotonic: a=%d b=%d", a, b)
	}
}