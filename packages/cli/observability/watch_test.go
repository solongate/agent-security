// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !windows

package observability

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
)

func TestPrintWatchRowJSON(t *testing.T) {
	row := watchRow{
		At: 1700000000000, Tool: "Bash", Decision: "ALLOW", Permission: "EXEC",
		Detail: "ok", Agent: "agent-a", Source: "local", DLP: false,
	}
	out := captureFD(t, 1, func() { printWatchRow(row, true) })

	var got watchRow
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, out)
	}
	if got != row {
		t.Errorf("round-tripped row = %+v, want %+v", got, row)
	}
}

func TestPrintWatchRowText(t *testing.T) {
	cases := []struct {
		name     string
		row      watchRow
		want     []string
		dontWant []string
	}{
		{
			name: "allow, local source",
			row: watchRow{At: 1700000000000, Tool: "Bash", Decision: "ALLOW", Permission: "EXEC",
				Detail: "ran ls", Agent: "agent-a", Source: "local"},
			want:     []string{"ALLOW", "Bash", "LOC", "agent-a", "ran ls"},
			dontWant: []string{"DLP!", "CLD"},
		},
		{
			name: "deny, cloud source, no agent",
			row: watchRow{At: 1700000000000, Tool: "WebFetch", Decision: "DENY", Permission: "NET",
				Detail: "blocked", Source: "cloud"},
			want:     []string{"DENY", "WebFetch", "CLD", "blocked"},
			dontWant: []string{"DLP!", "LOC"},
		},
		{
			name: "dlp flagged",
			row: watchRow{At: 1700000000000, Tool: "Write", Decision: "DENY", Permission: "WRITE",
				Detail: "redacted", Agent: "agent-b", Source: "local", DLP: true},
			want: []string{"DLP!", "DENY", "Write"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := captureFD(t, 1, func() { printWatchRow(c.row, false) })
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("output missing %q:\n%q", w, out)
				}
			}
			for _, nw := range c.dontWant {
				if strings.Contains(out, nw) {
					t.Errorf("output should not contain %q:\n%q", nw, out)
				}
			}
		})
	}
}

func TestReadLocalRows(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "log.jsonl")
	content := strings.Join([]string{
		`{"ts":"2026-01-01T00:00:00Z","tool":"Bash","decision":"ALLOW","permission":"EXEC","agent_name":"agent-a"}`,
		`{"ts":"2026-01-01T00:01:00Z","tool":"Write","decision":"DENY","reason":"nope"}`,
		`not json`,
		`{"ts":"2025-01-01T00:00:00Z","tool":"Old","decision":"ALLOW"}`,
	}, "\n")
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	after, ok := parseTimestamp("2025-06-01T00:00:00Z")
	if !ok {
		t.Fatal("test setup: could not parse the `after` boundary")
	}

	rows := readLocalRows(file, after)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (the malformed line skipped, the too-old line filtered)", len(rows))
	}
	if rows[0].Tool != "Bash" || rows[0].Agent != "agent-a" || rows[0].Decision != "ALLOW" {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if rows[1].Tool != "Write" || rows[1].Detail != "nope" || rows[1].Decision != "DENY" {
		t.Errorf("row 1 = %+v", rows[1])
	}
}

func TestTailLines(t *testing.T) {
	t.Run("nonexistent file", func(t *testing.T) {
		if got := tailLines(filepath.Join(t.TempDir(), "missing.jsonl"), 1024); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})

	t.Run("small file read whole", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "log.jsonl")
		if err := os.WriteFile(file, []byte("line1\nline2\nline3\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got := tailLines(file, 1024)
		want := []string{"line1", "line2", "line3"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("line %d = %q, want %q", i, got[i], want[i])
			}
		}
	})

	// Issue #222: "line1\nline2\nline3\n" is 18 bytes, so a window of 6
	// opens right after line2's newline, a window of 7 opens on that newline,
	// and a window of 8 opens inside line2. Only the last one has a fragment.
	t.Run("keeps a complete first line when the window opens on a line boundary", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "log.jsonl")
		if err := os.WriteFile(file, []byte("line1\nline2\nline3\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, maxBytes := range []int64{6, 7, 8} {
			got := tailLines(file, maxBytes)
			if len(got) != 1 || got[0] != "line3" {
				t.Errorf("tailLines(file, %d) = %q, want [line3]", maxBytes, got)
			}
		}
		if got := tailLines(file, 12); len(got) != 2 || got[0] != "line2" || got[1] != "line3" {
			t.Errorf("tailLines(file, 12) = %q, want [line2 line3]", got)
		}
	})

	t.Run("large file returns only the tail and drops the leading partial line", func(t *testing.T) {
		dir := t.TempDir()
		file := filepath.Join(dir, "log.jsonl")
		var lines []string
		for i := 0; i < 2000; i++ {
			lines = append(lines, "line-"+strconv.Itoa(i))
		}
		content := strings.Join(lines, "\n") + "\n"
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		const maxBytes = 2000
		got := tailLines(file, maxBytes)
		if len(got) == 0 {
			t.Fatal("got no lines back from a large file")
		}

		valid := make(map[string]bool, len(lines))
		for _, l := range lines {
			valid[l] = true
		}
		for _, l := range got {
			if !valid[l] {
				t.Errorf("tailLines returned a corrupted/partial line: %q (this is the bug: Seek must land on an "+
					"exact byte offset and the first, possibly-partial, line after it must be dropped)", l)
			}
		}
		if got[len(got)-1] != lines[len(lines)-1] {
			t.Errorf("last line = %q, want %q (the file's actual last line)", got[len(got)-1], lines[len(lines)-1])
		}
		if got[0] == lines[0] {
			t.Error("tailLines did not truncate at all: first returned line is the file's first line")
		}
	})
}

func TestDetailOf(t *testing.T) {
	cases := []struct {
		name      string
		arguments json.RawMessage
		reason    string
		want      string
	}{
		{"truthy arguments are compacted", json.RawMessage(`{"command":  "ls",  "x": 1}`), "ignored", `{"command":"ls","x":1}`},
		{"empty arguments fall back to reason", json.RawMessage(``), "no match", "no match"},
		{"null arguments fall back to reason", json.RawMessage(`null`), "no match", "no match"},
		{"false arguments fall back to reason", json.RawMessage(`false`), "no match", "no match"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := detailOf(c.arguments, c.reason); got != c.want {
				t.Errorf("detailOf(...) = %q, want %q", got, c.want)
			}
		})
	}
}

func TestCollapse(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a  b   c", "a b c"},
		{"a\tb\nc", "a b c"},
		{"single", "single"},
		{"", ""},
	}
	for _, c := range cases {
		if got := collapse(c.in); got != c.want {
			t.Errorf("collapse(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestJSONTruthy(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
		want bool
	}{
		{"empty", json.RawMessage(``), false},
		{"null", json.RawMessage(`null`), false},
		{"false", json.RawMessage(`false`), false},
		{"zero", json.RawMessage(`0`), false},
		{"empty string literal", json.RawMessage(`""`), false},
		{"truthy string", json.RawMessage(`"x"`), true},
		{"truthy number", json.RawMessage(`1`), true},
		{"truthy bool", json.RawMessage(`true`), true},
		{"truthy object", json.RawMessage(`{"a":1}`), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := jsonTruthy(c.raw); got != c.want {
				t.Errorf("jsonTruthy(%s) = %v, want %v", c.raw, got, c.want)
			}
		})
	}
}

func TestJSONString(t *testing.T) {
	cases := []struct {
		name string
		raw  json.RawMessage
		want string
	}{
		{"empty", json.RawMessage(``), ""},
		{"null", json.RawMessage(`null`), ""},
		{"quoted string literal", json.RawMessage(`"hello"`), "hello"},
		{"bare unquoted token falls back to raw", json.RawMessage(`true`), "true"},
		{"bare number falls back to raw", json.RawMessage(`42`), "42"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := jsonString(c.raw); got != c.want {
				t.Errorf("jsonString(%s) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

func TestParseTimestamp(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want time.Time
		ok   bool
	}{
		{"RFC3339Nano, fractional seconds and zone", "2026-01-01T12:00:00.5Z",
			time.Date(2026, 1, 1, 12, 0, 0, 500000000, time.UTC), true},
		{"RFC3339, no fraction", "2026-01-01T12:00:00Z",
			time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), true},
		{"custom T-separated layout, no zone", "2026-01-01T12:00:00",
			time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), true},
		{"custom space-separated layout with zone", "2026-01-01 12:00:00.000000000Z",
			time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), true},
		{"plain space-separated datetime layout", "2026-01-01 12:00:00",
			time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC), true},
		{"unparseable string", "not a date", time.Time{}, false},
		{"empty string", "", time.Time{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := parseTimestamp(c.in)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			if want := c.want.UnixMilli(); got != want {
				t.Errorf("parseTimestamp(%q) = %d, want %d (%v)", c.in, got, want, c.want)
			}
		})
	}
}

func TestWatchClock(t *testing.T) {
	if got := watchClock(0); got != "--:--:--" {
		t.Errorf("watchClock(0) = %q, want --:--:--", got)
	}
	ms := time.Date(2026, 1, 1, 13, 45, 30, 0, time.UTC).UnixMilli()
	want := time.UnixMilli(ms).Format("15:04:05")
	if got := watchClock(ms); got != want {
		t.Errorf("watchClock(%d) = %q, want %q", ms, got, want)
	}
}

func TestFirstN(t *testing.T) {
	cases := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"longer than n", "hello world", 5, "hello"},
		{"shorter than n", "hi", 10, "hi"},
		{"multi-byte runes are sliced by rune, not byte", "héllo wörld", 3, "hél"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := firstN(c.s, c.n); got != c.want {
				t.Errorf("firstN(%q, %d) = %q, want %q", c.s, c.n, got, c.want)
			}
		})
	}
}

// TestRunWatchReturnsOnContextCancellation only checks that the polling loop
// actually exits (130, nil) once ctx is done. RunWatch is otherwise an
// infinite loop driven by tickers and is not exercised end-to-end beyond
// this. The select below gives the test itself a hard 2s deadline so a
// regression that makes RunWatch ignore ctx.Done() fails fast instead of
// hanging the suite.
func TestRunWatchReturnsOnContextCancellation(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		code, err := RunWatch(ctx, c, cliutil.Parse([]string{"--local-only", "--json"}))
		done <- result{code, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("RunWatch returned error: %v", r.err)
		}
		if r.code != 130 {
			t.Errorf("code = %d, want 130", r.code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunWatch did not return after context cancellation; it may be hanging")
	}
}