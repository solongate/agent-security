package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLog(t *testing.T, lines ...string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "solongate-audit.jsonl")
	if err := os.WriteFile(f, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestReadLocalRowsSkipsWhatItHasAlreadySeen(t *testing.T) {
	f := writeLog(t,
		`{"ts":"2026-08-01T10:00:00.000Z","tool":"Bash","decision":"DENY","permission":"EXECUTE","reason":"blocked by rule"}`,
		`{"ts":"2026-08-01T10:00:05.000Z","tool":"Read","decision":"ALLOW","permission":"READ","arguments":{"file":"/etc/passwd"}}`,
	)
	rows := readLocalRows(f, 0)
	if len(rows) != 2 {
		t.Fatalf("want 2 rows, got %d", len(rows))
	}
	if rows[0].Detail != "blocked by rule" {
		t.Fatalf("a call with no arguments falls back to its reason, got %q", rows[0].Detail)
	}
	if rows[1].Detail != `{"file":"/etc/passwd"}` {
		t.Fatalf("arguments should render compactly, got %q", rows[1].Detail)
	}

	// The watermark is what stops the backlog being replayed every two seconds.
	again := readLocalRows(f, rows[len(rows)-1].At)
	if len(again) != 0 {
		t.Fatalf("already-seen rows came back: %+v", again)
	}
}

func TestReadLocalRowsSurvivesAHalfWrittenLine(t *testing.T) {
	// The guard appends while this is reading, so the last line is regularly a
	// fragment. One bad line must not stop the tail.
	f := writeLog(t,
		`{"ts":"2026-08-01T10:00:00.000Z","tool":"Bash","decision":"ALLOW"}`,
		`{"ts":"2026-08-01T10:00:01.000Z","tool":"Rea`,
	)
	rows := readLocalRows(f, 0)
	if len(rows) != 1 || rows[0].Tool != "Bash" {
		t.Fatalf("want the one complete row, got %+v", rows)
	}
}

func TestReadLocalRowsIgnoresAnEntryWithNoUsableTimestamp(t *testing.T) {
	// Without a time there is no way to order or de-duplicate the row, and
	// emitting it would replay it on every poll forever.
	f := writeLog(t, `{"tool":"Bash","decision":"ALLOW"}`)
	if rows := readLocalRows(f, 0); len(rows) != 0 {
		t.Fatalf("want no rows, got %+v", rows)
	}
}

func TestDetailPrefersArgumentsButNotEmptyOnes(t *testing.T) {
	if got := detailOf(json.RawMessage(`null`), "the reason"); got != "the reason" {
		t.Fatalf("null arguments are not a detail, got %q", got)
	}
	if got := detailOf(nil, "the reason"); got != "the reason" {
		t.Fatalf("absent arguments are not a detail, got %q", got)
	}
	if got := detailOf(json.RawMessage(`{}`), "the reason"); got != "{}" {
		t.Fatalf("an empty object IS a detail, got %q", got)
	}
}

func TestCollapseFlattensMultiLineArguments(t *testing.T) {
	// A row is one line. A command argument containing a newline used to push
	// the rest of the stream out of alignment.
	if got := collapse("a\n  b\tc"); got != "a b c" {
		t.Fatalf("got %q", got)
	}
}

func TestTailLinesDropsThePartialFirstLine(t *testing.T) {
	f := filepath.Join(t.TempDir(), "log.jsonl")
	body := strings.Repeat("x", 100) + "\nsecond\nthird\n"
	if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// Reading only the tail means the first line in the window is almost
	// certainly a fragment, so it is discarded.
	lines := tailLines(f, 20)
	for _, l := range lines {
		if strings.HasPrefix(l, "x") {
			t.Fatalf("a fragment survived: %q", l)
		}
	}
	if len(lines) == 0 || lines[len(lines)-1] != "third" {
		t.Fatalf("want the newest line last, got %v", lines)
	}
}

func TestWatchJSONIsOneObjectPerLine(t *testing.T) {
	rows := []watchRow{
		{At: 1, Tool: "Bash", Decision: "DENY", Source: "local"},
		{At: 2, Tool: "Read", Decision: "ALLOW", Source: "cloud"},
	}
	o, e := capture(t, func() {
		for _, r := range rows {
			printWatchRow(r, true)
		}
	})
	if e != "" {
		t.Fatalf("--json must leave stderr alone, got %q", e)
	}
	lines := strings.Split(strings.TrimRight(o, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want one line per row, got %d: %q", len(lines), o)
	}
	for _, l := range lines {
		var back watchRow
		if err := json.Unmarshal([]byte(l), &back); err != nil {
			t.Fatalf("line is not a JSON object: %v (%q)", err, l)
		}
	}
}

func TestWatchHumanRowGoesToStdout(t *testing.T) {
	// Unlike every other command here, watch's rows ARE the output: it is a
	// stream meant to be piped or teed, so the rows go to stdout and only the
	// "watching…" banner goes to stderr.
	o, e := capture(t, func() {
		printWatchRow(watchRow{At: 0, Tool: "Bash", Decision: "DENY", Source: "local", DLP: true}, false)
	})
	if e != "" {
		t.Fatalf("stderr got %q", e)
	}
	plain := ansi.ReplaceAllString(o, "")
	if !strings.Contains(plain, "DENY") || !strings.Contains(plain, "Bash") || !strings.Contains(plain, "DLP!") {
		t.Fatalf("row is missing content: %q", plain)
	}
	// An unreadable timestamp prints placeholders rather than a plausible wrong
	// time from 1970.
	if !strings.Contains(plain, "--:--:--") {
		t.Fatalf("want a placeholder clock, got %q", plain)
	}
}
