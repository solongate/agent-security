package auditscan

import (
	"fmt"
	"strings"
	"time"
)

// Transcripts are written by four different programs and a timestamp is
// whatever each of them decided to write. The TypeScript this is ported from
// hands every one of them to `new Date(...)`, which either understands it or
// produces NaN — and NaN silently makes every comparison false, which is how
// several checks avoid flagging a session whose clocks make no sense.
//
// parseMillis reproduces that: a timestamp either parses, or the caller is told
// it did not and skips the comparison rather than treating it as zero. Treating
// an unparseable timestamp as the epoch would put every such call "before" every
// user message and manufacture unsolicited-action findings out of bad data.

var timeLayouts = []struct {
	layout string
	// A layout with no zone is local time in JavaScript, except a date-only
	// ISO string, which is UTC.
	utc bool
}{
	{time.RFC3339Nano, false},
	{time.RFC3339, false},
	{"2006-01-02T15:04:05.999999999", false},
	{"2006-01-02T15:04:05", false},
	{"2006-01-02T15:04Z07:00", false},
	{"2006-01-02T15:04", false},
	{"2006-01-02 15:04:05", false},
	{"2006-01-02", true},
}

func parseTimestamp(ts string) (time.Time, bool) {
	s := strings.TrimSpace(ts)
	if s == "" {
		return time.Time{}, false
	}
	for _, l := range timeLayouts {
		loc := time.Local
		if l.utc {
			loc = time.UTC
		}
		if t, err := time.ParseInLocation(l.layout, s, loc); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// parseMillis is `new Date(ts).getTime()`, with the second return standing in
// for "not NaN".
func parseMillis(ts string) (float64, bool) {
	t, ok := parseTimestamp(ts)
	if !ok {
		return 0, false
	}
	return float64(t.UnixNano()) / 1e6, true
}

// ── Display ────────────────────────────────────────────────────────────────
//
// The npm tool formats through `toLocaleDateString`/`toLocaleTimeString`. Two
// of those calls pass 'en-GB' explicitly and are reproduced exactly here. One
// does not, and takes the machine's locale — Go has no equivalent, so it gets
// the en-GB form the rest of the tool uses rather than a third convention.

// formatClock is toLocaleTimeString('en-GB', { hour, minute, second: '2-digit' }).
// The ten spaces for a missing timestamp keep the log columns aligned.
func formatClock(ts string) string {
	if ts == "" {
		return "          "
	}
	t, ok := parseTimestamp(ts)
	if !ok {
		// The TypeScript falls back to slicing the ISO string in place.
		if len(ts) >= 19 {
			return ts[11:19]
		}
		return ts
	}
	return t.Local().Format("15:04:05")
}

// formatDayMonth is toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit' }).
func formatDayMonth(ts string) string {
	if ts == "" {
		return ""
	}
	t, ok := parseTimestamp(ts)
	if !ok {
		return ""
	}
	return t.Local().Format("02/01")
}

// formatDateNumeric stands in for a bare toLocaleDateString().
func formatDateNumeric(ts string) string {
	t, ok := parseTimestamp(ts)
	if !ok {
		return ts
	}
	return t.Local().Format("02/01/2006")
}

// formatDateLong is toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }).
func formatDateLong(ts string) string {
	t, ok := parseTimestamp(ts)
	if !ok {
		return ""
	}
	t = t.Local()
	return fmt.Sprintf("%d %s %d", t.Day(), t.Month().String(), t.Year())
}

// formatDateShortYear is toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }).
func formatDateShortYear(ts string) string {
	t, ok := parseTimestamp(ts)
	if !ok {
		return ""
	}
	t = t.Local()
	return fmt.Sprintf("%d %s %d", t.Day(), t.Format("Jan"), t.Year())
}

// formatDateShort is toLocaleDateString('en-GB', { day: 'numeric', month: 'short' }).
func formatDateShort(ts string) string {
	t, ok := parseTimestamp(ts)
	if !ok {
		return ""
	}
	t = t.Local()
	return fmt.Sprintf("%d %s", t.Day(), t.Format("Jan"))
}

// nowDateShortYear is the report's generation date.
func nowDateShortYear() string {
	t := time.Now()
	return fmt.Sprintf("%d %s %d", t.Day(), t.Format("Jan"), t.Year())
}
