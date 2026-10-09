// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/core/api"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/core/term"
)

// `solongate watch` tails the guard's tool-call stream like `tail -f`, without
// starting the full TUI. It merges two sources that see different halves of the
// truth: the on-disk local log, which is written the moment a call is decided
// and exists even offline, and the cloud audit feed, which has the calls made
// from every other device. Neither alone is the stream.

type watchRow struct {
	At         int64  `json:"at"`
	Tool       string `json:"tool"`
	Decision   string `json:"decision"`
	Permission string `json:"permission"`
	Detail     string `json:"detail"`
	Agent      string `json:"agent"`
	Source     string `json:"source"`
	DLP        bool   `json:"dlp"`
}

const (
	// How much of the local log to re-read each pass. Large enough to cover a
	// burst between polls, small enough that the tail of a log that has grown to
	// hundreds of megabytes is still cheap.
	watchTailBytes = 131072
	localPollEvery = 2 * time.Second
	cloudPollEvery = 4 * time.Second
	// Bound on the ids remembered for de-duplication. Only the newest page can
	// ever be seen twice, so forgetting older ids cannot resurrect them, and an
	// unbounded set is a slow leak in a command designed to run all day.
	seenLimit = 4096
)

var whitespaceRun = regexp.MustCompile(`\s+`)

func runWatch(ctx context.Context, c *api.Client, p parsedArgs) (int, error) {
	jsonOut := p.flagBool("json")
	decisionFilter := strings.ToUpper(p.flagStr("filter"))
	toolFilter := strings.ToLower(p.flagStr("tool"))
	localOnly := p.flagBool("local-only")
	cloudOnly := p.flagBool("cloud-only")

	keep := func(r watchRow) bool {
		if decisionFilter != "" {
			d := strings.ToUpper(r.Decision)
			// DENY and DENIED are the same event with two spellings: the guard
			// writes one and the audit trail the other. A filter for one that
			// dropped the other would show half the denials.
			if d != decisionFilter && !(decisionFilter == "DENY" && d == "DENIED") {
				return false
			}
		}
		if toolFilter != "" && !strings.Contains(strings.ToLower(r.Tool), toolFilter) {
			return false
		}
		return true
	}

	emit := func(rows []watchRow) {
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].At < rows[j].At })
		for _, r := range rows {
			if keep(r) {
				printWatchRow(r, jsonOut)
			}
		}
	}

	var lastLocalTS int64
	seen := map[string]bool{}
	first := true

	pollLocal := func() {
		if cloudOnly {
			return
		}
		file := config.LocalLogFile()
		rows := readLocalRows(file, lastLocalTS)
		if len(rows) > 0 {
			// The watermark is the last row in FILE order, not in time order:
			// the log is append-only, so its own order is the record of what has
			// been read, and sorting first would move the mark backwards on a
			// clock skew.
			lastLocalTS = rows[len(rows)-1].At
		}
		if !first {
			emit(rows)
		}
	}

	pollCloud := func() {
		if localOnly {
			return
		}
		res, err := c.Audit.List(ctx, api.AuditQuery{Limit: 50})
		if err != nil {
			// Transient by assumption. A watch that exited on the first blip
			// would be useless on a laptop that sleeps.
			return
		}
		if len(seen) > seenLimit {
			seen = map[string]bool{}
		}
		var rows []watchRow
		for _, e := range res.Entries {
			if seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			at, _ := parseTimestamp(e.CreatedAt)
			rows = append(rows, watchRow{
				At:         at,
				Tool:       e.ToolName,
				Decision:   e.Decision,
				Permission: e.Permission,
				Detail:     collapse(detailOf(e.ArgumentsSummary, deref(e.Reason, ""))),
				Agent:      deref(e.AgentName, ""),
				Source:     "cloud",
				DLP:        len(e.DLPMatches) > 0,
			})
		}
		if !first {
			emit(rows)
		}
	}

	if !jsonOut {
		errln("  " + dim("watching guard stream - Ctrl+C to stop"))
	}
	// Prime both sources before emitting anything: the backlog already on disk
	// and in the cloud is history, and printing it on startup would bury the
	// live calls this command exists to show.
	pollLocal()
	pollCloud()
	first = false

	localTick := time.NewTicker(localPollEvery)
	defer localTick.Stop()
	cloudTick := time.NewTicker(cloudPollEvery)
	defer cloudTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return 130, nil
		case <-localTick.C:
			pollLocal()
		case <-cloudTick.C:
			pollCloud()
		}
	}
}

func printWatchRow(r watchRow, jsonOut bool) {
	if jsonOut {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if enc.Encode(r) != nil {
			return
		}
		// One object per line, so the stream can be piped straight into jq -c or
		// a log shipper while it is still running.
		fmt.Fprint(stdout, buf.String())
		return
	}
	decision := term.Red
	if r.Decision == "ALLOW" {
		decision = term.Green
	}
	source := term.Blue4 + "CLD"
	if r.Source == "local" {
		source = term.Green + "LOC"
	}
	dlp := ""
	if r.DLP {
		dlp = term.Red + "DLP! " + term.Reset
	}
	agent := r.Agent
	if agent == "" {
		agent = "-"
	}
	out(term.Dim + "[" + watchClock(r.At) + "]" + term.Reset + " " +
		source + term.Reset + " " +
		decision + padRight(r.Decision, 6) + term.Reset + " " +
		term.Cyan + padRight(truncate(r.Tool, 12), 13) + term.Reset +
		term.Dim + padRight(firstN(r.Permission, 4), 5) + term.Reset +
		dlp + term.Dim + padRight(truncate(agent, 12), 13) + r.Detail + term.Reset)
}

// readLocalRows returns the entries newer than the watermark, in file order.
func readLocalRows(file string, after int64) []watchRow {
	var rows []watchRow
	for _, line := range tailLines(file, watchTailBytes) {
		var j map[string]json.RawMessage
		if json.Unmarshal([]byte(line), &j) != nil {
			continue // a line the guard was still writing when this read it
		}
		at, ok := parseTimestamp(jsonString(j["ts"]))
		if !ok || at <= after {
			continue
		}
		tool := jsonString(j["tool"])
		if tool == "" {
			tool = "?"
		}
		decision := jsonString(j["decision"])
		if decision == "" {
			decision = "ALLOW"
		}
		rows = append(rows, watchRow{
			At:         at,
			Tool:       tool,
			Decision:   decision,
			Permission: jsonString(j["permission"]),
			Detail:     collapse(detailOf(j["arguments"], jsonString(j["reason"]))),
			Agent:      jsonString(j["agent_name"]),
			Source:     "local",
			DLP:        jsonTruthy(j["dlp"]),
		})
	}
	return rows
}

// tailLines reads the last maxBytes of a file and returns its complete lines.
//
// The first line is dropped whenever the read started mid-file, because it is
// almost certainly a fragment. Reading the whole file instead would make each
// poll cost more as the log grows, on a command that polls forever.
func tailLines(file string, maxBytes int64) []string {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	start := max(int64(0), st.Size()-maxBytes)
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	if start > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	return lines
}

// detailOf prefers the call's arguments and falls back to the reason, matching
// the TypeScript's truthiness test: an arguments field that is null, absent or
// empty is not a detail, and the reason is what is left to say.
func detailOf(arguments json.RawMessage, reason string) string {
	if jsonTruthy(arguments) {
		var buf bytes.Buffer
		if json.Compact(&buf, arguments) == nil {
			return buf.String()
		}
		return string(arguments)
	}
	return reason
}

func collapse(s string) string { return whitespaceRun.ReplaceAllString(s, " ") }

// jsonTruthy applies JavaScript's idea of truthy to a raw JSON value, because
// that is the test the rows are built with. null, false, 0 and "" are all
// "nothing here"; an empty object is not.
func jsonTruthy(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	switch s {
	case "", "null", "false", "0", `""`:
		return false
	}
	return true
}

// jsonString reads a raw value as a string, tolerating the field being a number
// or absent — the local log is written by several hook versions and a decision
// or timestamp has been both at different times.
func jsonString(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return ""
	}
	var out string
	if json.Unmarshal(raw, &out) == nil {
		return out
	}
	return s
}

// The layouts an audit timestamp arrives in. RFC3339 is what the API sends;
// the space-separated form is what a SQLite datetime() default produces, and it
// has reached the log through older hooks.
var timeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05",
}

func parseTimestamp(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UnixMilli(), true
		}
	}
	return 0, false
}

// watchClock renders the local wall-clock time of a row. A row whose timestamp
// could not be read prints placeholders rather than 1970: the column is there to
// tell calls apart, and a plausible wrong time is worse than an obvious gap.
func watchClock(ms int64) string {
	if ms == 0 {
		return "--:--:--"
	}
	return time.UnixMilli(ms).Format("15:04:05")
}

func firstN(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
