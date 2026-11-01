// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package observability

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

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/core/term"
)

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
	watchTailBytes = 131072
	localPollEvery = 2 * time.Second
	cloudPollEvery = 4 * time.Second

	seenLimit = 4096
)

var whitespaceRun = regexp.MustCompile(`\s+`)

func RunWatch(ctx context.Context, c *client.Client, p cliutil.ParsedArgs) (int, error) {
	jsonOut := p.FlagBool("json")
	decisionFilter := strings.ToUpper(p.FlagStr("filter"))
	toolFilter := strings.ToLower(p.FlagStr("tool"))
	localOnly := p.FlagBool("local-only")
	cloudOnly := p.FlagBool("cloud-only")

	keep := func(r watchRow) bool {
		if decisionFilter != "" {
			d := strings.ToUpper(r.Decision)

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
		res, err := c.Audit.List(ctx, client.AuditQuery{Limit: 50})
		if err != nil {

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
		cliutil.Errln("  " + cliutil.Dim("watching guard stream, Ctrl+C to stop"))
	}

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

		fmt.Fprint(os.Stdout, buf.String())
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
	cliutil.Out(term.Dim + "[" + watchClock(r.At) + "]" + term.Reset + " " +
		source + term.Reset + " " +
		decision + cliutil.PadRight(r.Decision, 6) + term.Reset + " " +
		term.Cyan + cliutil.PadRight(cliutil.Truncate(r.Tool, 12), 13) + term.Reset +
		term.Dim + cliutil.PadRight(firstN(r.Permission, 4), 5) + term.Reset +
		dlp + term.Dim + cliutil.PadRight(cliutil.Truncate(agent, 12), 13) + r.Detail + term.Reset)
}

func readLocalRows(file string, after int64) []watchRow {
	var rows []watchRow
	for _, line := range tailLines(file, watchTailBytes) {
		var j map[string]json.RawMessage
		if json.Unmarshal([]byte(line), &j) != nil {
			continue
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
	split := strings.Split(string(b), "\n")
	// Only a window that opens mid-line starts with a fragment. Opening
	// exactly after a newline, the first chunk is a complete log entry and
	// must be kept, or watch skips it (issue #222). The fragment has to go
	// before empties are filtered: when start sits on the newline itself,
	// split[0] is the empty fragment, and dropping the first non-empty line
	// instead would skip a real entry.
	if start > 0 && !precededByNewline(f, start) {
		split = split[1:]
	}
	var lines []string
	for _, l := range split {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func precededByNewline(f *os.File, off int64) bool {
	b := make([]byte, 1)
	_, err := f.ReadAt(b, off-1)
	return err == nil && b[0] == '\n'
}

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

func jsonTruthy(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	switch s {
	case "", "null", "false", "0", `""`:
		return false
	}
	return true
}

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
