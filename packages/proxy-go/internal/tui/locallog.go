// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// Reading the machine-local audit log the hooks write.
//
// internal/config already answers WHERE the file is and whether local logging
// is on (config.LocalLogsSetting). What was missing, and is here, is reading
// its contents: the port of the second half of
// packages/proxy/src/tui/local-log.ts. It lives in the TUI package because the
// dataroom is its only caller today; when `watch`, `doctor` or the logs server
// land they should take it into internal/config rather than copy it.

// localLogLine is one parsed line of the local JSONL. Every field is
// best-effort: the hooks have added fields over time and a line written by an
// older one still has to render.
type localLogLine struct {
	TS               string          `json:"ts"`
	Tool             string          `json:"tool"`
	Decision         string          `json:"decision"`
	Reason           string          `json:"reason"`
	Arguments        json.RawMessage `json:"arguments"`
	DLP              json.RawMessage `json:"dlp"`
	Permission       string          `json:"permission"`
	TrustLevel       string          `json:"trust_level"`
	SessionID        string          `json:"session_id"`
	AgentName        string          `json:"agent_name"`
	EvaluationTimeMs *float64        `json:"evaluation_time_ms"`
	MatchedRuleID    string          `json:"matched_rule_id"`
	RateLimitBurst   bool            `json:"rate_limit_burst"`

	// At is the parsed ts, filled in by parseLocalLines.
	At int64 `json:"-"`
}

// tailLines reads the last maxBytes of a file as COMPLETE lines.
//
// The first line of a mid-file read is dropped because it is almost certainly a
// fragment, and a fragment that happens to parse is worse than one that does
// not: it would enter the stream as a call that never occurred.
func tailLines(file string, maxBytes int64) []string {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil
	}
	size := info.Size()
	start := size - maxBytes
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(string(buf), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	if start > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	return lines
}

const defaultTailBytes = 131_072

// parseLocalLines reads every line in the machine's own log.
//
// IT USED TO FILTER BY ACCOUNT. The log is one file per machine and carried an `acct`
// tag — a hash prefix of the key — because after pairing a different account the
// previous one's calls kept showing up in Live; unstamped lines could not be
// attributed, so they were dropped rather than pass as ours.
//
// Nothing stamps the tag now: there are no accounts, and both guards stopped reading a
// credential. Keeping the filter would have been quietly destructive rather than
// merely dead — a credential file left behind by an older install makes `mine`
// non-empty, and then every line written since would be dropped as somebody else's.
// Live would go blank on exactly the machines that had been upgraded, while a machine
// that had never been paired looked fine.
func parseLocalLines(lines []string) []localLogLine {
	out := make([]localLogLine, 0, len(lines))
	for _, line := range lines {
		var j localLogLine
		if json.Unmarshal([]byte(line), &j) != nil {
			continue
		}
		at, ok := parseMillis(j.TS)
		if !ok {
			continue
		}
		j.At = at
		out = append(out, j)
	}
	return out
}

// The guard writes a DENY reason like "Security layer (DLP): blocked -
// arguments contain a Anthropic key" to BOTH the cloud and the local file at
// block time, and it is never redacted — so it is the reliable signal source
// when the dlp/burst fields are not stored and a re-scan of the arguments would
// miss the value that was blocked or redacted.
var (
	dlpReason = regexp.MustCompile(`(?i)security layer \(dlp\)`)
	rlReason  = regexp.MustCompile(`(?i)security layer \(rate limit\)|rate[- ]?limit(ed)?\b.*exceed|exceeded \d+ calls`)
	dlpName   = regexp.MustCompile(`(?i)contain(s)? (a |an )?(.+?)(\.|$)`)
)

// reasonSignals derives the DLP pattern name and the rate-limit burst flag from
// a decision's reason.
func reasonSignals(reason string) (dlp []string, burst bool) {
	if dlpReason.MatchString(reason) {
		name := "DLP"
		if m := dlpName.FindStringSubmatch(reason); m != nil {
			if v := strings.TrimSpace(m[3]); v != "" {
				name = v
			}
		}
		dlp = append(dlp, name)
	}
	return dlp, rlReason.MatchString(reason)
}

// deleteLocalEntry removes ONE matching line (ts + tool, and session when the
// caller knows it) and reports how many it removed.
//
// Lines that do not parse are KEPT. They are the only record of a call the
// reader could not understand, and a delete that quietly tidies them up is a
// delete that destroys evidence.
func deleteLocalEntry(at int64, tool, session string) int {
	file := config.LocalLogFile()
	b, err := os.ReadFile(file)
	if err != nil {
		return 0
	}
	removed := 0
	var kept []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if removed > 0 {
			kept = append(kept, line)
			continue
		}
		var j localLogLine
		if json.Unmarshal([]byte(line), &j) == nil {
			lineAt, ok := parseMillis(j.TS)
			name := j.Tool
			if name == "" {
				name = "?"
			}
			if ok && lineAt == at && name == tool && (session == "" || j.SessionID == session) {
				removed++
				continue
			}
		}
		kept = append(kept, line)
	}
	if removed == 0 {
		return 0
	}
	body := ""
	if len(kept) > 0 {
		body = strings.Join(kept, "\n") + "\n"
	}
	if os.WriteFile(file, []byte(body), 0o644) != nil {
		return 0
	}
	return removed
}

// clearLocalLog empties the local log and reports how many lines went.
func clearLocalLog() int {
	file := config.LocalLogFile()
	b, err := os.ReadFile(file)
	if err != nil {
		return 0
	}
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" {
			n++
		}
	}
	if os.WriteFile(file, nil, 0o644) != nil {
		return 0
	}
	return n
}
