// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/shared"
)

type LocalLogLine struct {
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

	At int64 `json:"-"`
}

func TailLines(file string, maxBytes int64) []string {
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
	// Read one byte before start to know whether the window opens exactly
	// after a newline: then the first chunk is a complete line, not a
	// fragment, and it must not be dropped (issue #206).
	var firstIsFragment bool
	if start > 0 {
		probe := make([]byte, 1)
		if _, err := f.ReadAt(probe, start-1); err == nil && probe[0] != '\n' {
			firstIsFragment = true
		}
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	split := strings.Split(string(buf), "\n")
	// split[0] only corresponds to a leading fragment when it is non-empty.
	// If it's empty, file[start] was itself the newline that ends the
	// previous (out-of-window) line, so split[1:] already starts clean and
	// nothing needs dropping.
	dropFragment := firstIsFragment && len(split) > 0 && split[0] != ""
	var lines []string
	for i, l := range split {
		if i == 0 && dropFragment {
			continue
		}
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

const DefaultTailBytes = 131_072

func ParseLocalLines(lines []string) []LocalLogLine {
	out := make([]LocalLogLine, 0, len(lines))
	for _, line := range lines {
		var j LocalLogLine
		if json.Unmarshal([]byte(line), &j) != nil {
			continue
		}
		at, ok := ParseMillis(j.TS)
		if !ok {
			continue
		}
		j.At = at
		out = append(out, j)
	}
	return out
}

var (
	dlpReason = regexp.MustCompile(`(?i)security layer \(dlp\)`)
	rlReason  = regexp.MustCompile(`(?i)security layer \(rate limit\)|rate[- ]?limit(ed)?\b.*exceed|exceeded \d+ calls`)
	dlpName   = regexp.MustCompile(`(?i)contain(s)? (a |an )?(.+?)(\.|$)`)
)

func ReasonSignals(reason string) (dlp []string, burst bool) {
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

func DeleteLocalEntry(at int64, tool, session string) int {
	file := config.LocalLogFile()
	b, size, ok := readLogWithSize(file)
	if !ok {
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
		var j LocalLogLine
		if json.Unmarshal([]byte(line), &j) == nil {
			lineAt, ok := ParseMillis(j.TS)
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
	if !rewriteLog(file, size, []byte(body)) {
		return 0
	}
	return removed
}

// DeleteLocalLogMatching removes every local audit-log entry whose raw line the
// predicate accepts and reports how many lines it removed. The audit view passes
// the same filter it displays, so "delete all" cannot remove entries the user
// filtered out of the current view. A nil predicate deletes nothing: the caller
// must state what it is willing to destroy. Lines that do not parse are kept, so
// malformed rows survive instead of being dropped silently.
func DeleteLocalLogMatching(match func(raw []byte) bool) int {
	if match == nil {
		return 0
	}
	file := config.LocalLogFile()
	b, size, ok := readLogWithSize(file)
	if !ok {
		return 0
	}
	removed := 0
	var kept []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var j LocalLogLine
		if json.Unmarshal([]byte(line), &j) == nil && match([]byte(line)) {
			removed++
			continue
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
	if !rewriteLog(file, size, []byte(body)) {
		return 0
	}
	return removed
}

func ClearLocalLog() int {
	file := config.LocalLogFile()
	b, size, ok := readLogWithSize(file)
	if !ok {
		return 0
	}
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" {
			n++
		}
	}
	if !rewriteLog(file, size, nil) {
		return 0
	}
	return n
}

func readLogWithSize(file string) ([]byte, int64, bool) {
	f, err := os.Open(file)
	if err != nil {
		return nil, 0, false
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, 0, false
	}
	st, err := f.Stat()
	if err != nil {
		return nil, 0, false
	}
	return b, st.Size(), true
}

func rewriteLog(file string, readSize int64, body []byte) bool {

	unlock, ok := lockAuditLog(filepath.Dir(file))
	if !ok {
		return false
	}
	defer unlock()

	st, err := os.Stat(file)
	if err != nil {
		return false
	}
	if st.Size() != readSize {

		return false
	}
	return os.WriteFile(file, body, shared.FileMode) == nil
}

func lockAuditLog(dir string) (func(), bool) {
	lock := filepath.Join(dir, shared.AuditLockName)
	deadline := time.Now().Add(shared.AuditLockWaitMS * time.Millisecond)
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, shared.FileMode)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(lock) }, true
		}

		if st, serr := os.Stat(lock); serr == nil {
			if time.Since(st.ModTime()) > shared.AuditLockStaleAfterMS*time.Millisecond {
				_ = os.Remove(lock)
				continue
			}
		}
		if time.Now().After(deadline) {
			return nil, false
		}
		time.Sleep(10 * time.Millisecond)
	}
}