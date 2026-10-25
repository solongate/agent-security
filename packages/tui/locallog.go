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
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	split := strings.Split(string(buf), "\n")
	var lines []string
	for _, l := range split {
		if l != "" {
			lines = append(lines, l)
		}
	}
	if start > 0 && len(split) > 0 && split[0] != "" {
		lines = lines[1:]
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