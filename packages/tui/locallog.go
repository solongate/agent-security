// SPDX-License-Identifier: Apache-2.0

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

// Reading the machine-local audit log the hooks write.
//
// core/config already answers WHERE the file is and whether local logging
// is on (config.LocalLogsSetting). What was missing, and is here, is reading
// its contents: the port of the second half of
// packages/proxy/src/tui/local-log.ts. It lives in the TUI package because the
// TUI is its only caller today; when `watch`, `doctor` or the logs server
// land they should take it into core/config rather than copy it.

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
// tag, a hash prefix of the key, because after pairing a different account the
// previous one's calls kept showing up in Live; unstamped lines could not be
// attributed, so they were dropped rather than pass as ours.
//
// Nothing stamps the tag now: there are no accounts, and both guards stopped reading a
// credential. Keeping the filter would have been quietly destructive rather than
// merely dead, a credential file left behind by an older install makes `mine`
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
// block time, and it is never redacted, so it is the reliable signal source
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
	if !rewriteLog(file, size, []byte(body)) {
		return 0
	}
	return removed
}

// clearLocalLog empties the local log and reports how many lines went.
func clearLocalLog() int {
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

// ── rewriting a file the hooks are appending to ──────────────────────────────
//
// THE HOT PATH TAKES NO LOCK, AND MUST NOT. Every tool call on this machine
// appends one line to this file, from a hook that has milliseconds before the
// client kills it. A lock there would be a syscall and a contention point on
// the critical path of every call, to protect against something that happens
// when somebody presses x in a TUI.
//
// It does not need one. O_APPEND writes are atomic against each other, which is
// why a burst of concurrent hooks never corrupts the log. The ONE unsafe
// operation is this: read the whole file, decide what it should say, write it
// back. Anything appended between the read and the write is inside neither the
// old content nor the new, and it is gone, silently, which is the part that
// matters for an audit trail.
//
// So the rewriter checks instead of locking: it remembers the size it read and
// refuses to write if the file has grown since. The caller reports zero removed
// and the row stays, which is the safe direction, a delete that did not happen
// is visible, a record that vanished is not.
//
// WHAT THIS DOES NOT CLOSE, stated rather than discovered: the window between
// the stat and the write. An append landing in those microseconds is still
// lost. Closing it needs the appenders to take a lock too, and that is the hot
// path. What is closed is the case that actually happens, a delete pressed
// while an agent is working, where the appends are milliseconds apart and the
// read-decide-write is not.

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

// rewriteLog replaces the file only if it is still the size it was read at.
//
// 0600, not the 0644 this used to pass. The mode only applies on create, so it
// was usually moot, and "usually" is the wrong guarantee for a file that
// records every command an agent was refused, which is a log of what somebody
// was working on. shared.FileMode is the number the rest of the product writes.
func rewriteLog(file string, readSize int64, body []byte) bool {
	// THE LOCK CLOSES WHAT THE SIZE CHECK COULD NOT. The check alone left the
	// window between the stat and the write open: an append landing in those
	// microseconds was still lost. The appender takes this same lock now, in the
	// detached child that does the writing, so there is no window left.
	//
	// The size check stays, and is not redundant: it catches the case where an
	// appender gave up waiting and wrote anyway, which it is allowed to do
	// because losing the lock race must not lose the record.
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
		// Something appended while this was being decided. Writing now would
		// drop it, so nothing is written.
		return false
	}
	return os.WriteFile(file, body, shared.FileMode) == nil
}

// lockAuditLog takes the lock the Node writer takes, and GIVES UP rather than
// forcing it.
//
// The two sides fail in opposite directions on purpose, and shared.AuditLockName
// says why: an appender that cannot get the lock writes anyway, because losing
// the record is worse than racing. A rewriter that cannot get it does nothing,
// because a delete that did not happen is visible to the person who pressed the
// key and a vanished record is not.
func lockAuditLog(dir string) (func(), bool) {
	lock := filepath.Join(dir, shared.AuditLockName)
	deadline := time.Now().Add(shared.AuditLockWaitMS * time.Millisecond)
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, shared.FileMode)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(lock) }, true
		}
		// Somebody holds it, or a dead writer left it behind. A lock older than
		// the stale window is broken: this is a log, and a killed writer must
		// not stop every later one for the rest of the session.
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