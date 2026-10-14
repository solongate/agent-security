// SPDX-License-Identifier: Apache-2.0

package main

// Port of packages/hooks/tokens.mjs (HOOK_VERSION 6).
//
// What a turn COST: the tokens a client reports for one exchange with the
// model. Nothing else in this binary records it. Each client already reports
// its own usage; the readers below pull it out of whatever that client
// writes — Claude Code and Codex in the transcript file the hook is handed a
// path to, Antigravity in a local SQLite database, OpenCode in process (the
// payload on stdin already carries the counted numbers). That file is read
// ONLY for its usage numbers; no prose is read out of it and none is written
// anywhere.
//
// WHERE IT GOES: ~/.solongate/local-logs/token-usage-<date>.jsonl, one JSON
// object per turn, beside the audit trail the other commands write. Nothing
// leaves the machine and nothing is sent anywhere.
//
// Fire-and-forget, and every failure is silent: this records something ABOUT
// the work, and the work matters more. runTokens always returns 0 — this hook
// never has an opinion about whether a turn should have happened.

import (
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/shared"
)

// How much of a transcript to read. A turn is a few kilobytes; two megabytes
// is a long turn with large tool results in it, and reading a 50MB
// transcript on every Stop is the cost this bound exists to refuse.
const tokensTailBytes = 2 * 1024 * 1024

// tokenTurn is one exchange's cost, in the shape written to the log.
type tokenTurn struct {
	TurnKey    string
	Model      string
	Input      int
	Output     int
	CacheRead  int
	CacheWrite int
	Reasoning  int
	Total      int
	At         int64
}

// tokNumF is tokens.mjs's `num`: a value only counts if it is a finite
// positive number, and it is rounded to a whole token.
func tokNumF(v float64) int {
	if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
		return 0
	}
	return int(math.Round(v))
}

// tokStamp is tokens.mjs's `stamp`: an unparsable or absent timestamp falls
// back to now rather than to zero, so a bad record still sorts near the turn
// that produced it.
func tokStamp(v string) int64 {
	if v != "" {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t.UnixMilli()
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UnixMilli()
		}
	}
	return time.Now().UnixMilli()
}

// tailLines reads the last bytes of a file and splits them into lines,
// dropping the first partial line when the read started mid-file — that
// fragment is not JSON and would be the one line that fails to parse on
// every single turn.
func tailLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil
	}
	size := info.Size()
	from := size - tokensTailBytes
	if from < 0 {
		from = 0
	}
	length := size - from
	if length <= 0 {
		return nil
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(f, buf); err != nil {
		if from == 0 {
			// A short read from the start is still a partial file worth
			// reading what we got of; anywhere else it is unreadable.
			buf = buf[:0]
		} else {
			return nil
		}
	}
	lines := strings.Split(string(buf), "\n")
	if from > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	return lines
}

// ── payload field access ───────────────────────────────────────────────────
// The same `a || b || c` chain over alternative spellings that the client
// adapters in clients.go use, applied here to a decoded map instead of raw
// JSON — this hook does not need to preserve key order.

func strField(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func boolField(m map[string]interface{}, key string) bool {
	b, ok := m[key].(bool)
	return ok && b
}

func objField(m map[string]interface{}, key string) map[string]interface{} {
	if o, ok := m[key].(map[string]interface{}); ok {
		return o
	}
	return nil
}

func numField(m map[string]interface{}, key string) float64 {
	f, _ := m[key].(float64)
	return f
}

// ── collecting and writing ─────────────────────────────────────────────────

// collectTokens works out which client this payload is from and reads its
// numbers. Returns nil when the client cannot report, which is a normal
// answer and never a zero.
func collectTokens(data map[string]interface{}, source string) []tokenTurn {
	transcript := strField(data, "transcript_path", "transcriptPath")
	if transcript == "" {
		if common := objField(data, "common"); common != nil {
			transcript = strField(common, "transcriptPath", "transcript_path")
		}
	}

	if source == "antigravity" {
		id := ""
		if common := objField(data, "common"); common != nil {
			id = strField(common, "conversationId", "conversation_id")
		}
		return readAntigravity(id)
	}
	if transcript == "" {
		return nil
	}
	if _, err := os.Stat(transcript); err != nil {
		return nil
	}
	if source == "codex" {
		return readCodex(transcript, strField(data, "session_id", "sessionId"))
	}
	// Claude Code needs no prefix: requestId is provider-issued and unique
	// across every transcript, which is exactly what makes a resumed session
	// report the same turn once rather than twice.
	return readClaudeCode(transcript)
}

type tokenUsageParams struct {
	SessionID string
	AgentID   string
	AgentName string
	Source    string
	Turns     []tokenTurn
}

// writeTokenUsage appends one line per turn to this machine's own record.
//
// ~/.solongate/local-logs/, beside the audit trail, because one machine
// should have one place to look. One file per day so the thing stays
// greppable and a person can delete last month without parsing anything.
// Owner-only: what a session cost is not as sensitive as what it said, but it
// is nobody else's business either.
//
// Every failure is silent: this records something ABOUT the work, and the
// work matters more.
func writeTokenUsage(p tokenUsageParams) {
	if len(p.Turns) == 0 {
		return
	}
	dir := filepath.Join(shared.SGDir(), "local-logs")
	if os.MkdirAll(dir, shared.DirMode) != nil {
		return
	}
	now := time.Now().UTC()
	day := now.Format("2006-01-02")
	ts := now.Format("2006-01-02T15:04:05.000Z")

	var buf strings.Builder
	for _, t := range p.Turns {
		line, err := json.Marshal(map[string]interface{}{
			"ts": ts,
			// The turn id, so a reader can drop a repeat — a Stop that fires
			// twice for one exchange must not double somebody's count.
			"turn_key":    t.TurnKey,
			"session_id":  p.SessionID,
			"agent_id":    p.AgentID,
			"agent_name":  p.AgentName,
			"source":      p.Source,
			"input":       t.Input,
			"output":      t.Output,
			"cache_read":  t.CacheRead,
			"cache_write": t.CacheWrite,
			"reasoning":   t.Reasoning,
			"total":       t.Total,
			"model":       t.Model,
			"at":          t.At,
		})
		if err != nil {
			continue
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	path := filepath.Join(dir, "token-usage-"+day+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, shared.FileMode)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(buf.String())
	_ = os.Chmod(path, shared.FileMode)
}

// reportTokens records what the turn cost.
func reportTokens(data map[string]interface{}, source, sessionID, agentName, agentID string) {
	writeTokenUsage(tokenUsageParams{
		SessionID: sessionID,
		AgentID:   agentID,
		AgentName: agentName,
		Source:    source,
		Turns:     collectTokens(data, source),
	})
}

// tokenSourceOf names the client from the payload's SHAPE, for the reason the
// Antigravity branch in runTokens gives: a payload is a fact and an argument
// is a claim.
func tokenSourceOf(data map[string]interface{}) string {
	agCommon := objField(data, "common")
	if agCommon == nil {
		if hookArgs := objField(data, "hookArgs"); hookArgs != nil {
			agCommon = objField(hookArgs, "common")
		}
	}
	if agCommon != nil {
		return "antigravity"
	}
	path := strField(data, "transcript_path", "transcriptPath")
	if strings.Contains(path, "/.codex/") || strings.Contains(path, `\.codex\`) {
		return "codex"
	}
	return "claude-code"
}

// runTokens is the Stop-hook entry point for recording what a turn cost. It
// reads one JSON payload from stdin and always returns 0: this hook has no
// opinion about whether the work should proceed, and must never be the
// reason a turn fails.
//
// args[0], if present, overrides the agent id the way tokens.mjs's own
// argv[2] did (SOLONGATE_AGENT_ID takes precedence over it, same as there).
func runTokens(args []string) int {
	idSource := os.Getenv("SOLONGATE_AGENT_ID")
	if idSource == "" && len(args) > 0 {
		idSource = args[0]
	}
	agentID := shared.AgentKey(idSource)

	input, _ := io.ReadAll(os.Stdin)
	var data map[string]interface{}
	if json.Unmarshal(input, &data) != nil || data == nil {
		return 0
	}

	event := strField(data, "hook_event_name", "hookEventName")

	// OPENCODE calls this hook directly from its plugin, and its spend
	// arrives already counted, in process, rather than being read back off a
	// transcript the way the other three are.
	if boolField(data, "opencode") {
		if !boolField(data, "tokens") {
			return 0
		}
		writeTokenUsage(tokenUsageParams{
			SessionID: strField(data, "session_id"),
			AgentID:   agentID,
			AgentName: "OpenCode",
			Source:    "opencode",
			Turns: []tokenTurn{{
				TurnKey:    strField(data, "turn_key"),
				Input:      int(numField(data, "input")),
				Output:     int(numField(data, "output")),
				CacheRead:  int(numField(data, "cache_read")),
				CacheWrite: int(numField(data, "cache_write")),
				Reasoning:  int(numField(data, "reasoning")),
				Total:      int(numField(data, "total")),
				At:         int64(numField(data, "at")),
			}},
		})
		return 0
	}

	// ANTIGRAVITY sends a different shape: `{common: {...}, args: {...}}`,
	// with the generations already on disk. Detected by shape rather than by
	// a flag, because the client name is an argv argument this hook is also
	// given for the other three, and a payload is a fact while an argument is
	// a claim.
	agCommon := objField(data, "common")
	if agCommon == nil {
		if hookArgs := objField(data, "hookArgs"); hookArgs != nil {
			agCommon = objField(hookArgs, "common")
		}
	}
	agStop := objField(data, "stopHookArgs")
	if agStop == nil {
		if a := objField(data, "args"); a != nil {
			agStop = objField(a, "stopHookArgs")
		}
	}
	if agStop == nil {
		if hookArgs := objField(data, "hookArgs"); hookArgs != nil {
			agStop = objField(hookArgs, "stopHookArgs")
		}
	}
	if agCommon != nil {
		// Only at the END of an exchange: this hook fires on several events
		// and the generations are already on disk, so reading them on every
		// one would be the same rows read many times for nothing.
		if agStop != nil {
			agentName := strField(agCommon, "agentName", "agent_name")
			if agentName == "" {
				agentName = "Antigravity"
			}
			reportTokens(data, "antigravity",
				strField(agCommon, "conversationId", "conversation_id"),
				agentName, agentID)
		}
		return 0
	}

	// Stop is the one event that matters: a turn ends once, and that is when
	// its cost is final. A turn that ended with a tool call and no prose
	// still cost something, so nothing here is gated on there having been
	// words.
	if event != "Stop" && event != "SubagentStop" {
		return 0
	}
	sessionID := strField(data, "session_id", "sessionId", "conversation_id")
	if sessionID == "" {
		return 0
	}
	reportTokens(data, tokenSourceOf(data), sessionID, strField(data, "agent_name"), agentID)
	return 0
}