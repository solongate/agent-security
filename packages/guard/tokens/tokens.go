// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tokens

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

const tokensTailBytes = 2 * 1024 * 1024

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

func tokNumF(v float64) int {
	if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
		return 0
	}
	return int(math.Round(v))
}

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
	if from > 0 {
		if _, err := f.Seek(from, io.SeekStart); err != nil {
			return nil
		}
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(f, buf); err != nil {
		if from == 0 {

			buf = buf[:0]
		} else {
			return nil
		}
	}
	lines := strings.Split(string(buf), "\n")
	// The first chunk is a fragment of a line cut by the seek only when the
	// byte before from is not a newline. On an exact boundary it is a whole
	// turn, and dropping it would undercount that turn's tokens (issue #214).
	if from > 0 && len(lines) > 0 && !precededByNewline(f, from) {
		lines = lines[1:]
	}
	return lines
}

func precededByNewline(f *os.File, off int64) bool {
	b := make([]byte, 1)
	_, err := f.ReadAt(b, off-1)
	return err == nil && b[0] == '\n'
}

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

	return readClaudeCode(transcript)
}

type tokenUsageParams struct {
	SessionID string
	AgentID   string
	AgentName string
	Source    string
	Turns     []tokenTurn
}

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

func reportTokens(data map[string]interface{}, source, sessionID, agentName, agentID string) {
	writeTokenUsage(tokenUsageParams{
		SessionID: sessionID,
		AgentID:   agentID,
		AgentName: agentName,
		Source:    source,
		Turns:     collectTokens(data, source),
	})
}

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

func Run(args []string) int {
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