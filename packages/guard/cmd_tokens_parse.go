// SPDX-License-Identifier: Apache-2.0

package main

// Split from cmd_tokens.go: the per-client transcript/database readers that
// turn a Claude Code, Codex, or Antigravity record into tokenTurn values.

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"

	_ "modernc.org/sqlite"
)

// ── Claude Code ────────────────────────────────────────────────────────────

// readClaudeCode reads one row per API REQUEST, deduped.
//
// The dedupe is the whole correctness of this reader. Usage is reported per
// API request but the transcript writes one record per content block, so the
// same usage object appears up to four times with the same requestId.
// Summing records rather than requests overcounts by roughly half.
func readClaudeCode(transcriptPath string) []tokenTurn {
	seen := map[string]bool{}
	var out []tokenTurn
	for _, line := range tailLines(transcriptPath) {
		if line == "" || line[0] != '{' {
			continue
		}
		var r struct {
			Type      string `json:"type"`
			RequestID string `json:"requestId"`
			Timestamp string `json:"timestamp"`
			Message   *struct {
				ID    string `json:"id"`
				Model string `json:"model"`
				Usage *struct {
					InputTokens              float64 `json:"input_tokens"`
					CacheCreationInputTokens float64 `json:"cache_creation_input_tokens"`
					CacheReadInputTokens     float64 `json:"cache_read_input_tokens"`
					OutputTokens             float64 `json:"output_tokens"`
					OutputTokensDetails      *struct {
						ThinkingTokens float64 `json:"thinking_tokens"`
					} `json:"output_tokens_details"`
				} `json:"usage"`
			} `json:"message"`
		}
		if json.Unmarshal([]byte(line), &r) != nil || r.Type != "assistant" || r.Message == nil || r.Message.Usage == nil {
			continue
		}

		// requestId is the API request's identity. A few synthetic records
		// carry none — API-error placeholders with all-zero usage — so the
		// message id is the fallback rather than letting them collide on
		// empty.
		key := r.RequestID
		if key == "" {
			key = r.Message.ID
		}
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true

		u := r.Message.Usage
		input := tokNumF(u.InputTokens)
		cacheWrite := tokNumF(u.CacheCreationInputTokens)
		cacheRead := tokNumF(u.CacheReadInputTokens)
		output := tokNumF(u.OutputTokens)
		total := input + cacheWrite + cacheRead + output
		if total <= 0 {
			continue
		}
		reasoning := 0
		if u.OutputTokensDetails != nil {
			reasoning = tokNumF(u.OutputTokensDetails.ThinkingTokens)
		}

		out = append(out, tokenTurn{
			TurnKey: key,
			// WHICH MODEL RAN IT. Only Claude Code reports it; the others
			// leave it empty rather than guessing.
			Model:      r.Message.Model,
			Input:      input,
			Output:     output,
			CacheRead:  cacheRead,
			CacheWrite: cacheWrite,
			Reasoning:  reasoning,
			Total:      total,
			At:         tokStamp(r.Timestamp),
		})
	}
	return out
}

// ── Codex ──────────────────────────────────────────────────────────────────

// readCodex reads one row per model request, from the token_count events.
//
// `last_token_usage` rather than `total_token_usage`: the second is
// cumulative for the session, and treating it as a per-turn figure would
// count the whole session again on every turn.
func readCodex(transcriptPath, sessionID string) []tokenTurn {
	var out []tokenTurn
	for _, line := range tailLines(transcriptPath) {
		if line == "" || line[0] != '{' {
			continue
		}
		var r struct {
			Type      string   `json:"type"`
			Ordinal   *float64 `json:"ordinal"`
			Timestamp string   `json:"timestamp"`
			Payload   *struct {
				Type string `json:"type"`
				Info *struct {
					LastTokenUsage *struct {
						TotalTokens           float64 `json:"total_tokens"`
						InputTokens           float64 `json:"input_tokens"`
						OutputTokens          float64 `json:"output_tokens"`
						CachedInputTokens     float64 `json:"cached_input_tokens"`
						CacheWriteInputTokens float64 `json:"cache_write_input_tokens"`
						ReasoningOutputTokens float64 `json:"reasoning_output_tokens"`
					} `json:"last_token_usage"`
					TotalTokenUsage *struct {
						TotalTokens float64 `json:"total_tokens"`
					} `json:"total_token_usage"`
				} `json:"info"`
			} `json:"payload"`
		}
		if json.Unmarshal([]byte(line), &r) != nil || r.Type != "event_msg" || r.Payload == nil || r.Payload.Type != "token_count" || r.Payload.Info == nil {
			continue
		}
		last := r.Payload.Info.LastTokenUsage
		if last == nil {
			continue
		}

		total := tokNumF(last.TotalTokens)
		if total == 0 {
			total = tokNumF(last.InputTokens) + tokNumF(last.OutputTokens)
		}
		if total <= 0 {
			continue
		}

		// The record's OWN ordinal, never a count of what this read happened
		// to see. Counting within the tail renumbers every event the moment
		// the file grows past the window — the same turn gets a new key, and
		// a new key is a second row. Older rollouts carry no ordinal, so
		// those fall back to the timestamp paired with the running total,
		// which together do not repeat.
		var id string
		if r.Ordinal != nil {
			id = "o:" + strconv.FormatInt(int64(*r.Ordinal), 10)
		} else {
			running := 0
			if r.Payload.Info.TotalTokenUsage != nil {
				running = tokNumF(r.Payload.Info.TotalTokenUsage.TotalTokens)
			}
			id = "t:" + r.Timestamp + ":" + strconv.Itoa(running)
		}
		sid := sessionID
		if sid == "" {
			sid = "codex"
		}

		out = append(out, tokenTurn{
			// Prefixed with the session, because an ordinal is only unique
			// WITHIN a rollout.
			TurnKey: sid + ":" + id,
			// input_tokens INCLUDES cached here, and output INCLUDES
			// reasoning — the opposite of Claude Code's disjoint buckets.
			// The total is the provider's own, so the difference never has
			// to be reconciled.
			Input:      tokNumF(last.InputTokens),
			Output:     tokNumF(last.OutputTokens),
			CacheRead:  tokNumF(last.CachedInputTokens),
			CacheWrite: tokNumF(last.CacheWriteInputTokens),
			Reasoning:  tokNumF(last.ReasoningOutputTokens),
			Total:      total,
			At:         tokStamp(r.Timestamp),
		})
	}
	return out
}

// ── Antigravity ────────────────────────────────────────────────────────────

// pbVarint reads a protobuf varint, returning the value and the index past
// it.
func pbVarint(buf []byte, i int) (uint64, int) {
	var result uint64
	var shift uint
	for i < len(buf) {
		b := buf[i]
		i++
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, i
		}
		shift += 7
		if shift > 70 {
			break
		}
	}
	return result, i
}

// The field numbers, and what each one is. Antigravity stores an opaque
// message and this mapping was established by decoding real generations and
// testing an identity that held every time — it is the one client whose
// mapping is not published, so it is the one where the evidence matters
// most.
const (
	agyInUncached = "1.4.2"
	agyInCached   = "1.4.5"
	agyOut        = "1.4.3"
	agyThinking   = "1.4.9"
	// The generation's own clock: a google.protobuf.Timestamp, whose field 1
	// is seconds. Without it every generation in the tail would be stamped
	// with the moment it was READ, which puts a week of work on today's bar.
	agyAtSeconds = "1.9.4.1"
)

var agyWant = map[string]bool{
	agyInUncached: true,
	agyInCached:   true,
	agyOut:        true,
	agyThinking:   true,
	agyAtSeconds:  true,
}

// pbFields pulls the varints at the wanted dotted protobuf paths out of a
// blob. A tiny hand-rolled walker rather than a schema, because there is no
// schema on disk.
func pbFields(buf []byte, want map[string]bool) map[string]int64 {
	found := map[string]int64{}
	var walk func(b []byte, path string, depth int)
	walk = func(b []byte, path string, depth int) {
		i := 0
		for i < len(b) {
			var key uint64
			key, i = pbVarint(b, i)
			field := key >> 3
			wire := key & 7
			here := strconv.FormatUint(field, 10)
			if path != "" {
				here = path + "." + here
			}
			switch wire {
			case 0:
				var v uint64
				v, i = pbVarint(b, i)
				if want[here] {
					if _, ok := found[here]; !ok {
						found[here] = int64(v)
					}
				}
			case 2:
				var ln uint64
				ln, i = pbVarint(b, i)
				end := i + int(ln)
				if end > len(b) || int(ln) < 0 {
					return
				}
				if depth < 6 {
					walk(b[i:end], here, depth+1)
				}
				i = end
			case 5:
				i += 4
			case 1:
				i += 8
			default:
				return
			}
		}
	}
	// A blob we cannot read is a blob we skip.
	func() {
		defer func() { _ = recover() }()
		walk(buf, "", 0)
	}()
	return found
}

// readAntigravity reads every generation's usage out of this conversation's
// own SQLite database. Read-only: this is the client's own live database and
// nothing here has any business writing to it.
//
// The Node hook used node:sqlite (Node 22+, no native dependency) and simply
// returned nothing on an older runtime rather than add one for a security
// tool to report a number. This binary has no such runtime gate, so it reads
// the database directly with a pure-Go driver (modernc.org/sqlite) instead —
// no cgo, consistent with every other package in this module.
func readAntigravity(conversationID string) []tokenTurn {
	if conversationID == "" {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	dbPath := filepath.Join(home, ".gemini", "antigravity-cli", "conversations", conversationID+".db")
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}

	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		return nil
	}
	defer db.Close()

	rows, err := db.Query("SELECT idx, data FROM gen_metadata ORDER BY idx")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []tokenTurn
	for rows.Next() {
		var idx int64
		var blob []byte
		if rows.Scan(&idx, &blob) != nil || len(blob) == 0 {
			continue
		}
		f := pbFields(blob, agyWant)

		input := f[agyInUncached] + f[agyInCached]
		output := f[agyOut]
		if input+output <= 0 {
			continue
		}

		out = append(out, tokenTurn{
			// The generation index, prefixed with the conversation it counts
			// within: an index is only unique inside one database.
			TurnKey:    conversationID + ":gen:" + strconv.FormatInt(idx, 10),
			Input:      int(input),
			Output:     int(output),
			CacheRead:  int(f[agyInCached]),
			CacheWrite: 0,
			Reasoning:  int(f[agyThinking]),
			Total:      int(input + output),
			At:         f[agyAtSeconds] * 1000,
		})
	}
	return out
}