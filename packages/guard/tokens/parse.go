// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tokens

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"

	_ "modernc.org/sqlite"
)

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

			TurnKey: sid + ":" + id,

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

const (
	agyInUncached = "1.4.2"
	agyInCached   = "1.4.5"
	agyOut        = "1.4.3"
	agyThinking   = "1.4.9"

	agyAtSeconds = "1.9.4.1"
)

var agyWant = map[string]bool{
	agyInUncached: true,
	agyInCached:   true,
	agyOut:        true,
	agyThinking:   true,
	agyAtSeconds:  true,
}

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

	func() {
		defer func() { _ = recover() }()
		walk(buf, "", 0)
	}()
	return found
}

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