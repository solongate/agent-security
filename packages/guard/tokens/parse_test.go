// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tokens

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pbVarintBytes(v uint64) []byte {
	var buf []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			buf = append(buf, b|0x80)
		} else {
			buf = append(buf, b)
			break
		}
	}
	return buf
}

func pbTag(field, wire int) []byte {
	return pbVarintBytes(uint64(field)<<3 | uint64(wire))
}

func pbLenDelim(field int, payload []byte) []byte {
	out := pbTag(field, 2)
	out = append(out, pbVarintBytes(uint64(len(payload)))...)
	out = append(out, payload...)
	return out
}

func pbVarField(field int, v uint64) []byte {
	out := pbTag(field, 0)
	out = append(out, pbVarintBytes(v)...)
	return out
}

// buildAntigravityBlob hand-encodes a protobuf message shaped like the one
// pbFields/agyWant expects: field 1 -> {field 4 -> {2: uncachedIn, 3: out,
// 5: cachedIn, 9: thinking}, field 9 -> {field 4 -> {1: atSeconds}}}.
func buildAntigravityBlob(uncachedIn, cachedIn, out, thinking, atSeconds uint64) []byte {
	f4 := pbVarField(2, uncachedIn)
	f4 = append(f4, pbVarField(3, out)...)
	f4 = append(f4, pbVarField(5, cachedIn)...)
	f4 = append(f4, pbVarField(9, thinking)...)

	f9inner := pbVarField(1, atSeconds)
	f9 := pbLenDelim(4, f9inner)

	f1payload := pbLenDelim(4, f4)
	f1payload = append(f1payload, pbLenDelim(9, f9)...)

	return pbLenDelim(1, f1payload)
}

func newAntigravitySQLiteDB(t *testing.T, home, conversationID string, blobs [][]byte) {
	t.Helper()
	dir := filepath.Join(home, ".gemini", "antigravity-cli", "conversations")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, conversationID+".db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE gen_metadata (idx INTEGER, data BLOB)"); err != nil {
		t.Fatal(err)
	}
	for i, b := range blobs {
		if _, err := db.Exec("INSERT INTO gen_metadata (idx, data) VALUES (?, ?)", i, b); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPbVarint(t *testing.T) {
	cases := []struct {
		name    string
		buf     []byte
		at      int
		want    uint64
		wantIdx int
	}{
		{"single byte", []byte{0x05}, 0, 5, 1},
		{"classic two-byte 150", []byte{0x96, 0x01}, 0, 150, 2},
		{"starting at an offset", []byte{0xff, 0x05}, 1, 5, 2},
		{"empty buffer", []byte{}, 0, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, idx := pbVarint(c.buf, c.at)
			if got != c.want || idx != c.wantIdx {
				t.Errorf("pbVarint(%v, %d) = (%d, %d), want (%d, %d)", c.buf, c.at, got, idx, c.want, c.wantIdx)
			}
		})
	}
}

func TestPbFields(t *testing.T) {
	blob := buildAntigravityBlob(1000, 200, 500, 50, 1700000000)
	got := pbFields(blob, agyWant)

	want := map[string]int64{
		agyInUncached: 1000,
		agyOut:        500,
		agyInCached:   200,
		agyThinking:   50,
		agyAtSeconds:  1700000000,
	}
	if len(got) != len(want) {
		t.Fatalf("pbFields() = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("pbFields()[%q] = %d, want %d", k, got[k], v)
		}
	}
}

func TestReadClaudeCode(t *testing.T) {
	lines := []string{
		`{"type":"assistant","requestId":"r1","timestamp":"2024-01-01T00:00:00Z","message":{"id":"m1","model":"claude-3","usage":{"input_tokens":10,"cache_creation_input_tokens":2,"cache_read_input_tokens":1,"output_tokens":5,"output_tokens_details":{"thinking_tokens":3}}}}`,
		`{"type":"assistant","requestId":"r1","timestamp":"2024-01-01T00:01:00Z","message":{"id":"m2","model":"claude-3","usage":{"input_tokens":99,"output_tokens":99}}}`,
		`{"type":"assistant","requestId":"r3","timestamp":"2024-01-01T00:02:00Z","message":{"id":"m3","model":"claude-3","usage":{"input_tokens":0,"output_tokens":0}}}`,
		`{"type":"user","requestId":"r4","timestamp":"2024-01-01T00:03:00Z"}`,
		`{not valid json`,
	}
	path := filepath.Join(t.TempDir(), "transcript.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := readClaudeCode(path)
	if len(got) != 1 {
		t.Fatalf("readClaudeCode() = %v, want 1 turn", got)
	}
	turn := got[0]
	if turn.TurnKey != "r1" || turn.Model != "claude-3" {
		t.Errorf("turn key/model = %q/%q, want r1/claude-3", turn.TurnKey, turn.Model)
	}
	if turn.Input != 10 || turn.Output != 5 || turn.CacheRead != 1 || turn.CacheWrite != 2 || turn.Reasoning != 3 || turn.Total != 18 {
		t.Errorf("turn = %+v, want input10/output5/cacheRead1/cacheWrite2/reasoning3/total18", turn)
	}
}

func TestReadCodex(t *testing.T) {
	lines := []string{
		`{"type":"event_msg","ordinal":1,"timestamp":"2024-01-01T00:00:00Z","payload":{"type":"token_count","info":{"last_token_usage":{"total_tokens":30,"input_tokens":10,"output_tokens":20,"cached_input_tokens":2,"cache_write_input_tokens":3,"reasoning_output_tokens":4}}}}`,
		`{"type":"event_msg","timestamp":"2024-01-01T00:01:00Z","payload":{"type":"token_count","info":{"last_token_usage":{"total_tokens":0,"input_tokens":5,"output_tokens":7},"total_token_usage":{"total_tokens":100}}}}`,
		`{"type":"event_msg","timestamp":"2024-01-01T00:02:00Z","payload":{"type":"token_count","info":{"last_token_usage":{"total_tokens":0,"input_tokens":0,"output_tokens":0}}}}`,
		`{"type":"other","payload":{"type":"token_count","info":{}}}`,
	}
	path := filepath.Join(t.TempDir(), "codex.jsonl")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := readCodex(path, "sess1")
	if len(got) != 2 {
		t.Fatalf("readCodex() = %v, want 2 turns", got)
	}
	if got[0].TurnKey != "sess1:o:1" || got[0].Total != 30 || got[0].CacheRead != 2 || got[0].CacheWrite != 3 || got[0].Reasoning != 4 {
		t.Errorf("ordinal turn = %+v", got[0])
	}
	if got[1].TurnKey != "sess1:t:2024-01-01T00:01:00Z:100" || got[1].Total != 12 {
		t.Errorf("timestamp turn = %+v, want total-fallback 12", got[1])
	}
}

func TestReadCodexDefaultsSessionIDWhenEmpty(t *testing.T) {
	line := `{"type":"event_msg","ordinal":1,"timestamp":"2024-01-01T00:00:00Z","payload":{"type":"token_count","info":{"last_token_usage":{"total_tokens":30,"input_tokens":10,"output_tokens":20}}}}`
	path := filepath.Join(t.TempDir(), "codex.jsonl")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := readCodex(path, "")
	if len(got) != 1 || got[0].TurnKey != "codex:o:1" {
		t.Fatalf("readCodex() = %v, want TurnKey codex:o:1", got)
	}
}

func TestReadAntigravity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	id := "conv-1"
	row0 := buildAntigravityBlob(1000, 200, 500, 50, 1700000000)
	row1 := buildAntigravityBlob(300, 0, 100, 10, 1700000100)
	rowSkipped := buildAntigravityBlob(0, 0, 0, 0, 1700000200)
	newAntigravitySQLiteDB(t, home, id, [][]byte{row0, row1, rowSkipped})

	got := readAntigravity(id)
	if len(got) != 2 {
		t.Fatalf("readAntigravity() = %v, want 2 turns (the input+output<=0 row should be skipped)", got)
	}

	if want := id + ":gen:0"; got[0].TurnKey != want || got[0].Input != 1200 || got[0].Output != 500 ||
		got[0].CacheRead != 200 || got[0].Reasoning != 50 || got[0].Total != 1700 || got[0].At != 1700000000*1000 {
		t.Errorf("row0 = %+v", got[0])
	}
	if want := id + ":gen:1"; got[1].TurnKey != want || got[1].Input != 300 || got[1].Output != 100 ||
		got[1].CacheRead != 0 || got[1].Reasoning != 10 || got[1].Total != 400 || got[1].At != 1700000100*1000 {
		t.Errorf("row1 = %+v", got[1])
	}
}

func TestReadAntigravityNotFound(t *testing.T) {
	if got := readAntigravity(""); got != nil {
		t.Errorf("readAntigravity(\"\") = %v, want nil", got)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	if got := readAntigravity("no-such-conversation"); got != nil {
		t.Errorf("readAntigravity(missing db) = %v, want nil", got)
	}
}