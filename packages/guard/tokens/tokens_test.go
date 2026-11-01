// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tokens

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/solongate/agent-security/packages/shared"
)

func TestTokNumF(t *testing.T) {
	cases := []struct {
		name string
		in   float64
		want int
	}{
		{"NaN", math.NaN(), 0},
		{"positive infinity", math.Inf(1), 0},
		{"negative infinity", math.Inf(-1), 0},
		{"negative", -5, 0},
		{"zero", 0, 0},
		{"rounds down", 3.2, 3},
		{"rounds up", 3.6, 4},
		{"large integer", 123456, 123456},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tokNumF(c.in); got != c.want {
				t.Errorf("tokNumF(%v) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

func TestTokStampParsesKnownFormats(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"RFC3339Nano", "2024-03-15T10:30:00.123456789Z"},
		{"RFC3339", "2024-03-15T10:30:00Z"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want, err := time.Parse(time.RFC3339Nano, c.in)
			if err != nil {
				t.Fatalf("reference parse failed: %v", err)
			}
			if got := tokStamp(c.in); got != want.UnixMilli() {
				t.Errorf("tokStamp(%q) = %d, want %d", c.in, got, want.UnixMilli())
			}
		})
	}
}

func TestTokStampFallsBackToNowOnEmptyString(t *testing.T) {
	before := time.Now().UnixMilli()
	got := tokStamp("")
	after := time.Now().UnixMilli()
	if got < before || got > after {
		t.Errorf("tokStamp(\"\") = %d, want within [%d, %d]", got, before, after)
	}
}

func TestTokStampFallsBackToNowOnUnparseableString(t *testing.T) {
	before := time.Now().UnixMilli()
	got := tokStamp("not-a-timestamp")
	after := time.Now().UnixMilli()
	if got < before || got > after {
		t.Errorf("tokStamp(garbage) = %d, want within [%d, %d]", got, before, after)
	}
}

func TestTailLinesOnASmallFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "small.jsonl")
	if err := os.WriteFile(path, []byte("a\nb\nc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := tailLines(path)
	want := []string{"a", "b", "c", ""}
	if len(got) != len(want) {
		t.Fatalf("tailLines() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestTailLinesOnAMissingFile(t *testing.T) {
	if got := tailLines(filepath.Join(t.TempDir(), "missing.jsonl")); got != nil {
		t.Errorf("tailLines(missing) = %v, want nil", got)
	}
}

func TestTailLinesDropsTheLeadingPartialLineOnTruncation(t *testing.T) {
	const width = 39
	numLines := tokensTailBytes/width + 1000

	var b strings.Builder
	for i := 0; i < numLines; i++ {
		line := fmt.Sprintf("line-%07d-%s", i, strings.Repeat("x", 25))
		if len(line) != width-1 {
			t.Fatalf("test setup: line %d has length %d, want %d", i, len(line), width-1)
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	content := b.String()
	size := int64(len(content))
	from := size - tokensTailBytes
	if from <= 0 {
		t.Fatalf("test setup: from = %d, want > 0 to exercise truncation", from)
	}
	if from%width == 0 {
		t.Fatalf("test setup: from = %d lands on a line boundary, need a mid-line cut", from)
	}

	path := filepath.Join(t.TempDir(), "big.jsonl")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got := tailLines(path)
	if len(got) == 0 {
		t.Fatal("tailLines() returned nothing")
	}

	cutLineIdx := int(from / width)
	firstFullLineIdx := cutLineIdx + 1
	wantFirst := fmt.Sprintf("line-%07d-%s", firstFullLineIdx, strings.Repeat("x", 25))
	if got[0] != wantFirst {
		t.Errorf("first returned line = %q, want %q (the leading partial line should have been dropped)", got[0], wantFirst)
	}

	wantLast := fmt.Sprintf("line-%07d-%s", numLines-1, strings.Repeat("x", 25))
	found := false
	for _, l := range got {
		if l == wantLast {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("the final written line %q was not present in the tail", wantLast)
	}
}

// Issue #214: a cut that lands exactly after a newline leaves a complete
// first line, and it used to be dropped as if it were a fragment.
func TestTailLinesKeepsTheFirstLineOnAnExactBoundary(t *testing.T) {
	const width = 64 // divides tokensTailBytes, so from lands on a line start
	const before = 1000
	numLines := tokensTailBytes/width + before

	var b strings.Builder
	for i := 0; i < numLines; i++ {
		line := fmt.Sprintf("line-%07d-%s", i, strings.Repeat("x", width-14))
		if len(line) != width-1 {
			t.Fatalf("test setup: line %d has length %d, want %d", i, len(line), width-1)
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	content := b.String()
	from := int64(len(content)) - tokensTailBytes
	if from <= 0 || from%width != 0 {
		t.Fatalf("test setup: from = %d, want a positive multiple of %d", from, width)
	}

	path := filepath.Join(t.TempDir(), "boundary.jsonl")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got := tailLines(path)
	if want := tokensTailBytes/width + 1; len(got) != want {
		t.Fatalf("tailLines() returned %d lines, want %d (every line in the window plus the trailing empty one)", len(got), want)
	}
	wantFirst := fmt.Sprintf("line-%07d-%s", before, strings.Repeat("x", width-14))
	if got[0] != wantFirst {
		t.Errorf("first returned line = %q, want %q (a complete line at the boundary must be kept)", got[0], wantFirst)
	}
}

func TestStrField(t *testing.T) {
	m := map[string]interface{}{"a": "", "b": "value", "c": 5}
	if got := strField(m, "a", "b"); got != "value" {
		t.Errorf("strField skipped an empty string match: got %q", got)
	}
	if got := strField(m, "c"); got != "" {
		t.Errorf("strField returned a non-string field: %q", got)
	}
	if got := strField(m, "missing"); got != "" {
		t.Errorf("strField(missing) = %q, want \"\"", got)
	}
}

func TestBoolField(t *testing.T) {
	m := map[string]interface{}{"t": true, "f": false, "s": "true"}
	if !boolField(m, "t") {
		t.Error("boolField(t) = false, want true")
	}
	if boolField(m, "f") {
		t.Error("boolField(f) = true, want false")
	}
	if boolField(m, "s") {
		t.Error("boolField did not type-check a string")
	}
	if boolField(m, "missing") {
		t.Error("boolField(missing) = true, want false")
	}
}

func TestObjField(t *testing.T) {
	inner := map[string]interface{}{"x": 1}
	m := map[string]interface{}{"o": inner, "s": "not an object"}
	if got := objField(m, "o"); got == nil || got["x"] != 1 {
		t.Errorf("objField(o) = %v, want %v", got, inner)
	}
	if got := objField(m, "s"); got != nil {
		t.Errorf("objField(s) = %v, want nil", got)
	}
	if got := objField(m, "missing"); got != nil {
		t.Errorf("objField(missing) = %v, want nil", got)
	}
}

func TestNumField(t *testing.T) {
	m := map[string]interface{}{"n": 42.5, "s": "42"}
	if got := numField(m, "n"); got != 42.5 {
		t.Errorf("numField(n) = %v, want 42.5", got)
	}
	if got := numField(m, "s"); got != 0 {
		t.Errorf("numField did not type-check a string: got %v", got)
	}
	if got := numField(m, "missing"); got != 0 {
		t.Errorf("numField(missing) = %v, want 0", got)
	}
}

func TestCollectTokensAntigravitySourceCallsReadAntigravity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	id := "conv-collect-1"
	blob := buildAntigravityBlob(100, 0, 50, 5, 1700000300)
	newAntigravitySQLiteDB(t, home, id, [][]byte{blob})

	data := map[string]interface{}{
		"common": map[string]interface{}{"conversationId": id},
	}
	got := collectTokens(data, "antigravity")
	if len(got) != 1 {
		t.Fatalf("collectTokens() = %v, want 1 turn", got)
	}
	if want := id + ":gen:0"; got[0].TurnKey != want {
		t.Errorf("TurnKey = %q, want %q", got[0].TurnKey, want)
	}
	if got[0].Input != 100 || got[0].Output != 50 {
		t.Errorf("Input/Output = %d/%d, want 100/50", got[0].Input, got[0].Output)
	}
}

func TestCollectTokensWithNoTranscriptPathReturnsNil(t *testing.T) {
	if got := collectTokens(map[string]interface{}{}, "claude-code"); got != nil {
		t.Errorf("collectTokens() = %v, want nil", got)
	}
}

func TestCollectTokensWithMissingTranscriptFileReturnsNil(t *testing.T) {
	data := map[string]interface{}{"transcript_path": filepath.Join(t.TempDir(), "missing.jsonl")}
	if got := collectTokens(data, "claude-code"); got != nil {
		t.Errorf("collectTokens() = %v, want nil", got)
	}
}

func TestCollectTokensDispatchesCodexVsClaudeCode(t *testing.T) {
	codexPath := filepath.Join(t.TempDir(), "codex.jsonl")
	codexLine := `{"type":"event_msg","ordinal":1,"timestamp":"2024-03-15T10:00:00Z","payload":{"type":"token_count","info":{"last_token_usage":{"total_tokens":30,"input_tokens":10,"output_tokens":20}}}}`
	if err := os.WriteFile(codexPath, []byte(codexLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := collectTokens(map[string]interface{}{
		"transcript_path": codexPath,
		"session_id":      "sess-codex",
	}, "codex")
	if len(got) != 1 || got[0].Total != 30 {
		t.Fatalf("codex dispatch: got %v, want 1 turn with total 30", got)
	}
	if !strings.HasPrefix(got[0].TurnKey, "sess-codex:") {
		t.Errorf("codex dispatch: TurnKey = %q, want sess-codex prefix", got[0].TurnKey)
	}

	ccPath := filepath.Join(t.TempDir(), "cc.jsonl")
	ccLine := `{"type":"assistant","requestId":"r1","timestamp":"2024-03-15T10:00:00Z","message":{"id":"m1","model":"claude-3","usage":{"input_tokens":10,"output_tokens":5}}}`
	if err := os.WriteFile(ccPath, []byte(ccLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got = collectTokens(map[string]interface{}{"transcript_path": ccPath}, "claude-code")
	if len(got) != 1 || got[0].TurnKey != "r1" {
		t.Fatalf("claude-code dispatch: got %v, want 1 turn keyed r1", got)
	}
}

func TestWriteTokenUsageWritesTheExpectedLine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	writeTokenUsage(tokenUsageParams{
		SessionID: "s1",
		AgentID:   "a1",
		AgentName: "A",
		Source:    "src",
		Turns: []tokenTurn{{
			TurnKey: "k1", Model: "m1",
			Input: 1, Output: 2, CacheRead: 3, CacheWrite: 4, Reasoning: 5, Total: 15, At: 123,
		}},
	})

	entry := readLastTokenUsageEntry(t)
	want := map[string]interface{}{
		"turn_key": "k1", "session_id": "s1", "agent_id": "a1", "agent_name": "A",
		"source": "src", "model": "m1",
		"input": 1.0, "output": 2.0, "cache_read": 3.0, "cache_write": 4.0, "reasoning": 5.0, "total": 15.0, "at": 123.0,
	}
	for k, v := range want {
		if entry[k] != v {
			t.Errorf("field %q = %v, want %v", k, entry[k], v)
		}
	}
	if ts, _ := entry["ts"].(string); ts == "" {
		t.Error("ts was not set")
	}
}

func TestWriteTokenUsageWithNoTurnsIsANoop(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeTokenUsage(tokenUsageParams{SessionID: "s1"})
	if _, err := os.Stat(filepath.Join(shared.SGDir(), "local-logs")); !os.IsNotExist(err) {
		t.Errorf("writeTokenUsage with no turns created %v, want nothing", err)
	}
}

func TestReportTokens(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	ccPath := filepath.Join(t.TempDir(), "cc.jsonl")
	ccLine := `{"type":"assistant","requestId":"r1","timestamp":"2024-03-15T10:00:00Z","message":{"id":"m1","model":"claude-3","usage":{"input_tokens":10,"output_tokens":5}}}`
	if err := os.WriteFile(ccPath, []byte(ccLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	reportTokens(map[string]interface{}{"transcript_path": ccPath}, "claude-code", "sess1", "AgentName", "agent1")

	entry := readLastTokenUsageEntry(t)
	if entry["session_id"] != "sess1" || entry["agent_name"] != "AgentName" || entry["agent_id"] != "agent1" {
		t.Errorf("entry = %v, want session_id=sess1 agent_name=AgentName agent_id=agent1", entry)
	}
}

func TestTokenSourceOf(t *testing.T) {
	cases := []struct {
		name string
		data map[string]interface{}
		want string
	}{
		{"common field present", map[string]interface{}{"common": map[string]interface{}{}}, "antigravity"},
		{"hookArgs.common present", map[string]interface{}{"hookArgs": map[string]interface{}{"common": map[string]interface{}{}}}, "antigravity"},
		{"unix codex path", map[string]interface{}{"transcript_path": "/home/u/.codex/sessions/abc.jsonl"}, "codex"},
		{"windows codex path", map[string]interface{}{"transcriptPath": `C:\Users\u\.codex\logs\x.jsonl`}, "codex"},
		{"claude code path", map[string]interface{}{"transcript_path": "/home/u/.claude/projects/x/abc.jsonl"}, "claude-code"},
		{"no fields at all", map[string]interface{}{}, "claude-code"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tokenSourceOf(c.data); got != c.want {
				t.Errorf("tokenSourceOf() = %q, want %q", got, c.want)
			}
		})
	}
}

func withStdin(t *testing.T, payload string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = old
	})
	if _, err := w.WriteString(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRunOpencodeTokensFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withStdin(t, `{"opencode": true, "tokens": true, "session_id": "s1", "turn_key": "k1", "input": 10, "output": 20, "cache_read": 1, "cache_write": 2, "reasoning": 3, "total": 30, "at": 1700000000000}`)

	if got := Run(nil); got != 0 {
		t.Fatalf("Run() = %d, want 0", got)
	}
	entry := readLastTokenUsageEntry(t)
	if entry["agent_name"] != "OpenCode" || entry["source"] != "opencode" || entry["turn_key"] != "k1" {
		t.Errorf("entry = %v, want OpenCode/opencode/k1", entry)
	}
	if entry["input"] != 10.0 || entry["total"] != 30.0 {
		t.Errorf("entry input/total = %v/%v, want 10/30", entry["input"], entry["total"])
	}
}

func TestRunOpencodeWithoutTokensFlagIsANoop(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	withStdin(t, `{"opencode": true, "tokens": false}`)

	if got := Run(nil); got != 0 {
		t.Fatalf("Run() = %d, want 0", got)
	}
	if _, err := os.Stat(filepath.Join(shared.SGDir(), "local-logs")); !os.IsNotExist(err) {
		t.Error("a no-op opencode call created log output")
	}
}

func TestRunAntigravityCommonBranch(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	id := "conv-run-1"
	blob := buildAntigravityBlob(100, 0, 50, 0, 1700000400)
	newAntigravitySQLiteDB(t, home, id, [][]byte{blob})

	withStdin(t, fmt.Sprintf(`{"common": {"conversationId": %q, "agentName": "Foo"}, "stopHookArgs": {}}`, id))

	if got := Run(nil); got != 0 {
		t.Fatalf("Run() = %d, want 0", got)
	}
	entry := readLastTokenUsageEntry(t)
	if entry["agent_name"] != "Foo" || entry["source"] != "antigravity" || entry["session_id"] != id {
		t.Errorf("entry = %v, want agent_name=Foo source=antigravity session_id=%s", entry, id)
	}
}

func TestRunStopAndSubagentStopEvents(t *testing.T) {
	for _, event := range []string{"Stop", "SubagentStop"} {
		t.Run(event, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)

			ccPath := filepath.Join(t.TempDir(), "cc.jsonl")
			ccLine := `{"type":"assistant","requestId":"r1","timestamp":"2024-03-15T10:00:00Z","message":{"id":"m1","model":"claude-3","usage":{"input_tokens":10,"output_tokens":5}}}`
			if err := os.WriteFile(ccPath, []byte(ccLine+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			payload := fmt.Sprintf(`{"hook_event_name": %q, "session_id": "sessA", "transcript_path": %q, "agent_name": "AgentX"}`, event, ccPath)
			withStdin(t, payload)

			if got := Run(nil); got != 0 {
				t.Fatalf("Run() = %d, want 0", got)
			}
			entry := readLastTokenUsageEntry(t)
			if entry["session_id"] != "sessA" || entry["agent_name"] != "AgentX" || entry["source"] != "claude-code" {
				t.Errorf("entry = %v, want sessA/AgentX/claude-code", entry)
			}
		})
	}
}

func TestRunNoopBranches(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"invalid JSON", "not json"},
		{"no hook_event_name", `{"session_id":"s1"}`},
		{"Stop event without session id", `{"hook_event_name":"Stop"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			withStdin(t, c.payload)

			if got := Run(nil); got != 0 {
				t.Fatalf("Run() = %d, want 0", got)
			}
			if _, err := os.Stat(filepath.Join(shared.SGDir(), "local-logs")); !os.IsNotExist(err) {
				t.Error("a no-op call created log output")
			}
		})
	}
}

func readLastTokenUsageEntry(t *testing.T) map[string]interface{} {
	t.Helper()
	day := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(shared.SGDir(), "local-logs", "token-usage-"+day+".jsonl")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading token usage log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("unmarshaling last entry: %v", err)
	}
	return entry
}