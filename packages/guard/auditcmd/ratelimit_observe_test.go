// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package auditcmd

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/solongate/agent-security/packages/shared"
)

func TestLoadRateLimitObserveCfg(t *testing.T) {
	if got := loadRateLimitObserveCfg(nil); got != nil {
		t.Errorf("loadRateLimitObserveCfg(nil) = %v, want nil", got)
	}
	limits := &shared.RateLimit{PerMinute: 5}
	sec := &shared.Security{RateLimitObserve: limits}
	if got := loadRateLimitObserveCfg(sec); got != limits {
		t.Errorf("loadRateLimitObserveCfg() = %v, want %v", got, limits)
	}
}

func seedRateLimitStamps(t *testing.T, agentKey string, stamps []int64) {
	t.Helper()
	file := filepath.Join(shared.SGDir(), ".ratelimit-observe-"+shared.AgentKey(agentKey)+".json")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(stamps)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readRateLimitStamps(t *testing.T, agentKey string) []int64 {
	t.Helper()
	file := filepath.Join(shared.SGDir(), ".ratelimit-observe-"+shared.AgentKey(agentKey)+".json")
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var stamps []int64
	if err := json.Unmarshal(b, &stamps); err != nil {
		t.Fatal(err)
	}
	return stamps
}

func TestRateLimitObserveBurstNilLimitsIsANoop(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if got := rateLimitObserveBurst("agent1", nil); got {
		t.Error("rateLimitObserveBurst(nil limits) = true, want false")
	}
	file := filepath.Join(shared.SGDir(), ".ratelimit-observe-"+shared.AgentKey("agent1")+".json")
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Error("nil limits still wrote a rate-limit file")
	}
}

func TestRateLimitObserveBurstThresholds(t *testing.T) {
	now := time.Now().UnixMilli()
	cases := []struct {
		name   string
		stamps []int64
		limits *shared.RateLimit
		want   bool
	}{
		{
			"per-minute threshold crossed",
			[]int64{now - 1000, now - 2000, now - 3000},
			&shared.RateLimit{PerMinute: 3},
			true,
		},
		{
			"per-minute threshold not reached",
			[]int64{now - 1000, now - 2000},
			&shared.RateLimit{PerMinute: 3},
			false,
		},
		{
			"per-hour threshold crossed by entries outside the minute window",
			[]int64{now - 5*60*1000, now - 10*60*1000, now - 15*60*1000},
			&shared.RateLimit{PerHour: 3},
			true,
		},
		{
			"per-day threshold crossed by entries outside the hour window",
			[]int64{now - 2*3600*1000, now - 3*3600*1000, now - 4*3600*1000},
			&shared.RateLimit{PerDay: 3},
			true,
		},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			agentKey := "agent-thresh"

			seedRateLimitStamps(t, agentKey, c.stamps)
			if got := rateLimitObserveBurst(agentKey, c.limits); got != c.want {
				t.Errorf("case %d: rateLimitObserveBurst() = %v, want %v", i, got, c.want)
			}

			after := readRateLimitStamps(t, agentKey)
			if len(after) != len(c.stamps)+1 {
				t.Errorf("case %d: stamps after call = %d, want %d (seeded + the new one)", i, len(after), len(c.stamps)+1)
			}
		})
	}
}

func TestRateLimitObserveBurstAgesOutOldTimestamps(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	agentKey := "agent-aging"

	now := time.Now().UnixMilli()
	stale := now - 90000000 // more than 24h ago
	seedRateLimitStamps(t, agentKey, []int64{stale})

	if got := rateLimitObserveBurst(agentKey, &shared.RateLimit{PerDay: 1}); got {
		t.Error("a stale timestamp outside the 24h window still counted toward the burst")
	}

	after := readRateLimitStamps(t, agentKey)
	for _, s := range after {
		if s == stale {
			t.Errorf("the stale timestamp %d survived into the persisted file: %v", stale, after)
		}
	}
	if len(after) != 1 {
		t.Errorf("stamps after call = %v, want exactly the freshly appended one", after)
	}
}

func TestReadLastEvalMsUsesProjectFlagDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := shared.ProjectFlagDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := float64(time.Now().UnixMilli())
	flag := map[string]interface{}{"ms": 42.0, "ts": now, "tool": "Read", "session": "s1"}
	b, _ := json.Marshal(flag)
	if err := os.WriteFile(filepath.Join(dir, ".last-eval"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	got := readLastEvalMs("Read", "s1")
	if got == nil || *got != 42 {
		t.Errorf("readLastEvalMs() = %v, want 42", got)
	}
}

func writeRingFile(t *testing.T, dir string, lines []string) {
	t.Helper()
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, ".eval-ring.jsonl"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadEvalRing(t *testing.T) {
	now := float64(time.Now().UnixMilli())

	cases := []struct {
		name      string
		lines     []string
		sessionID string
		wantNil   bool
		want      float64
	}{
		{
			"two recent entries average",
			[]string{
				`{"ms":100,"ts":` + f64(now-500) + `,"session":"s1"}`,
				`{"ms":200,"ts":` + f64(now-500) + `,"session":"s1"}`,
			},
			"s1", false, 150,
		},
		{
			"entry outside the 2500ms window is excluded",
			[]string{`{"ms":100,"ts":` + f64(now-5000) + `,"session":"s1"}`},
			"s1", true, 0,
		},
		{
			"mismatched non-empty sessions are excluded",
			[]string{`{"ms":100,"ts":` + f64(now-500) + `,"session":"s2"}`},
			"s1", true, 0,
		},
		{
			"an empty recorded session matches any caller session",
			[]string{`{"ms":100,"ts":` + f64(now-500) + `,"session":""}`},
			"s1", false, 100,
		},
		{
			"an empty caller session matches any recorded session",
			[]string{`{"ms":100,"ts":` + f64(now-500) + `,"session":"s2"}`},
			"", false, 100,
		},
		{
			"a malformed line is skipped, a valid one still counts",
			[]string{`not json`, `{"ms":100,"ts":` + f64(now-500) + `,"session":"s1"}`},
			"s1", false, 100,
		},
		{
			"no file at all",
			nil, "s1", true, 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if c.lines != nil {
				writeRingFile(t, dir, c.lines)
			}
			got := readEvalRing(dir, c.sessionID)
			if c.wantNil {
				if got != nil {
					t.Errorf("readEvalRing() = %v, want nil", *got)
				}
				return
			}
			if got == nil || *got != c.want {
				t.Errorf("readEvalRing() = %v, want %v", got, c.want)
			}
		})
	}
}

func f64(v float64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestReadLastEvalFlag(t *testing.T) {
	now := float64(time.Now().UnixMilli())

	cases := []struct {
		name      string
		flag      map[string]interface{}
		toolName  string
		sessionID string
		wantNil   bool
		want      float64
	}{
		{
			"tool and session match, within 2h",
			map[string]interface{}{"ms": 50.0, "ts": now, "tool": "Read", "session": "s1"},
			"Read", "s1", false, 50,
		},
		{
			"tool mismatch",
			map[string]interface{}{"ms": 50.0, "ts": now, "tool": "Write", "session": "s1"},
			"Read", "s1", true, 0,
		},
		{
			"session mismatch",
			map[string]interface{}{"ms": 50.0, "ts": now, "tool": "Read", "session": "s2"},
			"Read", "s1", true, 0,
		},
		{
			"tool matches but outside the 2h window",
			map[string]interface{}{"ms": 50.0, "ts": now - float64(3*3600*1000), "tool": "Read", "session": "s1"},
			"Read", "s1", true, 0,
		},
		{
			"no tool field, within 30s",
			map[string]interface{}{"ms": 50.0, "ts": now - 1000},
			"Read", "s1", false, 50,
		},
		{
			"no tool field, older than 30s",
			map[string]interface{}{"ms": 50.0, "ts": now - 40000},
			"Read", "s1", true, 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			b, _ := json.Marshal(c.flag)
			if err := os.WriteFile(filepath.Join(dir, ".last-eval"), b, 0o600); err != nil {
				t.Fatal(err)
			}
			got := readLastEvalFlag(dir, c.toolName, c.sessionID)
			if c.wantNil {
				if got != nil {
					t.Errorf("readLastEvalFlag() = %v, want nil", *got)
				}
				return
			}
			if got == nil || *got != c.want {
				t.Errorf("readLastEvalFlag() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestReadLastEvalFlagWithNoFile(t *testing.T) {
	dir := t.TempDir()
	if got := readLastEvalFlag(dir, "Read", "s1"); got != nil {
		t.Errorf("readLastEvalFlag(no file) = %v, want nil", *got)
	}
}

func TestJsToNumber(t *testing.T) {
	cases := []struct {
		name    string
		in      interface{}
		want    float64
		wantNaN bool
	}{
		{"nil", nil, 0, false},
		{"float64", 5.5, 5.5, false},
		{"bool true", true, 1, false},
		{"bool false", false, 0, false},
		{"numeric string", "5", 5, false},
		{"numeric string with whitespace", " 5 ", 5, false},
		{"empty string", "", 0, false},
		{"non-numeric string", "abc", 0, true},
		{"other type", []interface{}{1, 2}, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := jsToNumber(c.in)
			if c.wantNaN {
				if !math.IsNaN(got) {
					t.Errorf("jsToNumber(%v) = %v, want NaN", c.in, got)
				}
				return
			}
			if got != c.want {
				t.Errorf("jsToNumber(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}