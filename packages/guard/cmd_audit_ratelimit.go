// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

// Split from cmd_audit.go: rate-limit observation and eval-time ring reading
// used by the audit command.

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/shared"
)

func loadRateLimitObserveCfg(sec *shared.Security) *shared.RateLimit {
	if sec == nil {
		return nil
	}
	return sec.RateLimitObserve
}

// rateLimitObserveBurst is a sliding-window burst check for DETECT mode, over
// a SEPARATE stamps file from the guard's enforcement file so observation
// never interferes with blocking. Returns true when this call is at or over
// an enabled window's limit.
func rateLimitObserveBurst(agentKey string, limits *shared.RateLimit) bool {
	if limits == nil {
		return false
	}
	file := filepath.Join(shared.SGDir(), ".ratelimit-observe-"+shared.AgentKey(agentKey)+".json")
	now := time.Now().UnixMilli()

	var stamps []int64
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &stamps)
	}
	filtered := stamps[:0]
	for _, t := range stamps {
		if now-t < 86400000 {
			filtered = append(filtered, t)
		}
	}
	stamps = filtered
	if len(stamps) > 50000 {
		stamps = stamps[len(stamps)-50000:]
	}

	windows := []struct {
		ms  int64
		lim int
	}{
		{86400000, limits.PerDay},
		{3600000, limits.PerHour},
		{60000, limits.PerMinute},
	}
	burst := false
	for _, w := range windows {
		if w.lim <= 0 {
			continue
		}
		count := 0
		for _, t := range stamps {
			if now-t < w.ms {
				count++
			}
		}
		if count >= w.lim {
			burst = true
			break
		}
	}

	stamps = append(stamps, now)
	if b, err := json.Marshal(stamps); err == nil {
		_ = os.WriteFile(file, b, shared.FileMode)
	}
	return burst
}

// readLastEvalMs reads back the policy-eval time the PreToolUse guard
// measured for this tool call, so an ALLOW entry can carry it. Returns nil
// when no matching measurement exists — an unknown eval time is stored as
// null, not a fake 0 that drags averages.
func readLastEvalMs(toolName, sessionID string) *float64 {
	dir := shared.ProjectFlagDir()
	if v := readEvalRing(dir, sessionID); v != nil {
		return v
	}
	return readLastEvalFlag(dir, toolName, sessionID)
}

// readEvalRing averages the recent same-session eval records so that several
// tool calls landing within a moment (a parallel burst) each report the
// burst's mean eval time instead of a blank.
func readEvalRing(dir, sessionID string) (result *float64) {
	defer func() { recover() }()
	b, err := os.ReadFile(filepath.Join(dir, ".eval-ring.jsonl"))
	if err != nil {
		return nil
	}
	now := float64(time.Now().UnixMilli())
	var recent []float64
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		var r struct {
			MS      *float64 `json:"ms"`
			TS      *float64 `json:"ts"`
			Session string   `json:"session"`
		}
		if json.Unmarshal([]byte(line), &r) != nil || r.MS == nil || r.TS == nil {
			continue
		}
		if now-*r.TS > 2500 {
			continue
		}
		if r.Session != "" && sessionID != "" && r.Session != sessionID {
			continue
		}
		recent = append(recent, *r.MS)
	}
	if len(recent) == 0 {
		return nil
	}
	sum := 0.0
	for _, v := range recent {
		sum += v
	}
	avg := math.Round(math.Max(0, sum/float64(len(recent))))
	return &avg
}

func readLastEvalFlag(dir, toolName, sessionID string) (result *float64) {
	defer func() { recover() }()
	b, err := os.ReadFile(filepath.Join(dir, ".last-eval"))
	if err != nil {
		return nil
	}
	var c struct {
		MS      *float64 `json:"ms"`
		TS      *float64 `json:"ts"`
		Tool    *string  `json:"tool"`
		Session string   `json:"session"`
	}
	if json.Unmarshal(b, &c) != nil || c.MS == nil || c.TS == nil {
		return nil
	}
	now := float64(time.Now().UnixMilli())
	if c.Tool != nil {
		if *c.Tool != toolName {
			return nil
		}
		if c.Session != "" && sessionID != "" && c.Session != sessionID {
			return nil
		}
		if now-*c.TS > 2*3600*1000 {
			return nil
		}
		v := math.Round(math.Max(0, *c.MS))
		return &v
	}
	if now-*c.TS < 30000 {
		v := math.Round(math.Max(0, *c.MS))
		return &v
	}
	return nil
}

// jsToNumber mirrors JavaScript's ToNumber coercion for the shapes a decoded
// JSON value can take, which is as much as `toolResponse.exitCode > 0` needs.
func jsToNumber(v interface{}) float64 {
	switch t := v.(type) {
	case nil:
		return 0
	case float64:
		return t
	case bool:
		if t {
			return 1
		}
		return 0
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0
		}
		if f, err := strconv.ParseFloat(s, 64); err == nil {
			return f
		}
		return math.NaN()
	default:
		return math.NaN()
	}
}