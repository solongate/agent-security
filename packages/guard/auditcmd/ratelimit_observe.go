// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package auditcmd

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/guard/ratelimit"
	"github.com/solongate/agent-security/packages/shared"
)

func loadRateLimitObserveCfg(sec *shared.Security) *shared.RateLimit {
	if sec == nil {
		return nil
	}
	return sec.RateLimitObserve
}

func rateLimitObserveBurst(agentKey string, limits *shared.RateLimit) bool {
	return ratelimit.Observe(agentKey, limits)
}

func readLastEvalMs(toolName, sessionID string) *float64 {
	dir := shared.ProjectFlagDir()
	if v := readEvalRing(dir, sessionID); v != nil {
		return v
	}
	return readLastEvalFlag(dir, toolName, sessionID)
}

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