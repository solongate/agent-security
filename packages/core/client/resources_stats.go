// SPDX-License-Identifier: Apache-2.0

package client

// Split from resources.go: the /stats namespace. See resources_policy.go for
// the file-level rationale.

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// ── /stats ─────────────────────────────────────────────────────────────────

type StatsClient struct{ c *Client }

const (
	msHour = int64(3_600_000)
	msDay  = int64(86_400_000)
)

// Get counts what is RECORDED, which is not the same as what was called: the
// guard records a denial and the post-tool hook records the rest, so a client
// with no post-tool stage leaves denials only. That was true of the service's
// numbers too.
func (s StatsClient) Get(ctx context.Context) (Stats, error) {
	rows := readLog()
	st, _ := readStore()
	tools := map[string]bool{}
	var out Stats
	for _, r := range rows {
		if r.Tool != "" {
			tools[r.Tool] = true
		}
		if r.Decision == "DENY" {
			out.Denied++
		} else {
			out.Allowed++
		}
	}
	out.TotalCalls = len(rows)
	out.RegisteredTools = len(tools)
	if st.Policy != nil {
		out.ActivePolicies = 1
	}
	for i, r := range rows {
		if i >= 20 {
			break
		}
		e := toAuditEntry(r)
		out.RecentActivity = append(out.RecentActivity, struct {
			ID               string   `json:"id"`
			ToolName         string   `json:"tool_name"`
			Decision         string   `json:"decision"`
			TrustLevel       string   `json:"trust_level"`
			EvaluationTimeMs *float64 `json:"evaluation_time_ms"`
			CreatedAt        string   `json:"created_at"`
		}{e.ID, e.ToolName, e.Decision, e.TrustLevel, e.EvaluationTimeMs, e.CreatedAt})
	}
	return out, nil
}

func (s StatsClient) Timeseries(ctx context.Context, period, granularity string) (Timeseries, error) {
	bucketMS := msHour
	if granularity == "1d" {
		bucketMS = msDay
	}
	span := msDay
	switch period {
	case "7d":
		span = 7 * msDay
	case "30d":
		span = 30 * msDay
	case "all":
		span = 0
	}
	now := time.Now().UnixMilli()
	since := int64(0)
	if span > 0 {
		since = now - span
	}

	type bucket struct {
		total, allowed, denied, timed int
		ms                            float64
	}
	buckets := map[int64]*bucket{}
	for _, r := range readLog() {
		if r.at <= 0 || r.at < since {
			continue
		}
		key := (r.at / bucketMS) * bucketMS
		b := buckets[key]
		if b == nil {
			b = &bucket{}
			buckets[key] = b
		}
		b.total++
		if r.Decision == "DENY" {
			b.denied++
		} else {
			b.allowed++
		}
		if r.EvaluationTimeMs != nil {
			b.ms += *r.EvaluationTimeMs
			b.timed++
		}
	}

	keys := make([]int64, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	out := Timeseries{Period: period, Granularity: "hour", Timeseries: []TimeseriesPoint{}}
	if bucketMS == msDay {
		out.Granularity = "day"
	}
	for _, k := range keys {
		b := buckets[k]
		avg := 0.0
		if b.timed > 0 {
			// Averaged over the entries that CARRY a time, not over every entry:
			// an older line without one would pull the average towards zero.
			avg = float64(int((b.ms/float64(b.timed))*10+0.5)) / 10
		}
		out.Timeseries = append(out.Timeseries, TimeseriesPoint{
			Timestamp:    time.UnixMilli(k).UTC().Format(time.RFC3339Nano),
			Total:        b.total,
			Allowed:      b.allowed,
			Denied:       b.denied,
			AvgEvalTimeM: avg,
		})
	}
	return out, nil
}

// Drift groups by the REASON a call was denied rather than by rule id: a local
// record carries the reason the guard gave and not which rule produced it, and
// the reason is what somebody reads anyway.
func (s StatsClient) Drift(ctx context.Context, days int) (Drift, error) {
	if days < 1 {
		days = 7
	}
	span := int64(days) * msDay
	now := time.Now().UnixMilli()

	type agg struct {
		count int
		tool  string
	}
	current, previous := map[string]*agg{}, map[string]*agg{}
	for _, r := range readLog() {
		if r.at <= 0 || r.Decision != "DENY" {
			continue
		}
		age := now - r.at
		var into map[string]*agg
		switch {
		case age <= span:
			into = current
		case age <= span*2:
			into = previous
		default:
			continue
		}
		key := "denied"
		if r.Reason != nil && strings.TrimSpace(*r.Reason) != "" {
			key = strings.TrimSpace(*r.Reason)
		}
		a := into[key]
		if a == nil {
			a = &agg{}
			into[key] = a
		}
		a.count++
		if a.tool == "" {
			a.tool = r.Tool
		}
	}

	out := Drift{Days: days}
	seen := map[string]bool{}
	keys := []string{}
	for _, m := range []map[string]*agg{current, previous} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
	}
	for _, a := range current {
		out.TotalCurrent += a.count
	}
	for _, a := range previous {
		out.TotalPrevious += a.count
	}
	for _, k := range keys {
		cur, prev := 0, 0
		tool := ""
		if a := current[k]; a != nil {
			cur, tool = a.count, a.tool
		}
		if a := previous[k]; a != nil {
			prev = a.count
			if tool == "" {
				tool = a.tool
			}
		}
		reason, lastTool := k, tool
		row := struct {
			RuleID   *string  `json:"rule_id"`
			Reason   *string  `json:"reason"`
			LastTool *string  `json:"last_tool"`
			Current  int      `json:"current"`
			Previous int      `json:"previous"`
			Delta    int      `json:"delta"`
			DeltaPct *float64 `json:"delta_pct"`
			IsNew    bool     `json:"is_new"`
			Spike    bool     `json:"spike"`
		}{Reason: &reason, Current: cur, Previous: prev, Delta: cur - prev, IsNew: prev == 0 && cur > 0, Spike: prev > 0 && cur >= prev*2}
		if lastTool != "" {
			row.LastTool = &lastTool
		}
		// A percentage against zero is not a large increase, it is undefined.
		// IsNew is what says that case out loud.
		if prev > 0 {
			pct := float64(int(float64(cur-prev)/float64(prev)*1000+0.5)) / 10
			row.DeltaPct = &pct
		}
		out.Rules = append(out.Rules, row)
	}
	sort.SliceStable(out.Rules, func(i, j int) bool { return out.Rules[i].Current > out.Rules[j].Current })
	return out, nil
}

// SecurityInsights stays raw JSON, as it was: pinning a struct to it would mean
// this version silently dropping whatever is added next.
//
// `anomalies` are minutes that reached the CONFIGURED limit, never a statistical
// baseline. There is no inference here and there was none in the service either;
// the name is older than the behaviour.
func (s StatsClient) SecurityInsights(ctx context.Context, days int) (json.RawMessage, error) {
	if days < 1 {
		days = 7
	}
	span := int64(days) * msDay
	now := time.Now().UnixMilli()
	st, err := readStore()
	if err != nil {
		return nil, err
	}
	layers := toLayers(st.Security)
	limit := layers.RateLimit.PerMinute

	perMinute, perDay, perAgent, perPattern := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	dlpHits := []map[string]any{}
	scanned := 0
	for _, r := range readLog() {
		if r.at <= 0 || now-r.at > span {
			continue
		}
		scanned++
		agent := "unknown"
		if r.AgentName != nil && *r.AgentName != "" {
			agent = *r.AgentName
		} else if r.AgentID != nil && *r.AgentID != "" {
			agent = *r.AgentID
		}
		perAgent[agent]++
		perDay[time.UnixMilli(r.at).UTC().Format("2006-01-02")]++
		minute := time.UnixMilli((r.at / 60_000) * 60_000).UTC().Format(time.RFC3339)
		perMinute[agent+" "+minute]++
		for _, name := range r.DLP {
			perPattern[name]++
		}
		if len(r.DLP) > 0 || (r.Reason != nil && strings.Contains(strings.ToLower(*r.Reason), "dlp")) {
			if len(dlpHits) < 200 {
				dlp := r.DLP
				if dlp == nil {
					dlp = []string{}
				}
				dlpHits = append(dlpHits, map[string]any{
					"id": r.id, "tool": r.Tool, "decision": toAuditEntry(r).Decision,
					"patterns": dlp, "created_at": toAuditEntry(r).CreatedAt,
				})
			}
		}
	}

	anomalies := []map[string]any{}
	if limit > 0 {
		for _, kv := range sortedCounts(perMinute, 100) {
			if kv.Count < limit {
				continue
			}
			parts := strings.SplitN(kv.Key, " ", 2)
			row := map[string]any{"agent": parts[0], "count": kv.Count, "limit": limit}
			if len(parts) > 1 {
				row["minute"] = parts[1]
			}
			anomalies = append(anomalies, row)
		}
	}

	callsPerDay := []map[string]any{}
	dayKeys := make([]string, 0, len(perDay))
	for k := range perDay {
		dayKeys = append(dayKeys, k)
	}
	sort.Strings(dayKeys)
	for _, k := range dayKeys {
		callsPerDay = append(callsPerDay, map[string]any{"day": k, "count": perDay[k]})
	}

	topAgents := []map[string]any{}
	for _, kv := range sortedCounts(perAgent, 6) {
		topAgents = append(topAgents, map[string]any{"agent": kv.Key, "count": kv.Count})
	}
	byPattern := []map[string]any{}
	for _, kv := range sortedCounts(perPattern, 20) {
		byPattern = append(byPattern, map[string]any{"pattern": kv.Key, "count": kv.Count})
	}

	return json.Marshal(map[string]any{
		"days":             days,
		"layers":           layers,
		"anomalyThreshold": limit,
		"scanned":          scanned,
		"totalCalls":       scanned,
		"limitHistory":     readRateLimitHistory(),
		"anomalies":        anomalies,
		"dlpHits":          dlpHits,
		"callsPerDay":      callsPerDay,
		"topAgents":        topAgents,
		"dlpByPattern":     byPattern,
	})
}