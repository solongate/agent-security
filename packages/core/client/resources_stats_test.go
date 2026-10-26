// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func tsAgo(d time.Duration) string {
	return time.Now().Add(-d).UTC().Format(time.RFC3339Nano)
}

func TestStatsGetCountsAndRecentActivity(t *testing.T) {
	newHome(t)
	writeLogLines(t,
		`{"ts":"2026-01-01T00:00:00Z","tool":"Bash","decision":"ALLOW"}`,
		`{"ts":"2026-01-01T00:01:00Z","tool":"Bash","decision":"DENY"}`,
		`{"ts":"2026-01-01T00:02:00Z","tool":"Write","decision":"ALLOW"}`,
	)
	policy := &PolicySet{ID: "local", Name: "local"}
	if err := writeStore(stored{Policy: policy, envelope: true}); err != nil {
		t.Fatalf("writeStore: %v", err)
	}

	s := StatsClient{&Client{}}
	out, err := s.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.TotalCalls != 3 {
		t.Errorf("TotalCalls = %d, want 3", out.TotalCalls)
	}
	if out.Allowed != 2 || out.Denied != 1 {
		t.Errorf("Allowed/Denied = %d/%d, want 2/1", out.Allowed, out.Denied)
	}
	if out.RegisteredTools != 2 {
		t.Errorf("RegisteredTools = %d, want 2 (Bash, Write)", out.RegisteredTools)
	}
	if out.ActivePolicies != 1 {
		t.Errorf("ActivePolicies = %d, want 1", out.ActivePolicies)
	}
	if len(out.RecentActivity) != 3 {
		t.Fatalf("RecentActivity has %d entries, want 3", len(out.RecentActivity))
	}
	if out.RecentActivity[0].ToolName != "Write" {
		t.Errorf("RecentActivity[0] = %q, want the newest entry (Write)", out.RecentActivity[0].ToolName)
	}
}

func TestStatsGetWithNoLogOrPolicy(t *testing.T) {
	newHome(t)
	s := StatsClient{&Client{}}
	out, err := s.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.TotalCalls != 0 || out.ActivePolicies != 0 {
		t.Errorf("got %+v, want all zero", out)
	}
}

func TestTimeseriesFiltersByPeriod(t *testing.T) {
	newHome(t)
	writeLogLines(t,
		`{"ts":"`+tsAgo(time.Hour)+`","tool":"Bash","decision":"ALLOW","evaluation_time_ms":2.3}`,
		`{"ts":"`+tsAgo(72*time.Hour)+`","tool":"Bash","decision":"DENY"}`,
		`{"ts":"`+tsAgo(40*24*time.Hour)+`","tool":"Bash","decision":"ALLOW"}`,
	)
	s := StatsClient{&Client{}}

	sum := func(period string) (total, denied int) {
		out, err := s.Timeseries(context.Background(), period, "")
		if err != nil {
			t.Fatalf("Timeseries(%q): %v", period, err)
		}
		for _, p := range out.Timeseries {
			total += p.Total
			denied += p.Denied
		}
		return
	}

	if total, _ := sum(""); total != 1 {
		t.Errorf("default (1 day) period total = %d, want 1", total)
	}
	if total, denied := sum("7d"); total != 2 || denied != 1 {
		t.Errorf("7d period total/denied = %d/%d, want 2/1", total, denied)
	}
	if total, _ := sum("30d"); total != 2 {
		t.Errorf("30d period total = %d, want 2 (the 40-day-old entry excluded)", total)
	}
	if total, _ := sum("all"); total != 3 {
		t.Errorf("all period total = %d, want 3", total)
	}
}

func TestTimeseriesGranularityLabelAndAverage(t *testing.T) {
	newHome(t)
	writeLogLines(t, `{"ts":"`+tsAgo(time.Minute)+`","tool":"Bash","decision":"ALLOW","evaluation_time_ms":2.3}`)
	s := StatsClient{&Client{}}

	hourly, err := s.Timeseries(context.Background(), "", "")
	if err != nil {
		t.Fatalf("Timeseries: %v", err)
	}
	if hourly.Granularity != "hour" {
		t.Errorf("Granularity = %q, want hour", hourly.Granularity)
	}
	if len(hourly.Timeseries) != 1 {
		t.Fatalf("got %d points, want 1", len(hourly.Timeseries))
	}
	if hourly.Timeseries[0].AvgEvalTimeM != 2.3 {
		t.Errorf("AvgEvalTimeM = %v, want 2.3", hourly.Timeseries[0].AvgEvalTimeM)
	}

	daily, err := s.Timeseries(context.Background(), "", "1d")
	if err != nil {
		t.Fatalf("Timeseries: %v", err)
	}
	if daily.Granularity != "day" {
		t.Errorf("Granularity = %q, want day", daily.Granularity)
	}
}

func TestDriftComparesCurrentAndPreviousWindows(t *testing.T) {
	newHome(t)
	writeLogLines(t,
		`{"ts":"`+tsAgo(24*time.Hour)+`","tool":"Bash","decision":"DENY","reason":"bad command"}`,
		`{"ts":"`+tsAgo(10*24*time.Hour)+`","tool":"Bash","decision":"DENY","reason":"bad command"}`,
		`{"ts":"`+tsAgo(20*24*time.Hour)+`","tool":"Bash","decision":"DENY","reason":"bad command"}`,
		`{"ts":"`+tsAgo(time.Hour)+`","tool":"Write","decision":"ALLOW"}`,
		`{"ts":"`+tsAgo(2*time.Hour)+`","tool":"Bash","decision":"DENY"}`,
	)
	s := StatsClient{&Client{}}

	out, err := s.Drift(context.Background(), 7)
	if err != nil {
		t.Fatalf("Drift: %v", err)
	}
	if out.Days != 7 {
		t.Errorf("Days = %d, want 7", out.Days)
	}

	var badCommand, denied *struct {
		Current, Previous int
		IsNew, Spike      bool
		DeltaPct          *float64
	}
	for i := range out.Rules {
		r := out.Rules[i]
		row := &struct {
			Current, Previous int
			IsNew, Spike      bool
			DeltaPct          *float64
		}{r.Current, r.Previous, r.IsNew, r.Spike, r.DeltaPct}
		if r.Reason != nil && *r.Reason == "bad command" {
			badCommand = row
		}
		if r.Reason != nil && *r.Reason == "denied" {
			denied = row
		}
	}
	if badCommand == nil {
		t.Fatal("no row for the 'bad command' reason")
	}
	if badCommand.Current != 1 || badCommand.Previous != 1 {
		t.Errorf("bad command current/previous = %d/%d, want 1/1 (the 20-day-old entry is outside both windows)",
			badCommand.Current, badCommand.Previous)
	}
	if badCommand.IsNew {
		t.Error("a reason present in both windows should not be flagged as new")
	}

	if denied == nil {
		t.Fatal("no row for the default 'denied' reason")
	}
	if denied.Current != 1 || denied.Previous != 0 {
		t.Errorf("denied current/previous = %d/%d, want 1/0", denied.Current, denied.Previous)
	}
	if !denied.IsNew {
		t.Error("a reason with no previous occurrences should be flagged as new")
	}
	if denied.DeltaPct != nil {
		t.Error("DeltaPct should be nil when there is nothing in the previous window to divide by")
	}
}

func TestDriftDefaultsDaysWhenNotPositive(t *testing.T) {
	newHome(t)
	s := StatsClient{&Client{}}
	out, err := s.Drift(context.Background(), 0)
	if err != nil {
		t.Fatalf("Drift: %v", err)
	}
	if out.Days != 7 {
		t.Errorf("Days = %d, want the default of 7", out.Days)
	}
}

func TestSecurityInsights(t *testing.T) {
	newHome(t)
	writeLogLines(t,
		`{"ts":"2026-01-01T12:00:00Z","tool":"Bash","decision":"ALLOW","agent_name":"agent-x"}`,
		`{"ts":"2026-01-01T12:00:10Z","tool":"Bash","decision":"ALLOW","agent_name":"agent-x"}`,
		`{"ts":"2026-01-01T12:00:20Z","tool":"Bash","decision":"DENY","agent_name":"agent-x","reason":"rate limit exceeded","rate_limit_burst":true}`,
		`{"ts":"2026-01-02T09:00:00Z","tool":"WebFetch","decision":"DENY","agent_name":"agent-y","dlp":["AWS access key"],"reason":"dlp pattern matched"}`,
		`{"ts":"2026-01-03T09:00:00Z","tool":"Read","decision":"ALLOW","agent_name":"agent-y"}`,
	)

	c := New()
	layers := SecurityLayers{}
	layers.RateLimit.Mode = LayerBlock
	layers.RateLimit.PerMinute = 2
	if _, err := c.Settings.SetSecurityLayers(context.Background(), layers); err != nil {
		t.Fatalf("SetSecurityLayers: %v", err)
	}

	raw, err := c.Stats.SecurityInsights(context.Background(), 100000)
	if err != nil {
		t.Fatalf("SecurityInsights: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out["scanned"].(float64) != 5 {
		t.Errorf("scanned = %v, want 5", out["scanned"])
	}
	if out["anomalyThreshold"].(float64) != 2 {
		t.Errorf("anomalyThreshold = %v, want 2", out["anomalyThreshold"])
	}

	anomalies := out["anomalies"].([]any)
	if len(anomalies) != 1 {
		t.Fatalf("got %d anomalies, want 1", len(anomalies))
	}
	anomaly := anomalies[0].(map[string]any)
	if anomaly["agent"] != "agent-x" || anomaly["count"].(float64) != 3 {
		t.Errorf("anomaly = %+v, want agent-x with count 3", anomaly)
	}
	if anomaly["minute"] != "2026-01-01T12:00:00Z" {
		t.Errorf("minute = %v, want 2026-01-01T12:00:00Z", anomaly["minute"])
	}

	callsPerDay := out["callsPerDay"].([]any)
	if len(callsPerDay) != 3 {
		t.Fatalf("got %d days, want 3", len(callsPerDay))
	}
	first := callsPerDay[0].(map[string]any)
	if first["day"] != "2026-01-01" || first["count"].(float64) != 3 {
		t.Errorf("first day = %+v, want 2026-01-01 with 3 calls", first)
	}

	dlpHits := out["dlpHits"].([]any)
	if len(dlpHits) != 1 {
		t.Fatalf("got %d dlp hits, want 1", len(dlpHits))
	}

	byPattern := out["dlpByPattern"].([]any)
	if len(byPattern) != 1 {
		t.Fatalf("got %d patterns, want 1", len(byPattern))
	}
	pattern := byPattern[0].(map[string]any)
	if pattern["pattern"] != "AWS access key" || pattern["count"].(float64) != 1 {
		t.Errorf("pattern = %+v, want AWS access key with count 1", pattern)
	}

	topAgents := out["topAgents"].([]any)
	if len(topAgents) != 2 {
		t.Fatalf("got %d agents, want 2", len(topAgents))
	}
	top := topAgents[0].(map[string]any)
	if top["agent"] != "agent-x" || top["count"].(float64) != 3 {
		t.Errorf("top agent = %+v, want agent-x with count 3", top)
	}
}

func TestSecurityInsightsAgentNameWithSpaces(t *testing.T) {
	newHome(t)
	writeLogLines(t,
		`{"ts":"2026-01-01T12:00:00Z","tool":"Bash","decision":"ALLOW","agent_name":"Claude Code"}`,
		`{"ts":"2026-01-01T12:00:10Z","tool":"Bash","decision":"ALLOW","agent_name":"Claude Code"}`,
		`{"ts":"2026-01-01T12:00:20Z","tool":"Bash","decision":"DENY","agent_name":"Claude Code","reason":"rate limit exceeded","rate_limit_burst":true}`,
	)

	c := New()
	layers := SecurityLayers{}
	layers.RateLimit.Mode = LayerBlock
	layers.RateLimit.PerMinute = 2
	if _, err := c.Settings.SetSecurityLayers(context.Background(), layers); err != nil {
		t.Fatalf("SetSecurityLayers: %v", err)
	}

	raw, err := c.Stats.SecurityInsights(context.Background(), 100000)
	if err != nil {
		t.Fatalf("SecurityInsights: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	anomalies := out["anomalies"].([]any)
	if len(anomalies) != 1 {
		t.Fatalf("got %d anomalies, want 1", len(anomalies))
	}
	anomaly := anomalies[0].(map[string]any)
	if anomaly["agent"] != "Claude Code" {
		t.Errorf("agent = %v, want Claude Code", anomaly["agent"])
	}
	if anomaly["minute"] != "2026-01-01T12:00:00Z" {
		t.Errorf("minute = %v, want 2026-01-01T12:00:00Z", anomaly["minute"])
	}
	if anomaly["count"].(float64) != 3 {
		t.Errorf("count = %v, want 3", anomaly["count"])
	}
	if anomaly["limit"].(float64) != 2 {
		t.Errorf("limit = %v, want 2", anomaly["limit"])
	}
}

func TestSecurityInsightsDefaultsDaysWhenNotPositive(t *testing.T) {
	newHome(t)
	s := StatsClient{&Client{}}
	raw, err := s.SecurityInsights(context.Background(), 0)
	if err != nil {
		t.Fatalf("SecurityInsights: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out["days"].(float64) != 7 {
		t.Errorf("days = %v, want the default of 7", out["days"])
	}
}