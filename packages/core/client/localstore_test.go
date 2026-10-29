// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/solongate/agent-security/packages/core/config"
	pcrypto "github.com/solongate/agent-security/packages/crypto"
)

func newHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func TestReadStoreWhenPolicyFileIsAbsent(t *testing.T) {
	newHome(t)
	s, err := readStore()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !s.absent {
		t.Error("expected absent to be true when there is no policy file")
	}
	if !s.envelope {
		t.Error("expected envelope to be true for a fresh store")
	}
	if s.Policy != nil {
		t.Error("expected no policy on a fresh store")
	}
}

func TestWriteStoreThenReadStoreRoundTrip(t *testing.T) {
	newHome(t)
	policy := &PolicySet{ID: "local", Name: "local", Rules: Rules{Items: []PolicyRule{
		{ID: "rule-1", Effect: "DENY", ToolPattern: "Bash", Enabled: true},
	}}}
	if err := writeStore(stored{Policy: policy, envelope: true}); err != nil {
		t.Fatalf("writeStore: %v", err)
	}

	s, err := readStore()
	if err != nil {
		t.Fatalf("readStore: %v", err)
	}
	if s.absent {
		t.Error("expected absent to be false after writing")
	}
	if s.Policy == nil {
		t.Fatal("expected a policy to come back")
	}
	if s.Policy.ID != "local" || s.Policy.Name != "local" {
		t.Errorf("policy identity = %q/%q, want local/local", s.Policy.ID, s.Policy.Name)
	}
	if len(s.Policy.Rules.Items) != 1 || s.Policy.Rules.Items[0].ID != "rule-1" {
		t.Errorf("rules did not round-trip: %+v", s.Policy.Rules.Items)
	}
	if s.Version != localVersion {
		t.Errorf("Version = %d, want %d", s.Version, localVersion)
	}
}

func TestWriteStoreFileHasNoTrailingPermissionSurprises(t *testing.T) {
	newHome(t)
	policy := &PolicySet{ID: "local", Name: "local"}
	if err := writeStore(stored{Policy: policy, envelope: true}); err != nil {
		t.Fatalf("writeStore: %v", err)
	}
	if _, err := os.Stat(PolicyPath()); err != nil {
		t.Fatalf("policy file was not written where expected: %v", err)
	}
}

func TestReadStoreRefusesATamperedFile(t *testing.T) {
	newHome(t)
	policy := &PolicySet{ID: "local", Name: "local"}
	if err := writeStore(stored{Policy: policy, envelope: true}); err != nil {
		t.Fatalf("writeStore: %v", err)
	}

	raw, err := os.ReadFile(PolicyPath())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["_v"] = 999.0
	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(PolicyPath(), tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := readStore(); err == nil {
		t.Error("a file edited outside SolonGate was accepted without complaint")
	}
}

func TestToLayersWithNoSecurityIsEverythingOff(t *testing.T) {
	l := toLayers(nil)
	if l.RateLimit.Mode != LayerOff {
		t.Errorf("RateLimit.Mode = %q, want off", l.RateLimit.Mode)
	}
	if l.DLP.Mode != LayerOff {
		t.Errorf("DLP.Mode = %q, want off", l.DLP.Mode)
	}
	if l.DLP.Patterns == nil || l.DLP.Custom == nil {
		t.Error("DLP.Patterns and DLP.Custom should be empty slices, not nil")
	}
}

func TestToLayersAndFromLayersRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   SecurityLayers
	}{
		{"rate limit block", SecurityLayers{RateLimit: struct {
			Mode      LayerMode `json:"mode"`
			PerMinute int       `json:"perMinute"`
			PerHour   int       `json:"perHour"`
			PerDay    int       `json:"perDay"`
		}{Mode: LayerBlock, PerMinute: 5, PerHour: 50, PerDay: 500}}},
		{"rate limit detect", SecurityLayers{RateLimit: struct {
			Mode      LayerMode `json:"mode"`
			PerMinute int       `json:"perMinute"`
			PerHour   int       `json:"perHour"`
			PerDay    int       `json:"perDay"`
		}{Mode: LayerDetect, PerMinute: 1}}},
		{"dlp block with patterns", SecurityLayers{DLP: struct {
			Mode     LayerMode       `json:"mode"`
			Patterns []string        `json:"patterns"`
			Custom   []CustomPattern `json:"custom"`
		}{Mode: LayerBlock, Patterns: []string{"AWS access key"}, Custom: []CustomPattern{{Name: "x", Re: "y"}}}}},
		{"dlp redact", SecurityLayers{DLP: struct {
			Mode     LayerMode       `json:"mode"`
			Patterns []string        `json:"patterns"`
			Custom   []CustomPattern `json:"custom"`
		}{Mode: LayerRedact, Patterns: []string{"JWT"}}}},
		{"dlp detect", SecurityLayers{DLP: struct {
			Mode     LayerMode       `json:"mode"`
			Patterns []string        `json:"patterns"`
			Custom   []CustomPattern `json:"custom"`
		}{Mode: LayerDetect}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sec := fromLayers(c.in, nil)
			out := toLayers(sec)

			wantRateLimitMode := c.in.RateLimit.Mode
			if wantRateLimitMode == "" {
				wantRateLimitMode = LayerOff
			}
			if out.RateLimit.Mode != wantRateLimitMode {
				t.Errorf("RateLimit.Mode = %q, want %q", out.RateLimit.Mode, wantRateLimitMode)
			}
			if c.in.RateLimit.Mode != LayerOff && c.in.RateLimit.Mode != "" {
				if out.RateLimit.PerMinute != c.in.RateLimit.PerMinute || out.RateLimit.PerHour != c.in.RateLimit.PerHour ||
					out.RateLimit.PerDay != c.in.RateLimit.PerDay {
					t.Errorf("rate limit numbers = %+v, want %+v", out.RateLimit, c.in.RateLimit)
				}
			}

			wantDLPMode := c.in.DLP.Mode
			if wantDLPMode == "" {
				wantDLPMode = LayerOff
			}
			if out.DLP.Mode != wantDLPMode {
				t.Errorf("DLP.Mode = %q, want %q", out.DLP.Mode, wantDLPMode)
			}
		})
	}
}

func TestFromLayersPreservesLocalLogsFromKeep(t *testing.T) {
	keep := &guardSecurity{LocalLogs: &localLogsBlock{Enabled: true, Path: "/var/log/solongate"}}
	out := fromLayers(SecurityLayers{}, keep)
	if out.LocalLogs == nil || out.LocalLogs.Path != "/var/log/solongate" {
		t.Errorf("LocalLogs was not carried over from keep: %+v", out.LocalLogs)
	}
}

func TestHashOfIsStableAndChangesWithRules(t *testing.T) {
	p1 := &PolicySet{Rules: Rules{Items: []PolicyRule{{ID: "rule-1", ToolPattern: "Bash"}}}}
	p2 := &PolicySet{Rules: Rules{Items: []PolicyRule{{ID: "rule-1", ToolPattern: "Bash"}}}}
	p3 := &PolicySet{Rules: Rules{Items: []PolicyRule{{ID: "rule-1", ToolPattern: "Write"}}}}

	h1, h2, h3 := hashOf(p1), hashOf(p2), hashOf(p3)
	if h1 == "" {
		t.Fatal("hashOf returned an empty hash")
	}
	if h1 != h2 {
		t.Errorf("identical rules hashed differently: %q vs %q", h1, h2)
	}
	if h1 == h3 {
		t.Error("different rules hashed the same")
	}
	if len(h1) != 16 {
		t.Errorf("hash is %d characters, want 16", len(h1))
	}
}

func TestResolveID(t *testing.T) {
	p := &PolicySet{ID: "abc123", Name: "myteam"}
	cases := []struct {
		name    string
		id      string
		policy  *PolicySet
		wantErr bool
	}{
		{"no policy at all", "anything", nil, true},
		{"empty id matches anything", "", p, false},
		{"matches id", "abc123", p, false},
		{"matches literal local", "local", p, false},
		{"matches name", "myteam", p, false},
		{"matches nothing", "someone-else", p, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := resolveID(c.id, c.policy)
			if (err != nil) != c.wantErr {
				t.Errorf("resolveID(%q)=%v, wantErr=%v", c.id, err, c.wantErr)
			}
		})
	}
}

func TestNextRuleID(t *testing.T) {
	cases := []struct {
		name  string
		rules []PolicyRule
		want  string
	}{
		{"no rules", nil, "rule-1"},
		{"sequential", []PolicyRule{{ID: "rule-1"}, {ID: "rule-2"}}, "rule-3"},
		{"a gap", []PolicyRule{{ID: "rule-1"}, {ID: "rule-5"}}, "rule-6"},
		{"non-matching ids are ignored", []PolicyRule{{ID: "custom-id"}, {ID: "rule-2"}}, "rule-3"},
		{"out of order", []PolicyRule{{ID: "rule-9"}, {ID: "rule-1"}}, "rule-10"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nextRuleID(c.rules); got != c.want {
				t.Errorf("nextRuleID=%q, want %q", got, c.want)
			}
		})
	}
}

func writeLogLines(t *testing.T, lines ...string) {
	t.Helper()
	file := localLogFile()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadLogReversesOrderAndSkipsBadLines(t *testing.T) {
	newHome(t)
	writeLogLines(t,
		`{"ts":"2026-01-01T00:00:00Z","tool":"Bash","decision":"ALLOW"}`,
		`not json at all`,
		``,
		`{"ts":"2026-01-01T00:01:00Z","tool":"Write","decision":"DENY"}`,
	)

	rows := readLog()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Tool != "Write" || rows[1].Tool != "Bash" {
		t.Errorf("rows are not newest-first: %+v", rows)
	}
	if rows[0].id != "4" {
		t.Errorf("the Write row's id = %q, want %q (its 1-based line number)", rows[0].id, "4")
	}
	if rows[1].id != "1" {
		t.Errorf("the Bash row's id = %q, want %q", rows[1].id, "1")
	}
}

func TestReadLogWithNoFileReturnsNil(t *testing.T) {
	newHome(t)
	if rows := readLog(); rows != nil {
		t.Errorf("expected nil rows with no log file, got %v", rows)
	}
}

// Issue #224: when the 16MB cut lands right after a newline it already
// starts a complete entry, and skipping on to the next newline dropped it.
func TestReadLogKeepsTheFirstEntryWhenTheCutIsOnALineBoundary(t *testing.T) {
	newHome(t)
	const width = 128 // divides maxLogBytes, so the cut lands on a line start
	const before = 2
	n := maxLogBytes/width + before

	var b strings.Builder
	for i := 0; i < n; i++ {
		line := fmt.Sprintf(`{"ts":"2026-01-01T00:00:00Z","tool":"T%07d","decision":"ALLOW"}`, i)
		line += strings.Repeat(" ", width-1-len(line))
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if b.Len() != n*width {
		t.Fatalf("test setup: %d bytes, want %d", b.Len(), n*width)
	}
	file := localLogFile()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	rows := readLog()
	if want := maxLogBytes / width; len(rows) != want {
		t.Fatalf("got %d rows, want %d (every entry inside the 16MB window)", len(rows), want)
	}
	oldest := rows[len(rows)-1]
	if want := fmt.Sprintf("T%07d", before); oldest.Tool != want {
		t.Errorf("oldest kept row is %q, want %q", oldest.Tool, want)
	}
	if want := fmt.Sprint(before + 1); oldest.id != want {
		t.Errorf("oldest kept row's id = %q, want %q (its 1-based line number)", oldest.id, want)
	}
}

func TestToAuditEntryFillsInDefaults(t *testing.T) {
	l := logLine{id: "7", at: 1700000000000}
	e := toAuditEntry(l)
	if e.Decision != "ALLOW" {
		t.Errorf("Decision = %q, want ALLOW", e.Decision)
	}
	if e.Permission != "READ" {
		t.Errorf("Permission = %q, want READ", e.Permission)
	}
	if e.DLPMatches == nil {
		t.Error("DLPMatches should default to an empty slice, not nil")
	}
	wantCreated := time.UnixMilli(1700000000000).UTC().Format(time.RFC3339Nano)
	if e.CreatedAt != wantCreated {
		t.Errorf("CreatedAt = %q, want %q (derived from the timestamp)", e.CreatedAt, wantCreated)
	}
}

func TestToAuditEntryKeepsExplicitValues(t *testing.T) {
	reason := "blocked by rule-1"
	l := logLine{id: "1", TS: "2026-02-02T00:00:00Z", Decision: "DENY", Permission: "WRITE", Reason: &reason, DLP: []string{"JWT"}}
	e := toAuditEntry(l)
	if e.Decision != "DENY" || e.Permission != "WRITE" {
		t.Errorf("explicit decision/permission were overwritten: %q/%q", e.Decision, e.Permission)
	}
	if e.CreatedAt != "2026-02-02T00:00:00Z" {
		t.Errorf("CreatedAt = %q, want the original timestamp", e.CreatedAt)
	}
	if len(e.DLPMatches) != 1 || e.DLPMatches[0] != "JWT" {
		t.Errorf("DLPMatches = %v, want [JWT]", e.DLPMatches)
	}
}

func TestReadRateLimitHistoryWithNoFile(t *testing.T) {
	newHome(t)
	if got := readRateLimitHistory(); len(got) != 0 {
		t.Errorf("expected no history, got %v", got)
	}
}

func TestReadRateLimitHistoryCapsAtTwoHundred(t *testing.T) {
	newHome(t)
	entries := make([]RateLimitChange, 250)
	for i := range entries {
		entries[i] = RateLimitChange{TS: int64(i), Minute: i}
	}
	body, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(config.Dir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(historyPath(), body, 0o600); err != nil {
		t.Fatal(err)
	}

	got := readRateLimitHistory()
	if len(got) != 200 {
		t.Fatalf("got %d entries, want 200", len(got))
	}
	if got[0].Minute != 0 {
		t.Errorf("first entry's Minute = %d, want 0 (the file order is kept)", got[0].Minute)
	}
}

func TestRecordRateLimitChangeDedupesIdenticalEntries(t *testing.T) {
	newHome(t)
	layers := SecurityLayers{}
	layers.RateLimit.PerMinute, layers.RateLimit.PerHour, layers.RateLimit.PerDay = 10, 100, 1000

	recordRateLimitChange(layers)
	recordRateLimitChange(layers)
	if got := readRateLimitHistory(); len(got) != 1 {
		t.Fatalf("recording the same limits twice produced %d entries, want 1", len(got))
	}

	layers.RateLimit.PerMinute = 20
	recordRateLimitChange(layers)
	got := readRateLimitHistory()
	if len(got) != 2 {
		t.Fatalf("recording a change produced %d entries, want 2", len(got))
	}
	if got[0].Minute != 20 {
		t.Errorf("newest entry is not first: %+v", got[0])
	}
}

func TestSortedCountsOrdersByCountThenKey(t *testing.T) {
	m := map[string]int{"b": 2, "a": 2, "c": 5, "d": 1}
	got := sortedCounts(m, 0)
	want := []string{"c", "a", "b", "d"}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i, k := range want {
		if got[i].Key != k {
			t.Errorf("position %d = %q, want %q (full: %+v)", i, got[i].Key, k, got)
		}
	}
}

func TestSortedCountsRespectsLimit(t *testing.T) {
	m := map[string]int{"a": 1, "b": 2, "c": 3}
	if got := sortedCounts(m, 2); len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got := sortedCounts(m, 0); len(got) != 3 {
		t.Fatalf("a limit of 0 should mean no limit, got %d entries", len(got))
	}
}

func TestMirrorRulesIntoDefaultVariantHandlesNilAndNoVariants(t *testing.T) {
	mirrorRulesIntoDefaultVariant(nil)

	p := &PolicySet{Rules: Rules{Items: []PolicyRule{{ID: "rule-1"}}}}
	mirrorRulesIntoDefaultVariant(p)
	if len(p.Variants) != 0 {
		t.Error("a policy with no variants should stay that way")
	}
}

func TestMirrorRulesIntoDefaultVariantPicksTheDefault(t *testing.T) {
	p := &PolicySet{
		Rules:          Rules{Items: []PolicyRule{{ID: "rule-new"}}},
		DefaultVariant: "v2",
		Variants: []PolicyVariant{
			{ID: "v1", Rules: Rules{Items: []PolicyRule{{ID: "rule-old-1"}}}},
			{ID: "v2", Rules: Rules{Items: []PolicyRule{{ID: "rule-old-2"}}}},
		},
	}
	mirrorRulesIntoDefaultVariant(p)
	if len(p.Variants[1].Rules.Items) != 1 || p.Variants[1].Rules.Items[0].ID != "rule-new" {
		t.Errorf("the default variant (v2) did not receive the new rules: %+v", p.Variants[1].Rules.Items)
	}
	if len(p.Variants[0].Rules.Items) != 1 || p.Variants[0].Rules.Items[0].ID != "rule-old-1" {
		t.Errorf("a non-default variant was mutated: %+v", p.Variants[0].Rules.Items)
	}
}

func TestMirrorRulesIntoDefaultVariantFallsBackWhenDefaultIsUnknown(t *testing.T) {
	p := &PolicySet{
		Rules:          Rules{Items: []PolicyRule{{ID: "rule-new"}}},
		DefaultVariant: "does-not-exist",
		Variants: []PolicyVariant{
			{ID: "v1", Rules: Rules{Items: []PolicyRule{{ID: "rule-old"}}}},
		},
	}
	mirrorRulesIntoDefaultVariant(p)
	if len(p.Variants[0].Rules.Items) != 1 || p.Variants[0].Rules.Items[0].ID != "rule-new" {
		t.Errorf("an unknown DefaultVariant should fall back to index 0, got %+v", p.Variants[0].Rules.Items)
	}
}

func TestVersionOnDiskAndNewerThanThisBuild(t *testing.T) {
	newHome(t)
	if v := VersionOnDisk(); v != 0 {
		t.Errorf("VersionOnDisk with no file = %d, want 0", v)
	}
	if v, newer := NewerThanThisBuild(); v != 0 || newer {
		t.Errorf("NewerThanThisBuild with no file = (%d, %v), want (0, false)", v, newer)
	}

	kp, err := pcrypto.LoadOrCreateKeyPair(cryptoDir())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := pcrypto.SignDocument(kp, map[string]any{"_v": 2})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(config.Dir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(PolicyPath(), body, 0o600); err != nil {
		t.Fatal(err)
	}

	if v := VersionOnDisk(); v != 2 {
		t.Errorf("VersionOnDisk = %d, want 2", v)
	}
	if v, newer := NewerThanThisBuild(); v != 2 || !newer {
		t.Errorf("NewerThanThisBuild = (%d, %v), want (2, true)", v, newer)
	}
}