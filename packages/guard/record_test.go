// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/solongate/agent-security/packages/shared"
)

func TestObservingDLPWithNilSecurityReturnsNil(t *testing.T) {
	if got := observingDLP(nil); got != nil {
		t.Errorf("observingDLP(nil) = %+v, want nil", got)
	}
}

func TestObservingDLPPrefersRedactOverObserve(t *testing.T) {
	sec := &shared.Security{
		DLPRedact:  &shared.DLPConfig{Patterns: []string{"redact"}},
		DLPObserve: &shared.DLPConfig{Patterns: []string{"observe"}},
	}
	got := observingDLP(sec)
	if got == nil || got.mode != "redact" || got.cfg != sec.DLPRedact {
		t.Errorf("got %+v, want the redact config", got)
	}
}

func TestObservingDLPFallsBackToObserve(t *testing.T) {
	sec := &shared.Security{DLPObserve: &shared.DLPConfig{Patterns: []string{"observe"}}}
	got := observingDLP(sec)
	if got == nil || got.mode != "detect" || got.cfg != sec.DLPObserve {
		t.Errorf("got %+v, want the observe config in detect mode", got)
	}
}

func TestObservingDLPWithNeitherConfiguredReturnsNil(t *testing.T) {
	if got := observingDLP(&shared.Security{}); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func auditLogPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(shared.SGDir(), "local-logs", "solongate-audit.jsonl")
}

func readAuditEntries(t *testing.T) []map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile(auditLogPath(t))
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	var out []map[string]interface{}
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line is not valid json: %v (%q)", err, line)
		}
		out = append(out, m)
	}
	return out
}

func TestRecordWritesADenyEntryAndADenyFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	c := call{Tool: "Bash", Args: map[string]interface{}{"command": "rm -rf /"}, SessionID: "s1", CallID: "call-1"}
	record(nil, false, c, "claude-code", "claude", "too dangerous", time.Now())

	entries := readAuditEntries(t)
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1", len(entries))
	}
	e := entries[0]
	if e["decision"] != "DENY" || e["reason"] != "too dangerous" || e["tool"] != "Bash" {
		t.Errorf("entry = %v", e)
	}
	if e["session_id"] != "s1" {
		t.Errorf("session_id = %v, want s1", e["session_id"])
	}

	flagPath := filepath.Join(shared.ProjectFlagDir(), ".last-deny")
	fb, err := os.ReadFile(flagPath)
	if err != nil {
		t.Fatalf("reading deny flag: %v", err)
	}
	var flag map[string]interface{}
	if err := json.Unmarshal(fb, &flag); err != nil {
		t.Fatalf("deny flag is not valid json: %v", err)
	}
	if flag["tool"] != "Bash" || flag["id"] != "call-1" {
		t.Errorf("deny flag = %v", flag)
	}
}

func TestRecordObservedSkipsWhenTheActiveClientReportsAfter(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	orig := activeClient
	activeClient = clients["claude-code"] // ReportsAfter: true
	defer func() { activeClient = orig }()

	c := call{Tool: "Read"}
	recordObserved(nil, false, c, "claude-code", "claude", "observed", time.Now())

	if _, err := os.Stat(auditLogPath(t)); err == nil {
		t.Error("recordObserved wrote a log entry even though the active client reports after")
	}
}

func TestRecordObservedWritesAnAllowEntryWhenNotReportingAfter(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	orig := activeClient
	activeClient = clients["generic"] // ReportsAfter: false
	defer func() { activeClient = orig }()

	c := call{Tool: "Read", SessionID: "s2"}
	recordObserved(nil, false, c, "generic", "generic", "detected a secret", time.Now())

	entries := readAuditEntries(t)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0]["decision"] != "ALLOW" || entries[0]["reason"] != "detected a secret" {
		t.Errorf("entry = %v", entries[0])
	}
}

func TestRecordDecisionIncludesAllExpectedFields(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	c := call{
		Tool:      "Write",
		Args:      map[string]interface{}{"file_path": "/a"},
		SessionID: "s3",
	}
	started := time.Now().Add(-10 * time.Millisecond)
	recordDecision(nil, false, c, "codex", "codex-agent", "a reason", "DENY", started)

	entries := readAuditEntries(t)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	e := entries[0]
	wantKeys := []string{
		"tool", "arguments", "decision", "reason", "permission",
		"source", "agent_id", "agent_name", "session_id", "evaluation_time_ms", "ts",
	}
	for _, k := range wantKeys {
		if _, ok := e[k]; !ok {
			t.Errorf("entry is missing key %q: %v", k, e)
		}
	}
	if e["source"] != "codex-guard" {
		t.Errorf("source = %v, want codex-guard", e["source"])
	}
	if e["permission"] != "WRITE" {
		t.Errorf("permission = %v, want WRITE", e["permission"])
	}
	if ms, ok := e["evaluation_time_ms"].(float64); !ok || ms < 0 {
		t.Errorf("evaluation_time_ms = %v, want a non-negative number", e["evaluation_time_ms"])
	}
}

func TestRecordDecisionRespectsACustomLocalLogsDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	custom := filepath.Join(t.TempDir(), "custom-logs")

	sec := &shared.Security{LocalLogs: &shared.LocalLogs{Enabled: true, Path: custom}}
	c := call{Tool: "Edit"}
	recordDecision(sec, true, c, "claude-code", "claude", "r", "ALLOW", time.Now())

	if _, err := os.Stat(filepath.Join(custom, "solongate-audit.jsonl")); err != nil {
		t.Errorf("expected a log in the custom dir: %v", err)
	}
}