// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

import (
	"context"
	"strings"
	"testing"
)

func seedAuditLog(t *testing.T) {
	t.Helper()
	writeLogLines(t,
		`{"ts":"2026-01-01T00:00:00Z","tool":"Bash","decision":"ALLOW","agent_name":"agent-a","session_id":"s1"}`,
		`{"ts":"2026-01-01T01:00:00Z","tool":"WebFetch","decision":"DENY","reason":"dlp pattern matched","agent_name":"agent-b","session_id":"s2","dlp":["AWS access key"]}`,
		`{"ts":"2026-01-01T02:00:00Z","tool":"Write","decision":"DENY","reason":"rate limit exceeded","rate_limit_burst":true,"agent_name":"agent-a","session_id":"s1"}`,
		`{"ts":"2026-01-01T03:00:00Z","tool":"Read","decision":"ALLOW","agent_name":"agent-c","session_id":"s3"}`,
	)
}

func TestAuditListNoFilterReturnsEverythingNewestFirst(t *testing.T) {
	newHome(t)
	seedAuditLog(t)
	a := Audit{&Client{}}

	out, err := a.List(context.Background(), AuditQuery{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if out.Total != 4 || len(out.Entries) != 4 {
		t.Fatalf("Total=%d len(Entries)=%d, want 4 and 4", out.Total, len(out.Entries))
	}
	if out.Entries[0].ToolName != "Read" {
		t.Errorf("first entry = %q, want the newest (Read)", out.Entries[0].ToolName)
	}
	if out.Limit != 50 {
		t.Errorf("default Limit = %d, want 50", out.Limit)
	}
}

func TestAuditListFiltersByDecision(t *testing.T) {
	newHome(t)
	seedAuditLog(t)
	a := Audit{&Client{}}

	out, err := a.List(context.Background(), AuditQuery{Filter: "DENIED"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if out.Total != 2 {
		t.Fatalf("Total=%d, want 2", out.Total)
	}
	for _, e := range out.Entries {
		if e.Decision != "DENY" {
			t.Errorf("entry %+v does not have decision DENY", e)
		}
	}
}

func TestAuditListFiltersByToolCaseInsensitively(t *testing.T) {
	newHome(t)
	seedAuditLog(t)
	a := Audit{&Client{}}

	out, err := a.List(context.Background(), AuditQuery{Tool: "web"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if out.Total != 1 || out.Entries[0].ToolName != "WebFetch" {
		t.Fatalf("got %+v, want just WebFetch", out.Entries)
	}
}

func TestAuditListFiltersByAgentName(t *testing.T) {
	newHome(t)
	seedAuditLog(t)
	a := Audit{&Client{}}

	out, err := a.List(context.Background(), AuditQuery{AgentName: "agent-a"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if out.Total != 2 {
		t.Fatalf("Total=%d, want 2 (Bash and Write)", out.Total)
	}
}

func TestAuditListFiltersBySessionID(t *testing.T) {
	newHome(t)
	seedAuditLog(t)
	a := Audit{&Client{}}

	out, err := a.List(context.Background(), AuditQuery{SessionID: "s2"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if out.Total != 1 || out.Entries[0].ToolName != "WebFetch" {
		t.Fatalf("got %+v, want just the s2 entry", out.Entries)
	}
}

func TestAuditListFiltersBySignal(t *testing.T) {
	newHome(t)
	seedAuditLog(t)
	a := Audit{&Client{}}

	dlpOut, err := a.List(context.Background(), AuditQuery{Signal: "dlp"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if dlpOut.Total != 1 || dlpOut.Entries[0].ToolName != "WebFetch" {
		t.Fatalf("dlp signal got %+v, want just WebFetch", dlpOut.Entries)
	}

	rlOut, err := a.List(context.Background(), AuditQuery{Signal: "ratelimit"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if rlOut.Total != 1 || rlOut.Entries[0].ToolName != "Write" {
		t.Fatalf("ratelimit signal got %+v, want just Write", rlOut.Entries)
	}
}

func TestAuditListFiltersBySearch(t *testing.T) {
	newHome(t)
	seedAuditLog(t)
	a := Audit{&Client{}}

	out, err := a.List(context.Background(), AuditQuery{Search: "exceeded"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if out.Total != 1 || out.Entries[0].ToolName != "Write" {
		t.Fatalf("got %+v, want just the entry whose reason contains 'exceeded'", out.Entries)
	}
}

func TestAuditListPaginates(t *testing.T) {
	newHome(t)
	seedAuditLog(t)
	a := Audit{&Client{}}

	out, err := a.List(context.Background(), AuditQuery{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if out.Total != 4 {
		t.Errorf("Total=%d, want 4 (unaffected by pagination)", out.Total)
	}
	if len(out.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(out.Entries))
	}
	if out.Entries[0].ToolName != "Write" {
		t.Errorf("offset 1 of the newest-first list = %q, want Write", out.Entries[0].ToolName)
	}
}

func TestAuditListClampsLimitAndOffset(t *testing.T) {
	newHome(t)
	seedAuditLog(t)
	a := Audit{&Client{}}

	out, err := a.List(context.Background(), AuditQuery{Limit: 5000, Offset: -5})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if out.Limit != 1000 {
		t.Errorf("Limit = %d, want clamped to 1000", out.Limit)
	}
	if out.Offset != 0 {
		t.Errorf("Offset = %d, want clamped to 0", out.Offset)
	}
}

func TestAuditListOffsetPastEndReturnsNoEntries(t *testing.T) {
	newHome(t)
	seedAuditLog(t)
	a := Audit{&Client{}}

	out, err := a.List(context.Background(), AuditQuery{Offset: 100})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out.Entries) != 0 {
		t.Errorf("got %d entries past the end, want 0", len(out.Entries))
	}
}

func TestRuleSpecForRequiresATool(t *testing.T) {
	if _, err := RuleSpecFor("", nil, "exact", "DENY"); err == nil {
		t.Error("an empty tool name should be rejected")
	}
	if _, err := RuleSpecFor("   ", nil, "exact", "DENY"); err == nil {
		t.Error("a blank tool name should be rejected")
	}
}

func TestRuleSpecForNonExactScopeIgnoresArguments(t *testing.T) {
	spec, err := RuleSpecFor("Bash", []byte(`{"command":"rm -rf /"}`), "tool", "DENY")
	if err != nil {
		t.Fatalf("RuleSpecFor: %v", err)
	}
	if spec.Kind != "" || spec.ToolPattern != "Bash" || spec.Effect != "DENY" {
		t.Errorf("got %+v, want a bare tool-scoped spec", spec)
	}
}

func TestRuleSpecForExactScopePicksTheNarrowestField(t *testing.T) {
	cases := []struct {
		name      string
		tool      string
		arguments string
		wantKind  string
		wantValue string
	}{
		{"command", "Bash", `{"command":"rm -rf /"}`, "command", "rm -rf /"},
		{"cmd alias", "Bash", `{"cmd":"ls"}`, "command", "ls"},
		{"url", "WebFetch", `{"url":"http://evil.com"}`, "url", "http://evil.com"},
		{"path via file_path", "Write", `{"file_path":"/etc/passwd"}`, "path", "/etc/passwd"},
		{"path via notebook_path", "NotebookEdit", `{"notebook_path":"/tmp/x.ipynb"}`, "path", "/tmp/x.ipynb"},
		{"filename via pattern", "Grep", `{"pattern":"secret"}`, "filename", "secret"},
		{"command wins over url when both present", "Bash", `{"command":"curl x","url":"http://x"}`, "command", "curl x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, err := RuleSpecFor(c.tool, []byte(c.arguments), "exact", "DENY")
			if err != nil {
				t.Fatalf("RuleSpecFor: %v", err)
			}
			if spec.Kind != c.wantKind || spec.Value != c.wantValue {
				t.Errorf("got Kind=%q Value=%q, want Kind=%q Value=%q", spec.Kind, spec.Value, c.wantKind, c.wantValue)
			}
		})
	}
}

func TestRuleSpecForExactScopeWithNothingToNarrowOnErrors(t *testing.T) {
	_, err := RuleSpecFor("MysteryTool", []byte(`{}`), "exact", "DENY")
	if err == nil {
		t.Fatal("expected an error when no command/path/url/filename is present")
	}
	if !strings.Contains(err.Error(), "MysteryTool") {
		t.Errorf("error does not name the tool: %v", err)
	}
}

func TestAuditWhitelistAndBlockCreateRulesFromALogEntry(t *testing.T) {
	newHome(t)
	writeLogLines(t, `{"ts":"2026-01-01T00:00:00Z","tool":"Bash","decision":"DENY","arguments":{"command":"rm -rf /"}}`)

	policy := &PolicySet{ID: "local", Name: "local"}
	if err := writeStore(stored{Policy: policy, envelope: true}); err != nil {
		t.Fatalf("writeStore: %v", err)
	}

	a := Audit{&Client{}}
	mut, err := a.Whitelist(context.Background(), "1", "exact")
	if err != nil {
		t.Fatalf("Whitelist: %v", err)
	}
	if !mut.OK || mut.Rule == nil || mut.Rule.Effect != "ALLOW" {
		t.Fatalf("got %+v, want an ALLOW rule", mut)
	}
	if mut.Rule.CommandConstraints == nil || len(mut.Rule.CommandConstraints.Allowed) != 1 ||
		mut.Rule.CommandConstraints.Allowed[0] != "rm -rf /" {
		t.Errorf("CommandConstraints = %+v, want the command allowed", mut.Rule.CommandConstraints)
	}

	mut2, err := a.Block(context.Background(), "1", "exact")
	if err != nil {
		t.Fatalf("Block: %v", err)
	}
	if !mut2.OK || mut2.Rule == nil || mut2.Rule.Effect != "DENY" {
		t.Fatalf("got %+v, want a DENY rule", mut2)
	}
}

func TestAuditWhitelistWithUnknownEntryErrors(t *testing.T) {
	newHome(t)
	writeLogLines(t, `{"ts":"2026-01-01T00:00:00Z","tool":"Bash","decision":"ALLOW"}`)
	policy := &PolicySet{ID: "local", Name: "local"}
	if err := writeStore(stored{Policy: policy, envelope: true}); err != nil {
		t.Fatalf("writeStore: %v", err)
	}

	a := Audit{&Client{}}
	if _, err := a.Whitelist(context.Background(), "999", "exact"); err == nil {
		t.Error("expected an error for an entry id that does not exist")
	}
}