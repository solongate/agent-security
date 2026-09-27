package main

// What the light shape keeps, and what it drops.
//
// The bug this fixes was silent in both directions: the full shape was too big
// to read, and an over-eager slim shape would have emptied a column on the page
// without anything failing. So both halves are asserted.

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func slimFixture() []auditListEntry {
	args := json.RawMessage(`{"command":"rm -rf /tmp/x"}`)
	rule := json.RawMessage(`{"id":"rule-42"}`)
	return []auditListEntry{
		{ID: "a", Decision: "ALLOW", ToolName: "Read", ArgumentsSummary: args, MatchedRule: rule,
			PiCategories: json.RawMessage(`["x"]`), PiStageScores: json.RawMessage(`{"s":1}`)},
		{ID: "b", Decision: "DENY", ToolName: "Bash", ArgumentsSummary: args, MatchedRule: rule},
	}
}

// An allowed call's payload is what made the response too large to read, and
// nothing on an aggregating page looks at it.
func TestSlimDropsThePayloadOnAllowedCalls(t *testing.T) {
	out := slimAuditEntries(slimFixture())

	if out[0].ArgumentsSummary != nil {
		t.Error("an allowed call still carries its arguments")
	}
	for _, field := range []json.RawMessage{out[0].MatchedRule, out[0].PiCategories, out[0].PiStageScores} {
		if field != nil {
			t.Error("a heavy field survived the slim shape")
		}
	}
	// And the fields a count is grouped by are untouched.
	if out[0].ToolName != "Read" || out[0].Decision != "ALLOW" {
		t.Errorf("slim damaged what the page groups by: %+v", out[0])
	}
}

// A refusal keeps its payload, because the page reads it to say WHAT was
// refused. Dropping it would empty that column with nothing failing.
func TestSlimKeepsThePayloadOnARefusal(t *testing.T) {
	out := slimAuditEntries(slimFixture())

	if out[1].ArgumentsSummary == nil {
		t.Fatal("a refusal lost its arguments, so the page cannot say what was blocked")
	}
	if string(out[1].ArgumentsSummary) != `{"command":"rm -rf /tmp/x"}` {
		t.Errorf("the refusal's arguments were altered: %s", out[1].ArgumentsSummary)
	}
	// The rule document still goes: it is resolved per row and the page that
	// asked for slim does not draw it.
	if out[1].MatchedRule != nil {
		t.Error("the resolved rule survived the slim shape")
	}
}

// Opt-in, because deployed clients read these fields and a route that quietly
// stopped sending them would break a page with no error anywhere.
func TestTheLightShapeIsOnlySentWhenAsked(t *testing.T) {
	for query, want := range map[string]bool{
		"?slim=1":     true,
		"?slim=true":  true,
		"?slim=yes":   true,
		"?slim=0":     false,
		"?slim=":      false,
		"":            false,
		"?limit=5000": false,
	} {
		r := httptest.NewRequest("GET", "/api/v1/audit-logs"+query, nil)
		if got := auditSlimRequested(r); got != want {
			t.Errorf("%q asked for slim=%v, want %v", query, got, want)
		}
	}
}
