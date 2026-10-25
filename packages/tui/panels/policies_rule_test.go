// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"encoding/json"
	"testing"

	"github.com/solongate/agent-security/packages/core/client"
)

func TestRuleDocMarshalReturnsRawWhenUnedited(t *testing.T) {
	raw := json.RawMessage(`{"id":"r1","hand":"crafted"}`)
	d := ruleDoc{rule: client.PolicyRule{ID: "r1"}, raw: raw, edited: false}
	got, err := d.marshal()
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("marshal()=%s, want original raw %s", got, raw)
	}
}

func TestRuleDocMarshalRebuildsWhenEdited(t *testing.T) {
	d := ruleDoc{
		rule: client.PolicyRule{
			ID: "r1", Description: "desc", Effect: "DENY", Priority: 5,
			ToolPattern: "*", MinimumTrustLevel: "UNTRUSTED", Enabled: true,
			CommandConstraints: &client.Constraint{Denied: []string{"rm"}},
		},
		edited: true,
	}
	got, err := d.marshal()
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if obj["id"] != "r1" || obj["effect"] != "DENY" || obj["priority"] != float64(5) {
		t.Errorf("unexpected rebuilt object: %v", obj)
	}
	if _, ok := obj["commandConstraints"]; !ok {
		t.Errorf("expected commandConstraints to be present: %v", obj)
	}
	if _, ok := obj["permission"]; ok {
		t.Errorf("expected no permission key when Permission is empty: %v", obj)
	}
	if _, ok := obj["pathConstraints"]; ok {
		t.Errorf("expected no pathConstraints key when nil: %v", obj)
	}
}

func TestRuleDocMarshalKeepsPermissionWhenSet(t *testing.T) {
	perm, _ := json.Marshal([]string{"READ"})
	d := ruleDoc{rule: client.PolicyRule{ID: "r1", Permission: perm}, edited: true}
	got, err := d.marshal()
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatal(err)
	}
	if _, ok := obj["permission"]; !ok {
		t.Errorf("expected permission key present: %v", obj)
	}
}

func TestCurrentCType(t *testing.T) {
	cases := []struct {
		name string
		rule client.PolicyRule
		want cType
	}{
		{"none", client.PolicyRule{}, cNone},
		{"path", client.PolicyRule{PathConstraints: &client.PathConstraint{}}, cPath},
		{"command", client.PolicyRule{CommandConstraints: &client.Constraint{}}, cCommand},
		{"filename", client.PolicyRule{FilenameConstraints: &client.Constraint{}}, cFilename},
		{"url", client.PolicyRule{URLConstraints: &client.Constraint{}}, cURL},
		{
			"filename takes precedence over url, command and path",
			client.PolicyRule{
				FilenameConstraints: &client.Constraint{},
				URLConstraints:      &client.Constraint{},
				CommandConstraints:  &client.Constraint{},
				PathConstraints:     &client.PathConstraint{},
			},
			cFilename,
		},
		{
			"url takes precedence over command and path",
			client.PolicyRule{
				URLConstraints:     &client.Constraint{},
				CommandConstraints: &client.Constraint{},
				PathConstraints:    &client.PathConstraint{},
			},
			cURL,
		},
		{
			"command takes precedence over path",
			client.PolicyRule{
				CommandConstraints: &client.Constraint{},
				PathConstraints:    &client.PathConstraint{},
			},
			cCommand,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := currentCType(tc.rule); got != tc.want {
				t.Errorf("currentCType()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestSetCTypeNoneClearsConstraints(t *testing.T) {
	r := client.PolicyRule{Effect: "DENY", CommandConstraints: &client.Constraint{Denied: []string{"rm"}}}
	setCType(&r, cNone)
	if currentCType(r) != cNone {
		t.Errorf("expected cNone after clearing, got %v", currentCType(r))
	}
}

func TestSetCTypeAllowSideWritesAllowed(t *testing.T) {
	r := client.PolicyRule{Effect: "ALLOW", CommandConstraints: &client.Constraint{Allowed: []string{"ls", "cat"}}}
	setCType(&r, cPath)
	if r.CommandConstraints != nil {
		t.Errorf("expected command constraints cleared, got %v", r.CommandConstraints)
	}
	if r.PathConstraints == nil {
		t.Fatalf("expected path constraints set")
	}
	if len(r.PathConstraints.Allowed) != 2 || len(r.PathConstraints.Denied) != 0 {
		t.Errorf("expected items to move to Allowed side for ALLOW rule, got %+v", r.PathConstraints)
	}
}

func TestSetCTypeDenySideWritesDenied(t *testing.T) {
	r := client.PolicyRule{Effect: "DENY", PathConstraints: &client.PathConstraint{Allowed: []string{"x"}}}
	setCType(&r, cFilename)
	if r.FilenameConstraints == nil {
		t.Fatalf("expected filename constraints set")
	}
	if len(r.FilenameConstraints.Denied) != 1 || len(r.FilenameConstraints.Allowed) != 0 {
		t.Errorf("expected items to move to Denied side for DENY rule, got %+v", r.FilenameConstraints)
	}
}

func TestMatchItemsCombinesAllowedAndDenied(t *testing.T) {
	cases := []struct {
		name string
		rule client.PolicyRule
		want []string
	}{
		{"none", client.PolicyRule{}, nil},
		{"command", client.PolicyRule{CommandConstraints: &client.Constraint{Allowed: []string{"a"}, Denied: []string{"b"}}}, []string{"a", "b"}},
		{"filename", client.PolicyRule{FilenameConstraints: &client.Constraint{Allowed: []string{"*.go"}}}, []string{"*.go"}},
		{"url", client.PolicyRule{URLConstraints: &client.Constraint{Denied: []string{"http://x"}}}, []string{"http://x"}},
		{"path", client.PolicyRule{PathConstraints: &client.PathConstraint{Allowed: []string{"/tmp"}, Denied: []string{"/etc"}}}, []string{"/tmp", "/etc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchItems(tc.rule)
			if len(got) != len(tc.want) {
				t.Fatalf("matchItems()=%v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("matchItems()[%d]=%q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestSetMatchItemsNoOpForNoneType(t *testing.T) {
	r := client.PolicyRule{Effect: "DENY"}
	setMatchItems(&r, []string{"x"})
	if currentCType(r) != cNone {
		t.Errorf("expected rule to remain cNone, got %v", currentCType(r))
	}
}

func TestSetMatchItemsRewritesCurrentType(t *testing.T) {
	r := client.PolicyRule{Effect: "ALLOW", CommandConstraints: &client.Constraint{Allowed: []string{"old"}}}
	setMatchItems(&r, []string{"new1", "new2"})
	if r.CommandConstraints == nil || len(r.CommandConstraints.Allowed) != 2 {
		t.Errorf("expected constraints updated, got %+v", r.CommandConstraints)
	}
}

func TestCValueJoinsWithCommaSpace(t *testing.T) {
	r := client.PolicyRule{CommandConstraints: &client.Constraint{Allowed: []string{"a", "b"}, Denied: []string{"c"}}}
	if got := cValue(r); got != "a, b, c" {
		t.Errorf("cValue()=%q, want %q", got, "a, b, c")
	}
	if got := cValue(client.PolicyRule{}); got != "" {
		t.Errorf("cValue() for no-constraint rule=%q, want empty", got)
	}
}

func TestMigrateEffectMovesItemsToOtherSide(t *testing.T) {
	r := client.PolicyRule{
		Effect:             "ALLOW",
		CommandConstraints: &client.Constraint{Allowed: []string{"ls", "cat"}},
	}
	migrateEffect(&r, "DENY")
	if r.Effect != "DENY" {
		t.Errorf("Effect=%q, want DENY", r.Effect)
	}
	if len(r.CommandConstraints.Denied) != 2 || len(r.CommandConstraints.Allowed) != 0 {
		t.Errorf("expected items moved to Denied, got %+v", r.CommandConstraints)
	}
}

func TestMigrateEffectWithoutConstraintsOnlyFlipsEffect(t *testing.T) {
	r := client.PolicyRule{Effect: "ALLOW"}
	migrateEffect(&r, "DENY")
	if r.Effect != "DENY" {
		t.Errorf("Effect=%q, want DENY", r.Effect)
	}
	if currentCType(r) != cNone {
		t.Errorf("expected no constraint type introduced, got %v", currentCType(r))
	}
}

func TestFlipStar(t *testing.T) {
	cases := []struct {
		v, side, want string
	}{
		{"foo", "left", "*foo"},
		{"*foo", "left", "foo"},
		{"**foo", "left", "foo"},
		{"foo", "right", "foo*"},
		{"foo*", "right", "foo"},
		{"foo**", "right", "foo"},
	}
	for _, tc := range cases {
		if got := flipStar(tc.v, tc.side); got != tc.want {
			t.Errorf("flipStar(%q,%q)=%q, want %q", tc.v, tc.side, got, tc.want)
		}
	}
}

func TestPermListOfEmptyReturnsAll(t *testing.T) {
	got := permListOf(client.PolicyRule{})
	if len(got) != len(permsAll) {
		t.Fatalf("permListOf empty = %v, want all of %v", got, permsAll)
	}
	for i, p := range permsAll {
		if got[i] != p {
			t.Errorf("permListOf()[%d]=%q, want %q", i, got[i], p)
		}
	}
}

func TestPermListOfParsesSetPermission(t *testing.T) {
	raw, _ := json.Marshal([]string{"READ", "WRITE"})
	got := permListOf(client.PolicyRule{Permission: raw})
	if len(got) != 2 || got[0] != "READ" || got[1] != "WRITE" {
		t.Errorf("permListOf()=%v, want [READ WRITE]", got)
	}
}

func TestPermIsAny(t *testing.T) {
	if !permIsAny(client.PolicyRule{}) {
		t.Errorf("expected empty permission rule to be \"any\"")
	}
	raw, _ := json.Marshal([]string{"READ"})
	if permIsAny(client.PolicyRule{Permission: raw}) {
		t.Errorf("expected rule with only READ to not be \"any\"")
	}
}

func TestTogglePermAddAndRemove(t *testing.T) {
	r := client.PolicyRule{}
	togglePerm(&r, "READ")
	if permIsAny(r) {
		t.Fatalf("expected rule to no longer be \"any\" after removing READ from full set")
	}
	have := permListOf(r)
	if containsString(have, "READ") {
		t.Errorf("expected READ removed, have=%v", have)
	}

	togglePerm(&r, "READ")
	if !permIsAny(r) {
		t.Errorf("expected rule to be \"any\" again after re-adding READ, have=%v", permListOf(r))
	}
	if r.Permission != nil {
		t.Errorf("expected Permission cleared when set becomes \"any\", got %s", r.Permission)
	}
}

func TestTogglePermNeverLeavesEmptySet(t *testing.T) {
	r := client.PolicyRule{}
	for _, p := range permsAll {
		togglePerm(&r, p)
	}
	have := permListOf(r)
	if len(have) != 1 || have[0] != permsAll[len(permsAll)-1] {
		t.Errorf("expected toggling off everything to fall back to a single permission, got %v", have)
	}
}

func TestPermDisplay(t *testing.T) {
	if got := permDisplay(client.PolicyRule{}); got != "any (READ WRITE EXECUTE NETWORK)" {
		t.Errorf("permDisplay(any)=%q", got)
	}
	raw, _ := json.Marshal([]string{"READ", "WRITE"})
	if got := permDisplay(client.PolicyRule{Permission: raw}); got != "READ WRITE" {
		t.Errorf("permDisplay(subset)=%q, want %q", got, "READ WRITE")
	}
}

func TestRuleHasValuesAndIsBlanketRule(t *testing.T) {
	blank := client.PolicyRule{}
	if ruleHasValues(blank) {
		t.Errorf("expected no values for empty rule")
	}
	if !isBlanketRule(blank) {
		t.Errorf("expected empty rule with full permissions to be blanket")
	}

	withValue := client.PolicyRule{CommandConstraints: &client.Constraint{Denied: []string{"rm"}}}
	if !ruleHasValues(withValue) {
		t.Errorf("expected rule with a constraint value to have values")
	}
	if isBlanketRule(withValue) {
		t.Errorf("expected rule with a constraint value to not be blanket")
	}

	raw, _ := json.Marshal([]string{"READ"})
	narrowedPerm := client.PolicyRule{Permission: raw}
	if isBlanketRule(narrowedPerm) {
		t.Errorf("expected rule with narrowed permissions to not be blanket")
	}
}

func TestRuleSummary(t *testing.T) {
	r := client.PolicyRule{
		CommandConstraints:  &client.Constraint{Denied: []string{"rm", "dd"}},
		PathConstraints:     &client.PathConstraint{Allowed: []string{"/tmp"}},
		FilenameConstraints: &client.Constraint{},
		URLConstraints:      &client.Constraint{Allowed: []string{"http://x"}},
	}
	got := ruleSummary(r)
	want := "cmd:2 path:1 url:1"
	if got != want {
		t.Errorf("ruleSummary()=%q, want %q", got, want)
	}
	if got := ruleSummary(client.PolicyRule{}); got != "" {
		t.Errorf("ruleSummary(empty)=%q, want empty", got)
	}
}