// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

import (
	"context"
	"encoding/json"
	"testing"
)

func TestPoliciesListEmptyWhenNoPolicy(t *testing.T) {
	newHome(t)
	p := Policies{&Client{}}
	out, err := p.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("got %d entries, want 0", len(out))
	}
}

func TestPoliciesCreateThenList(t *testing.T) {
	newHome(t)
	p := Policies{&Client{}}

	detail, err := p.Create(context.Background(), PolicySet{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if detail.ID != "local" || detail.Name != "local" {
		t.Errorf("Create did not default ID/Name to local: %+v", detail.PolicySet)
	}
	if detail.Mode != ModeDenylist {
		t.Errorf("Mode = %q, want the default denylist", detail.Mode)
	}

	list, err := p.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].ID != "local" {
		t.Fatalf("got %+v, want one local entry", list)
	}
}

func TestPoliciesCreateRefusesASecondPolicy(t *testing.T) {
	newHome(t)
	p := Policies{&Client{}}
	if _, err := p.Create(context.Background(), PolicySet{}); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := p.Create(context.Background(), PolicySet{}); err == nil {
		t.Error("a second Create on a machine that already has a policy should fail")
	}
}

func TestPolicyModeDefaultsToDenylist(t *testing.T) {
	if got := policyMode(&PolicySet{}); got != ModeDenylist {
		t.Errorf("empty Mode -> %q, want denylist", got)
	}
	if got := policyMode(&PolicySet{Mode: ModeWhitelist}); got != ModeWhitelist {
		t.Errorf("whitelist Mode -> %q, want whitelist", got)
	}
	if got := policyMode(&PolicySet{Mode: "garbage"}); got != ModeDenylist {
		t.Errorf("unknown Mode -> %q, want it to fall back to denylist", got)
	}
}

func TestPoliciesGetResolvesOrErrors(t *testing.T) {
	newHome(t)
	p := Policies{&Client{}}
	if _, err := p.Create(context.Background(), PolicySet{}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := p.Get(context.Background(), "local", 0); err != nil {
		t.Errorf("Get(local): %v", err)
	}
	if _, err := p.Get(context.Background(), "", 0); err != nil {
		t.Errorf("Get(\"\"): %v", err)
	}
	if _, err := p.Get(context.Background(), "not-this-machine", 0); err == nil {
		t.Error("Get with an id that is not this machine's policy should fail")
	}
}

func TestPoliciesUpdateKeepsTheOriginalID(t *testing.T) {
	newHome(t)
	p := Policies{&Client{}}
	if _, err := p.Create(context.Background(), PolicySet{Name: "first"}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated, err := p.Update(context.Background(), "local", PolicySet{ID: "ignored-id", Name: "second"})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.ID != "local" {
		t.Errorf("Update let the caller change the policy ID: got %q", updated.ID)
	}
	if updated.Name != "second" {
		t.Errorf("Update did not apply the new name: %q", updated.Name)
	}
}

func TestPoliciesUpdateWiresActiveVariantSecurityIntoTheStore(t *testing.T) {
	newHome(t)
	p := Policies{&Client{}}
	if _, err := p.Create(context.Background(), PolicySet{}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	sec := &SecurityLayers{}
	sec.RateLimit.Mode = LayerBlock
	sec.RateLimit.PerMinute = 7
	if _, err := p.Update(context.Background(), "local", PolicySet{Security: sec}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	s, err := readStore()
	if err != nil {
		t.Fatal(err)
	}
	if s.Security == nil || s.Security.RateLimit == nil || s.Security.RateLimit.PerMinute != 7 {
		t.Errorf("security layers were not propagated into guardSecurity: %+v", s.Security)
	}
}

func TestActiveVariantLayers(t *testing.T) {
	baseSec := &SecurityLayers{}
	baseSec.RateLimit.PerMinute = 1
	variantSec := &SecurityLayers{}
	variantSec.RateLimit.PerMinute = 2

	if got := activeVariantLayers(nil); got != nil {
		t.Errorf("activeVariantLayers(nil) = %+v, want nil", got)
	}

	p := &PolicySet{Security: baseSec}
	if got := activeVariantLayers(p); got != baseSec {
		t.Error("with no variants, the policy's own security should be used")
	}

	withVariants := &PolicySet{
		Security:       baseSec,
		DefaultVariant: "v2",
		Variants: []PolicyVariant{
			{ID: "v1", Security: nil},
			{ID: "v2", Security: variantSec},
		},
	}
	if got := activeVariantLayers(withVariants); got != variantSec {
		t.Error("the default variant's own security should win when it is set")
	}

	fallback := &PolicySet{
		Security:       baseSec,
		DefaultVariant: "v1",
		Variants: []PolicyVariant{
			{ID: "v1", Security: nil},
		},
	}
	if got := activeVariantLayers(fallback); got != baseSec {
		t.Error("a variant with no security of its own should fall back to the policy's security")
	}

	unknownDefault := &PolicySet{
		DefaultVariant: "does-not-exist",
		Variants: []PolicyVariant{
			{ID: "v1", Security: variantSec},
		},
	}
	if got := activeVariantLayers(unknownDefault); got != variantSec {
		t.Error("an unknown DefaultVariant should fall back to the first variant")
	}
}

func TestPoliciesRemoveDeletesTheFileWhenNothingElseIsStored(t *testing.T) {
	newHome(t)
	p := Policies{&Client{}}
	if _, err := p.Create(context.Background(), PolicySet{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := p.Remove(context.Background(), "local"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	s, err := readStore()
	if err != nil {
		t.Fatal(err)
	}
	if !s.absent {
		t.Error("the policy file should be gone after Remove with nothing else stored")
	}
}

func TestPoliciesRemoveKeepsTheFileWhenSecurityOrSelfProtectRemain(t *testing.T) {
	newHome(t)
	p := Policies{&Client{}}
	if _, err := p.Create(context.Background(), PolicySet{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	enabled := true
	s, err := readStore()
	if err != nil {
		t.Fatal(err)
	}
	s.SelfProtect = &enabled
	if err := writeStore(s); err != nil {
		t.Fatal(err)
	}

	if err := p.Remove(context.Background(), "local"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	after, err := readStore()
	if err != nil {
		t.Fatal(err)
	}
	if after.absent {
		t.Error("the file should remain when selfProtect is still set")
	}
	if after.Policy != nil {
		t.Error("the policy itself should be cleared")
	}
	if after.SelfProtect == nil || !*after.SelfProtect {
		t.Error("selfProtect should survive removing the policy")
	}
}

func TestPermissionKey(t *testing.T) {
	if got := permissionKey(PolicyRule{}); got != "" {
		t.Errorf("no permissions -> %q, want empty", got)
	}
	raw, _ := json.Marshal([]string{"WRITE", "READ"})
	got := permissionKey(PolicyRule{Permission: raw})
	if got != "READ,WRITE" {
		t.Errorf("permissionKey = %q, want sorted READ,WRITE", got)
	}
}

func TestConstraintsOfDiffersWhenConstraintsDiffer(t *testing.T) {
	a := constraintsOf(PolicyRule{CommandConstraints: &Constraint{Denied: []string{"rm -rf /"}}})
	b := constraintsOf(PolicyRule{CommandConstraints: &Constraint{Denied: []string{"rm -rf /"}}})
	c := constraintsOf(PolicyRule{CommandConstraints: &Constraint{Denied: []string{"other"}}})
	if a != b {
		t.Error("identical constraints should serialize the same")
	}
	if a == c {
		t.Error("different constraints should serialize differently")
	}
}

func TestDescribeRule(t *testing.T) {
	cases := []struct {
		name   string
		effect string
		spec   RuleSpec
		want   string
	}{
		{"tool allow", "ALLOW", RuleSpec{Kind: "tool", Value: "Bash"}, "Allow the Bash tool"},
		{"tool deny", "DENY", RuleSpec{Kind: "tool", Value: "Bash"}, "Block the Bash tool"},
		{"command", "DENY", RuleSpec{Kind: "command", Value: "rm -rf /"}, "Block command rm -rf /"},
		{"pattern fallback", "DENY", RuleSpec{ToolPattern: "WebFetch"}, "Block WebFetch"},
		{"empty pattern becomes star", "ALLOW", RuleSpec{}, "Allow *"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := describeRule(c.effect, c.spec); got != c.want {
				t.Errorf("describeRule=%q, want %q", got, c.want)
			}
		})
	}
}

func newLocalPolicy(t *testing.T) Policies {
	t.Helper()
	p := Policies{&Client{}}
	if _, err := p.Create(context.Background(), PolicySet{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return p
}

func TestAddRuleDefaultsAndValidates(t *testing.T) {
	newHome(t)
	p := newLocalPolicy(t)

	if _, err := p.AddRule(context.Background(), "local", RuleSpec{Kind: "command", Value: "  "}); err == nil {
		t.Error("a blank value for a non-tool kind should be rejected")
	}

	mut, err := p.AddRule(context.Background(), "local", RuleSpec{})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if mut.Rule.Effect != "DENY" {
		t.Errorf("default effect = %q, want DENY", mut.Rule.Effect)
	}
	if mut.Rule.ToolPattern != "*" {
		t.Errorf("default tool pattern = %q, want *", mut.Rule.ToolPattern)
	}
	if mut.Rule.ID != "rule-1" {
		t.Errorf("first rule id = %q, want rule-1", mut.Rule.ID)
	}
}

func TestAddRuleAssignsIncreasingPriority(t *testing.T) {
	newHome(t)
	p := newLocalPolicy(t)

	m1, err := p.AddRule(context.Background(), "local", RuleSpec{ToolPattern: "Bash"})
	if err != nil {
		t.Fatalf("AddRule 1: %v", err)
	}
	m2, err := p.AddRule(context.Background(), "local", RuleSpec{ToolPattern: "Write"})
	if err != nil {
		t.Fatalf("AddRule 2: %v", err)
	}
	if m2.Rule.Priority <= m1.Rule.Priority {
		t.Errorf("priorities did not increase: %d then %d", m1.Rule.Priority, m2.Rule.Priority)
	}
}

func TestAddRuleWithConstraintKinds(t *testing.T) {
	newHome(t)
	p := newLocalPolicy(t)

	cases := []struct {
		kind string
		want func(r PolicyRule) bool
	}{
		{"command", func(r PolicyRule) bool {
			return r.CommandConstraints != nil && r.CommandConstraints.Denied[0] == "rm -rf /"
		}},
		{"path", func(r PolicyRule) bool { return r.PathConstraints != nil && r.PathConstraints.Denied[0] == "/etc" }},
		{"filename", func(r PolicyRule) bool {
			return r.FilenameConstraints != nil && r.FilenameConstraints.Denied[0] == "*.pem"
		}},
		{"url", func(r PolicyRule) bool {
			return r.URLConstraints != nil && r.URLConstraints.Denied[0] == "http://evil.com"
		}},
	}
	values := map[string]string{"command": "rm -rf /", "path": "/etc", "filename": "*.pem", "url": "http://evil.com"}
	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			mut, err := p.AddRule(context.Background(), "local", RuleSpec{Kind: c.kind, Value: values[c.kind]})
			if err != nil {
				t.Fatalf("AddRule: %v", err)
			}
			if !c.want(*mut.Rule) {
				t.Errorf("constraint not set as expected: %+v", mut.Rule)
			}
		})
	}

	if _, err := p.AddRule(context.Background(), "local", RuleSpec{Kind: "bogus", Value: "x"}); err == nil {
		t.Error("an unknown constraint kind should error")
	}
}

func TestAddRuleAllowedSideUsesAllowedConstraint(t *testing.T) {
	newHome(t)
	p := newLocalPolicy(t)
	mut, err := p.AddRule(context.Background(), "local", RuleSpec{Kind: "command", Value: "ls", Effect: "ALLOW"})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if mut.Rule.CommandConstraints == nil || len(mut.Rule.CommandConstraints.Allowed) != 1 || mut.Rule.CommandConstraints.Allowed[0] != "ls" {
		t.Errorf("an ALLOW rule should populate Allowed, not Denied: %+v", mut.Rule.CommandConstraints)
	}
}

func TestAddRuleDedupesIdenticalRules(t *testing.T) {
	newHome(t)
	p := newLocalPolicy(t)
	spec := RuleSpec{Kind: "command", Value: "rm -rf /", Effect: "DENY"}

	first, err := p.AddRule(context.Background(), "local", spec)
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	second, err := p.AddRule(context.Background(), "local", spec)
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if !second.Deduped {
		t.Error("an identical rule should be reported as deduped")
	}
	if second.Rule.ID != first.Rule.ID {
		t.Errorf("deduped rule should be the existing one: got %q, want %q", second.Rule.ID, first.Rule.ID)
	}

	s, err := readStore()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Policy.Rules.Items) != 1 {
		t.Errorf("got %d rules stored, want 1 after a dedupe", len(s.Policy.Rules.Items))
	}
}

func TestAddRuleUsesToolValueAsPattern(t *testing.T) {
	newHome(t)
	p := newLocalPolicy(t)
	mut, err := p.AddRule(context.Background(), "local", RuleSpec{Kind: "tool", Value: "Bash"})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if mut.Rule.ToolPattern != "Bash" {
		t.Errorf("ToolPattern = %q, want Bash", mut.Rule.ToolPattern)
	}
}

func TestRevokeRule(t *testing.T) {
	newHome(t)
	p := newLocalPolicy(t)
	mut, err := p.AddRule(context.Background(), "local", RuleSpec{ToolPattern: "Bash"})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	if _, err := p.RevokeRule(context.Background(), "local", "no-such-rule"); err == nil {
		t.Error("revoking an unknown rule id should error")
	}

	rm, err := p.RevokeRule(context.Background(), "local", mut.Rule.ID)
	if err != nil {
		t.Fatalf("RevokeRule: %v", err)
	}
	if !rm.OK {
		t.Error("RevokeRule should report OK")
	}
	s, err := readStore()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Policy.Rules.Items) != 0 {
		t.Errorf("got %d rules after revoking the only one, want 0", len(s.Policy.Rules.Items))
	}
}

func TestPoliciesActiveReflectsSecurityLayers(t *testing.T) {
	newHome(t)
	p := newLocalPolicy(t)

	sec := SecurityLayers{}
	sec.RateLimit.Mode = LayerBlock
	sec.RateLimit.PerMinute = 9
	sec.DLP.Mode = LayerRedact
	sec.DLP.Patterns = []string{"JWT"}

	st, err := readStore()
	if err != nil {
		t.Fatal(err)
	}
	st.Security = fromLayers(sec, st.Security)
	if err := writeStore(st); err != nil {
		t.Fatal(err)
	}

	active, err := p.Active(context.Background(), "")
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if active.Security.RateLimit == nil || active.Security.RateLimit.PerMinute != 9 {
		t.Errorf("RateLimit = %+v, want PerMinute 9", active.Security.RateLimit)
	}
	if active.Security.DLPRedact == nil || len(active.Security.DLPRedact.Patterns) != 1 || active.Security.DLPRedact.Patterns[0] != "JWT" {
		t.Errorf("DLPRedact = %+v, want patterns [JWT]", active.Security.DLPRedact)
	}
	if !active.SelfProtectionEnabled {
		t.Error("self protection should default to enabled when unset")
	}
	if active.Hash == "" {
		t.Error("an active policy should carry a hash")
	}
}

func TestPoliciesSetActive(t *testing.T) {
	newHome(t)
	p := newLocalPolicy(t)

	if err := p.SetActive(context.Background(), ""); err == nil {
		t.Error("an empty policy id should be rejected")
	}
	if err := p.SetActive(context.Background(), "local"); err != nil {
		t.Errorf("SetActive(local): %v", err)
	}
	if err := p.SetActive(context.Background(), "someone-else"); err == nil {
		t.Error("SetActive with a mismatched id should be rejected")
	}
}