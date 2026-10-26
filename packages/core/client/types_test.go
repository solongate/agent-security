// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

import (
	"encoding/json"
	"testing"

	"github.com/solongate/agent-security/packages/core/vocab"
)

func TestPolicyRulePermissions(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []vocab.Permission
	}{
		{"no permission set", "", nil},
		{"a single string", `"READ"`, []vocab.Permission{"READ"}},
		{"an empty string", `""`, nil},
		{"an array", `["READ","WRITE"]`, []vocab.Permission{"READ", "WRITE"}},
		{"an empty array", `[]`, []vocab.Permission{}},
		{"malformed json", `{not json`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := PolicyRule{}
			if c.raw != "" {
				r.Permission = json.RawMessage(c.raw)
			}
			got := r.Permissions()
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("element %d = %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestRulesUnmarshalAndMarshalRoundTrip(t *testing.T) {
	in := `[{"id":"rule-1","effect":"DENY","toolPattern":"Bash"},{"id":"rule-2","effect":"ALLOW","toolPattern":"Write"}]`
	var rules Rules
	if err := json.Unmarshal([]byte(in), &rules); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(rules.Items) != 2 {
		t.Fatalf("got %d items, want 2", len(rules.Items))
	}
	if rules.Unreadable != 0 {
		t.Errorf("Unreadable = %d, want 0", rules.Unreadable)
	}

	out, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != in {
		t.Errorf("round trip changed the JSON:\ngot  %s\nwant %s", out, in)
	}
}

func TestRulesUnmarshalCountsUnreadableEntries(t *testing.T) {
	in := `[{"id":"rule-1","effect":"DENY"}, "not a rule object", {"id":"rule-2","effect":"ALLOW"}]`
	var rules Rules
	if err := json.Unmarshal([]byte(in), &rules); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if rules.Unreadable != 1 {
		t.Errorf("Unreadable = %d, want 1", rules.Unreadable)
	}
	if len(rules.Items) != 2 {
		t.Errorf("got %d readable items, want 2", len(rules.Items))
	}
}

func TestRulesUnmarshalRejectsNonArrayJSON(t *testing.T) {
	var rules Rules
	if err := json.Unmarshal([]byte(`{"not":"an array"}`), &rules); err == nil {
		t.Error("expected an error unmarshaling a non-array into Rules")
	}
}

func TestRulesMarshalWithNoItemsProducesEmptyArray(t *testing.T) {
	out, err := json.Marshal(Rules{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != "[]" {
		t.Errorf("got %s, want []", out)
	}
}

func TestPolicySetVariantList(t *testing.T) {
	p := PolicySet{Rules: Rules{Items: []PolicyRule{{ID: "rule-1"}}}}
	base := p.VariantList()
	if len(base) != 1 || base[0].ID != "" || base[0].Name != "Base" {
		t.Errorf("a policy with no variants should synthesize one Base variant, got %+v", base)
	}

	withVariants := PolicySet{Variants: []PolicyVariant{{ID: "v1"}, {ID: "v2"}}}
	got := withVariants.VariantList()
	if len(got) != 2 || got[0].ID != "v1" || got[1].ID != "v2" {
		t.Errorf("got %+v, want the explicit variants unchanged", got)
	}
}

func TestPolicySetVariantLayers(t *testing.T) {
	policySec := &SecurityLayers{}
	policySec.RateLimit.PerMinute = 1
	variantSec := &SecurityLayers{}
	variantSec.RateLimit.PerMinute = 2

	p := PolicySet{Security: policySec}
	if got := p.VariantLayers(PolicyVariant{Security: variantSec}); got.RateLimit.PerMinute != 2 {
		t.Error("a variant's own security should win")
	}
	if got := p.VariantLayers(PolicyVariant{}); got.RateLimit.PerMinute != 1 {
		t.Error("with no variant security, the policy's security should be used")
	}

	empty := PolicySet{}
	if got := empty.VariantLayers(PolicyVariant{}); got.RateLimit.PerMinute != 0 {
		t.Error("with neither variant nor policy security, the zero value should come back")
	}
}