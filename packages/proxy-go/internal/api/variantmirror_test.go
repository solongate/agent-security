// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"testing"
)

// THE CLI WROTE THE TOP LEVEL; THE DATAROOM READ THE VARIANTS.
//
// A policy document carries its rules at the top level AND inside a variant bundle. The
// top level is a mirror rather than a second source — three readers in the field take
// only $.rules — and the dataroom wrote both. The CLI wrote only the top level, so after
// `solongate policy deny` the two disagreed and each tool showed its own list:
//
//	solongate policy show local   14 rules
//	the dataroom's Rules pane      1 rule
//
// The silent half is the dangerous one. The dataroom saves what it read, so opening a
// policy it believed had one rule and pressing save writes one rule back — deleting
// thirteen that were being enforced, with nothing to warn anybody, because from inside
// that panel nothing was being removed.
func TestARuleAddedByTheCLIReachesTheVariantBundle(t *testing.T) {
	newTestClient(t)

	// A policy written by the dataroom: one rule, in both places.
	writePolicyFile(t, `{
	  "id": "local", "name": "Local", "mode": "denylist",
	  "defaultVariant": "v1",
	  "rules": [{"id":"r1","effect":"DENY","priority":100,"toolPattern":"*","enabled":true,
	             "commandConstraints":{"denied":["curl*"]}}],
	  "variants": [{"id":"v1","name":"Base",
	    "rules": [{"id":"r1","effect":"DENY","priority":100,"toolPattern":"*","enabled":true,
	               "commandConstraints":{"denied":["curl*"]}}]}]
	}`)

	p := PoliciesAPI{}
	ctx := context.Background()
	if _, err := p.AddRule(ctx, "local", RuleSpec{
		Kind: "command", Value: "rm -rf *", Effect: "DENY", ToolPattern: "*",
	}); err != nil {
		t.Fatal(err)
	}

	s, err := readStore()
	if err != nil {
		t.Fatal(err)
	}
	top := len(s.Policy.Rules.Items)
	if top != 2 {
		t.Fatalf("the top level has %d rules, want 2", top)
	}
	if len(s.Policy.Variants) != 1 {
		t.Fatalf("variants = %d, want the bundle kept", len(s.Policy.Variants))
	}
	if got := len(s.Policy.Variants[0].Rules.Items); got != top {
		t.Errorf("the variant bundle has %d rules and the top level has %d.\n"+
			"The dataroom reads the bundle, so it would show %d and save %d back — "+
			"deleting the rest.", got, top, got, got)
	}
}

// THE DEFAULT VARIANT IS THE ONE MIRRORED, not merely the first in the list. A policy
// whose default is the second bundle would otherwise have its rules written into a
// bundle nobody is using, and the one being enforced left stale.
func TestTheMirrorFollowsTheDefaultVariant(t *testing.T) {
	newTestClient(t)

	writePolicyFile(t, `{
	  "id": "local", "name": "Local", "mode": "denylist",
	  "defaultVariant": "second",
	  "rules": [],
	  "variants": [
	    {"id":"first","name":"First","rules":[]},
	    {"id":"second","name":"Second","rules":[]}
	  ]
	}`)

	p := PoliciesAPI{}
	if _, err := p.AddRule(context.Background(), "local", RuleSpec{
		Kind: "command", Value: "wget *", Effect: "DENY", ToolPattern: "*",
	}); err != nil {
		t.Fatal(err)
	}

	s, err := readStore()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(s.Policy.Variants[1].Rules.Items); n != 1 {
		t.Errorf("the default variant has %d rules, want the new one mirrored into it", n)
	}
	if n := len(s.Policy.Variants[0].Rules.Items); n != 0 {
		t.Errorf("a variant that is not the default gained %d rules", n)
	}
}

// A policy with no bundle is left exactly as it is: most machines have one, and
// inventing a bundle for them would change the document's shape for no reason.
func TestAPolicyWithNoVariantsIsUntouched(t *testing.T) {
	newTestClient(t)

	writePolicyFile(t, `{"id":"local","name":"Local","mode":"denylist","rules":[]}`)

	p := PoliciesAPI{}
	if _, err := p.AddRule(context.Background(), "local", RuleSpec{
		Kind: "command", Value: "curl *", Effect: "DENY", ToolPattern: "*",
	}); err != nil {
		t.Fatal(err)
	}

	s, err := readStore()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Policy.Variants) != 0 {
		t.Errorf("a variant bundle was invented: %d", len(s.Policy.Variants))
	}
	if len(s.Policy.Rules.Items) != 1 {
		t.Errorf("rules = %d, want 1", len(s.Policy.Rules.Items))
	}
}
