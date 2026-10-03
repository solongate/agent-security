package api

import (
	"context"
	"strings"
	"testing"
)

// A PATTERN WITH A STRAY SPACE READS CORRECTLY AND MATCHES NOTHING.
//
// `policy show` prints `curl *` whether or not there is a space after it, the dataroom
// lists it the same way, and the glob never matches a command that does not end in one.
// So the rule looks right in every place somebody would check it, and is inert.
//
// It is the same failure the permission check already refuses a typo for, and easier to
// produce: a trailing space is invisible in the editor that made it.
func TestARuleIsStoredWithoutSurroundingSpace(t *testing.T) {
	withStore(t)

	p := PoliciesAPI{}
	ctx := context.Background()

	for _, in := range []string{"  curl *", "curl *  ", "\tcurl *\n", " curl * "} {
		res, err := p.AddRule(ctx, "local", RuleSpec{
			Kind: "command", Value: in, Effect: "DENY", ToolPattern: "*",
		})
		if err != nil {
			t.Fatalf("AddRule(%q): %v", in, err)
		}
		if res.Rule == nil {
			continue // deduped against an earlier spelling, which is the point
		}
		got := storedCommandPattern(t, res.Rule)
		if got != "curl *" {
			t.Errorf("stored %q from input %q, want the trimmed pattern", got, in)
		}
	}
}

// AND THE SAME PATTERN TWICE IS THE SAME RULE.
//
// Trimming has a second effect worth stating: ` curl *` and `curl * ` are now one
// pattern, so the dedup that already exists can see them as equal. Without it a person
// correcting a rule by retyping it ends up with two, and the list grows copies that
// differ by nothing visible.
func TestTwoSpellingsOfOnePatternDoNotBecomeTwoRules(t *testing.T) {
	withStore(t)

	p := PoliciesAPI{}
	ctx := context.Background()
	spec := func(v string) RuleSpec {
		return RuleSpec{Kind: "command", Value: v, Effect: "DENY", ToolPattern: "*"}
	}

	if _, err := p.AddRule(ctx, "local", spec("rm -rf *")); err != nil {
		t.Fatal(err)
	}
	second, err := p.AddRule(ctx, "local", spec("  rm -rf *  "))
	if err != nil {
		t.Fatal(err)
	}
	if !second.Deduped {
		t.Error("the same pattern with different spacing was stored as a second rule")
	}
}

// A pattern of nothing but spaces is refused rather than stored.
//
// What an empty pattern means depends on which field it landed in — everything, or
// nothing — and neither is what somebody who typed only spaces was asking for.
func TestAnEmptyPatternIsRefused(t *testing.T) {
	withStore(t)

	p := PoliciesAPI{}
	_, err := p.AddRule(context.Background(), "local", RuleSpec{
		Kind: "command", Value: "   ", Effect: "DENY", ToolPattern: "*",
	})
	if err == nil {
		t.Fatal("a pattern of only spaces was accepted; it can never match anything")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("the error is %q, which does not say what is wrong", err)
	}
}

// withStore gives each test a machine of its own with one empty policy on it, using
// the same seeding the rest of this package's tests use — so what is exercised is the
// real file the CLI and the guard both read.
func withStore(t *testing.T) {
	t.Helper()
	newTestClient(t)
	writePolicyFile(t, `{"policy":{"id":"local","name":"Local","mode":"denylist","rules":[]}}`)
}

// storedCommandPattern digs the command pattern back out of a stored rule, which is
// where the trim has to have taken effect — not merely in what AddRule was handed.
func storedCommandPattern(t *testing.T, r *PolicyRule) string {
	t.Helper()
	if r.CommandConstraints == nil {
		t.Fatalf("rule %s has no command constraints", r.ID)
	}
	all := append(append([]string{}, r.CommandConstraints.Denied...), r.CommandConstraints.Allowed...)
	if len(all) != 1 {
		t.Fatalf("rule %s holds %d patterns, want 1", r.ID, len(all))
	}
	return all[0]
}
