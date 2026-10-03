package panels

import (
	"testing"

	"github.com/codeyevsky/solongate/proxy/internal/api"
)

// CHANGING WHAT A RULE MATCHES ON MUST NOT THROW AWAY WHAT IT MATCHES.
//
// setCType wrote an empty list, so cycling the constraint type discarded the rule's
// patterns. The field is cycled with ← and → while moving around the editor, so somebody
// navigating a rule could land on Constraint, press an arrow, and watch `curl*` turn into
// a dash two rows below where they were looking. Nothing warned them, and nothing could
// bring it back.
func TestChangingTheConstraintTypeKeepsThePatterns(t *testing.T) {
	r := api.PolicyRule{
		Effect:             "DENY",
		CommandConstraints: &api.Constraint{Denied: []string{"curl*", "wget *"}},
	}

	setCType(&r, cFilename)

	if r.CommandConstraints != nil && len(r.CommandConstraints.Denied) > 0 {
		t.Error("the old constraint was left behind, so the rule now matches on two kinds")
	}
	got := matchItems(r)
	if len(got) != 2 || got[0] != "curl*" || got[1] != "wget *" {
		t.Fatalf("after switching to filename the patterns are %v, want them carried across", got)
	}
}

// ROUND TRIP. Cycling past a type and back is what pressing an arrow twice does, and it
// has to be a no-op rather than a slow way to empty a rule.
func TestCyclingThroughEveryTypeAndBackKeepsThePatterns(t *testing.T) {
	r := api.PolicyRule{
		Effect:             "DENY",
		CommandConstraints: &api.Constraint{Denied: []string{"rm -rf *"}},
	}

	for _, to := range []cType{cFilename, cURL, cPath, cCommand} {
		setCType(&r, to)
		if got := matchItems(r); len(got) != 1 || got[0] != "rm -rf *" {
			t.Fatalf("switching to %v left %v", to, got)
		}
	}
	if currentCType(r) != cCommand {
		t.Errorf("ended on %v, want to be back at command", currentCType(r))
	}
}

// AN ALLOW RULE KEEPS ITS PATTERNS ON THE ALLOW SIDE, which is a separate list from the
// denied one — carrying the values to the wrong side would turn a whitelist entry into a
// block.
func TestAnAllowRuleKeepsItsPatternsOnTheAllowSide(t *testing.T) {
	r := api.PolicyRule{
		Effect:             "ALLOW",
		CommandConstraints: &api.Constraint{Allowed: []string{"ls *"}},
	}

	setCType(&r, cURL)

	if r.URLConstraints == nil {
		t.Fatal("no url constraint after switching to it")
	}
	if len(r.URLConstraints.Denied) > 0 {
		t.Errorf("an ALLOW rule's patterns landed on the denied side: %v", r.URLConstraints.Denied)
	}
	if len(r.URLConstraints.Allowed) != 1 || r.URLConstraints.Allowed[0] != "ls *" {
		t.Errorf("allowed = %v, want the pattern carried across", r.URLConstraints.Allowed)
	}
}

// Clearing the constraint entirely is still allowed to empty it: that is what choosing
// "no constraint" means, and it is a choice rather than a side effect.
func TestChoosingNoConstraintClearsIt(t *testing.T) {
	r := api.PolicyRule{
		Effect:             "DENY",
		CommandConstraints: &api.Constraint{Denied: []string{"curl*"}},
	}

	setCType(&r, cNone)

	if got := matchItems(r); len(got) != 0 {
		t.Errorf("choosing no constraint left %v", got)
	}
}
