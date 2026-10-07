// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"testing"

	"github.com/codeyevsky/solongate/proxy/internal/api"
)

// `policy show` LISTS WHAT IS ENFORCED, so it has to say what each rule matches.
//
// The columns were effect, priority, id and description. Description is free text that
// somebody may never have written — a rule added from the dataroom has none — so the
// list of what this machine enforces contained rows like:
//
//	DENY  100  rule-1791039653150  -
//
// A rule that is blocking something, in the list of things that block, with no way to
// tell what. The kind and the pattern are not decoration; they are the rule.
func TestEveryRuleShapeSaysWhatItMatches(t *testing.T) {
	cases := []struct {
		name       string
		rule       api.PolicyRule
		kind, patt string
	}{
		{
			"a denied command",
			api.PolicyRule{CommandConstraints: &api.Constraint{Denied: []string{"curl *"}}},
			"command", "curl *",
		},
		{
			"an allowed command, which is the whitelist shape",
			api.PolicyRule{CommandConstraints: &api.Constraint{Allowed: []string{"ls *"}}},
			"command", "ls *",
		},
		{
			"a path",
			api.PolicyRule{PathConstraints: &api.PathConstraint{Denied: []string{"/etc/*"}}},
			"path", "/etc/*",
		},
		{
			"a filename",
			api.PolicyRule{FilenameConstraints: &api.Constraint{Denied: []string{"*.pem"}}},
			"filename", "*.pem",
		},
		{
			"a url",
			api.PolicyRule{URLConstraints: &api.Constraint{Denied: []string{"http://*"}}},
			"url", "http://*",
		},
		{
			"several patterns in one rule",
			api.PolicyRule{CommandConstraints: &api.Constraint{Denied: []string{"curl *", "wget *"}}},
			"command", "curl *, wget *",
		},
		{
			// No constraints at all: the rule is about the tool, and its tool pattern
			// is the only thing it matches on. Printing nothing here would reproduce
			// the blank row this column exists to remove.
			"a rule about a tool",
			api.PolicyRule{ToolPattern: "Bash"},
			"tool", "Bash",
		},
		{
			"a rule about every tool",
			api.PolicyRule{ToolPattern: "*"},
			"tool", "*",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind, patt := ruleMatch(c.rule)
			if kind != c.kind || patt != c.patt {
				t.Errorf("ruleMatch() = %q %q, want %q %q", kind, patt, c.kind, c.patt)
			}
		})
	}
}

// A RULE WITH NO DESCRIPTION IS STILL FULLY READABLE, which is the case that prompted
// this: the dataroom writes no description, so those rules were the blank ones.
func TestARuleWithNoDescriptionStillShowsWhatItDoes(t *testing.T) {
	r := api.PolicyRule{
		Effect:             "DENY",
		Priority:           100,
		CommandConstraints: &api.Constraint{Denied: []string{"rm -rf *"}},
	}
	kind, patt := ruleMatch(r)
	if kind == "" || patt == "" {
		t.Fatalf("a rule with no description reports %q %q — the row would be blank", kind, patt)
	}
	if patt != "rm -rf *" {
		t.Errorf("pattern = %q, want the thing it actually blocks", patt)
	}
}
