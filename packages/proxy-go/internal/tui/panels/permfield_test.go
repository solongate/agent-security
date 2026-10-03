package panels

import (
	"testing"

	"github.com/codeyevsky/solongate/proxy/internal/api"
)

// PERMISSIONS ARE ONLY A QUESTION FOR A RULE ABOUT FILES.
//
// READ, WRITE, EXECUTE and NETWORK come from the TOOL a call was made with, so narrowing
// by them says which KIND of tool a rule covers. For a path or a filename that is a real
// choice — block reading a directory but not writing to it. For a command rule it is
// noise: it already only matches a command. For a URL rule it already only matches a
// fetch. The row sat on both anyway, showing all four lit as though somebody had chosen
// them, and it is one of the three rows where ←→ edits instead of navigating.
func TestPermissionsAppearOnlyForFileRules(t *testing.T) {
	has := func(fields []polField) bool {
		for _, f := range fields {
			if f.kind == "perms" {
				return true
			}
		}
		return false
	}

	cases := []struct {
		name string
		rule api.PolicyRule
		want bool
	}{
		{
			"a path rule",
			api.PolicyRule{PathConstraints: &api.PathConstraint{Denied: []string{"/etc/*"}}},
			true,
		},
		{
			"a filename rule",
			api.PolicyRule{FilenameConstraints: &api.Constraint{Denied: []string{"*.pem"}}},
			true,
		},
		{
			"a command rule, which is already only commands",
			api.PolicyRule{CommandConstraints: &api.Constraint{Denied: []string{"curl *"}}},
			false,
		},
		{
			"a url rule, which is already only fetches",
			api.PolicyRule{URLConstraints: &api.Constraint{Denied: []string{"http://*"}}},
			false,
		},
		{
			"a rule with no constraint at all",
			api.PolicyRule{ToolPattern: "*"},
			false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := has(fieldsFor(c.rule)); got != c.want {
				t.Errorf("permissions row present = %v, want %v", got, c.want)
			}
		})
	}
}

// AND THE OTHER FIVE ROWS ARE ALWAYS THERE. Hiding one row must not drop another: the
// cursor indexes this list, so a short list is also what the editor can reach.
func TestEveryOtherFieldSurvives(t *testing.T) {
	want := []string{"effect", "ctype", "priority", "text", "match"}

	for _, r := range []api.PolicyRule{
		{CommandConstraints: &api.Constraint{Denied: []string{"curl *"}}},
		{PathConstraints: &api.PathConstraint{Denied: []string{"/etc/*"}}},
	} {
		fields := fieldsFor(r)
		for _, kind := range want {
			found := false
			for _, f := range fields {
				if f.kind == kind {
					found = true
				}
			}
			if !found {
				t.Errorf("%q is missing from the editor for %v", kind, currentCType(r))
			}
		}
	}
}
