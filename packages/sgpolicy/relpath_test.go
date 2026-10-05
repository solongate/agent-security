package sgpolicy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/codeyevsky/solongate/sgshared"
)

// THE SAME FILE, TWO WAYS OF NAMING IT.
//
// A path rule is written absolute, because that is what a file tool sends: the
// client resolves the path before the hook sees the call. A shell command
// carries whatever the model typed, and a model sitting in the directory types
// a relative path. So `Read /abs/forbidden/notes.txt` was refused and
// `cat forbidden/notes.txt` went through, against one rule, in one directory.
func policyDenyingPath(pattern string, perms []string) *sgshared.Policy {
	rule := map[string]interface{}{
		"id":          "r1",
		"effect":      "DENY",
		"enabled":     true,
		"toolPattern": "*",
		"pathConstraints": map[string]interface{}{
			"denied": []interface{}{pattern},
		},
	}
	if len(perms) > 0 {
		rule["permission"] = perms
	}
	raw, err := json.Marshal([]interface{}{rule})
	if err != nil {
		panic(err)
	}
	return &sgshared.Policy{Mode: "denylist", Rules: raw}
}

func TestARelativePathInAShellCommandHitsAnAbsolutePathRule(t *testing.T) {
	pol := policyDenyingPath("/home/u/proj/forbidden/*", nil)

	reason := EvaluatePolicy(pol, map[string]interface{}{
		"command": "cat forbidden/notes.txt",
	}, "Bash", "/home/u/proj")

	if reason == "" {
		t.Fatal("cat with a relative path walked past the rule that refuses the same file read absolutely")
	}
	if !strings.Contains(reason, "forbidden") {
		t.Errorf("refused, but the reason does not name the path: %q", reason)
	}
}

// The EXECUTE-scoped case is the one the manual run caught: the filename-scoped
// EXECUTE rule beside it fired, so the scope was not the problem, the path was.
func TestAnExecuteScopedPathRuleCatchesARelativeCommandPath(t *testing.T) {
	pol := policyDenyingPath("/home/u/proj/forbidden/exec/*", []string{"EXECUTE"})

	if reason := EvaluatePolicy(pol, map[string]interface{}{
		"command": "cat forbidden/exec/notes.txt",
	}, "Bash", "/home/u/proj"); reason == "" {
		t.Fatal("an EXECUTE-scoped path rule did not hold against a relative path in a Bash command")
	}
}

// `./x` and `../x` are the same two dodges written differently.
func TestDotAndDotDotResolveToo(t *testing.T) {
	pol := policyDenyingPath("/home/u/proj/forbidden/*", nil)

	if reason := EvaluatePolicy(pol, map[string]interface{}{
		"command": "cat ./forbidden/notes.txt",
	}, "Bash", "/home/u/proj"); reason == "" {
		t.Error("./ prefix walked past the rule")
	}
	if reason := EvaluatePolicy(pol, map[string]interface{}{
		"command": "cat ../forbidden/notes.txt",
	}, "Bash", "/home/u/proj/work"); reason == "" {
		t.Error("../ walked past the rule")
	}
}

// AND THE DIRECTION THAT MATTERS MORE: resolving must not invent a match. A
// relative path under a DIFFERENT cwd is a different file and has to stay one.
func TestAPathOutsideTheRuleStaysOutsideIt(t *testing.T) {
	pol := policyDenyingPath("/home/u/proj/forbidden/*", nil)

	if reason := EvaluatePolicy(pol, map[string]interface{}{
		"command": "cat forbidden/notes.txt",
	}, "Bash", "/home/u/other"); reason != "" {
		t.Fatalf("a file in another directory was refused by this rule: %q", reason)
	}
	if reason := EvaluatePolicy(pol, map[string]interface{}{
		"command": "cat work/notes.txt",
	}, "Bash", "/home/u/proj"); reason != "" {
		t.Fatalf("an unrelated file was refused: %q", reason)
	}
}

// With no cwd there is nothing to resolve against, and guessing one would
// refuse calls on the strength of where the guard happened to be started.
func TestNoCwdLeavesTheLiteralMatchAlone(t *testing.T) {
	if got := AbsolutizePaths([]string{"forbidden/notes.txt"}, ""); len(got) > 0 {
		// os.Getwd is the documented fallback; it must not produce the rule's dir
		// by accident in this test's environment.
		for _, g := range got {
			if strings.Contains(g, "/home/u/proj/") {
				t.Fatalf("resolved to %q with no cwd given", g)
			}
		}
	}
}

// An absolute token is already resolved; re-adding it would double every path.
func TestAnAbsoluteTokenIsNotResolvedAgain(t *testing.T) {
	if got := AbsolutizePaths([]string{"/already/abs.txt", "~/home.txt"}, "/base"); len(got) != 0 {
		t.Fatalf("resolved paths that needed no resolving: %v", got)
	}
}
