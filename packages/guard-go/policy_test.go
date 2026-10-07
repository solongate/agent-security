// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"testing"

	"github.com/codeyevsky/solongate/sgpolicy"
	"github.com/codeyevsky/solongate/sgshared"
)

// What is left here after the policy engine moved to packages/sgpolicy: the
// wiring this binary owns. The engine's own behaviour is tested beside the
// engine, so a change there fails there rather than in whichever consumer
// happened to notice.

func policyFrom(t *testing.T, mode, rulesJSON string) *sgshared.Policy {
	t.Helper()
	return &sgshared.Policy{ID: "t", Name: "t", Mode: mode, Rules: json.RawMessage(rulesJSON)}
}

func args(pairs ...interface{}) map[string]interface{} {
	m := map[string]interface{}{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i].(string)] = pairs[i+1]
	}
	return m
}

// Aliased argument keys are neutralised before anything looks at them, so a
// rule written against the neutral name matches whichever client sent the call.
func TestPolicyArgumentKeyAliases(t *testing.T) {
	rules := `[{
	  "id":"no-secrets","description":"no secrets dir","effect":"DENY","priority":10,
	  "toolPattern":"*","minimumTrustLevel":"UNTRUSTED","enabled":true,
	  "argumentConstraints":{"file_path":{"$contains":"/secrets/"}}
	}]`
	pol := policyFrom(t, "denylist", rules)
	dir := t.TempDir()

	// The rule names file_path; the client sent notebook_path.
	neutral := neutralizeArgs(args("notebook_path", "/secrets/a.ipynb", "new_source", "x"),
		[]string{"notebook_path", "new_source"})
	if r := sgpolicy.EvaluatePolicy(pol, neutral, "NotebookEdit", dir); r == "" {
		t.Error("notebook_path must be seen as file_path")
	}

	// And the first value wins for a neutral name, in payload order.
	both := neutralizeArgs(args("command", "ls", "cmd", "cat .env"), []string{"command", "cmd"})
	if both["command"] != "ls" {
		t.Errorf("the first key in the payload should win, got %v", both["command"])
	}
}
