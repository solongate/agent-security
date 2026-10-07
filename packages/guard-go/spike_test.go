// SPDX-License-Identifier: Apache-2.0

package main

// De-risks the one thing the whole port rests on: can this evaluate the same
// Rego the API already generates, with the same answers, and how long does it
// take compared with the 27ms the Node hook spends instantiating WASM per call?
//
// Run: go test -run TestRego -v

import (
	"context"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/rego"
)

// Shaped like what convertPolicySetToRego emits: a default allow, and a deny
// rule keyed off the command.
const policySrc = `
package solongate.policy

# Spelled out rather than relying on the parser's default dialect: rego.Module
# parses as v0 unless told otherwise, and "some x in xs" is v1 syntax.
import future.keywords.in
import future.keywords.if

default decision := {"allow": true, "reason": ""}

decision := {"allow": false, "reason": r} if {
	some rule in deny_rules
	glob.match(rule.pattern, [], input.command)
	r := rule.reason
}

deny_rules := [
	{"pattern": "*sg-conformance-deny*", "reason": "blocked by the conformance rule"},
	{"pattern": "sudo*", "reason": "privilege escalation"},
]
`

func evalOnce(t *testing.T, q rego.PreparedEvalQuery, cmd string) map[string]interface{} {
	t.Helper()
	rs, err := q.Eval(context.Background(), rego.EvalInput(map[string]interface{}{"command": cmd}))
	if err != nil {
		t.Fatalf("eval %q: %v", cmd, err)
	}
	if len(rs) == 0 {
		t.Fatalf("eval %q: no result", cmd)
	}
	m, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		t.Fatalf("eval %q: unexpected shape %T", cmd, rs[0].Expressions[0].Value)
	}
	return m
}

func TestRego(t *testing.T) {
	ctx := context.Background()

	t0 := time.Now()
	q, err := rego.New(
		rego.Query("data.solongate.policy.decision"),
		rego.Module("policy.rego", policySrc),
	).PrepareForEval(ctx)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	prepare := time.Since(t0)

	if got := evalOnce(t, q, "echo hello"); got["allow"] != true {
		t.Errorf("plain command should be allowed, got %v", got)
	}
	if got := evalOnce(t, q, "echo sg-conformance-deny"); got["allow"] != false {
		t.Errorf("marked command should be denied, got %v", got)
	} else {
		t.Logf("deny reason: %v", got["reason"])
	}
	if got := evalOnce(t, q, "sudo rm -rf /"); got["allow"] != false {
		t.Errorf("sudo should be denied, got %v", got)
	}

	// The number that decides the port: the Node hook pays ~27ms per call to
	// instantiate WASM. Here preparation happens once and each decision is what
	// a call actually costs.
	const n = 200
	t1 := time.Now()
	for i := 0; i < n; i++ {
		evalOnce(t, q, "echo hello")
	}
	per := time.Since(t1) / n

	t.Logf("prepare (once): %v", prepare)
	t.Logf("per decision:   %v", per)
	t.Logf("node hook spends ~27ms per call instantiating WASM it then discards")
}
