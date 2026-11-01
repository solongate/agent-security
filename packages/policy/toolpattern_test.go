// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package policy

import (
	"testing"
)

func listPtr(items ...string) *ListConstraints {
	return &ListConstraints{Denied: items}
}

func pathSet(patterns ...string) *PathConstraintSet {
	return &PathConstraintSet{Denied: patterns}
}

// Issue #208: the fallback path ignored ToolPattern, so a rule scoped to one
// tool fired for any tool whose paths matched. These tests pin the gate.

func TestFallbackEvaluateRespectsToolPatternOnDeny(t *testing.T) {
	rules := []PolicyRule{{
		ID:                 "no-rm-via-bash",
		Effect:             "DENY",
		ToolPattern:        "Bash",
		CommandConstraints: listPtr("rm -rf*"),
	}}
	args := map[string]interface{}{
		"command": "rm -rf /",
	}

	if got := FallbackEvaluate(rules, "denylist", args, "SomeOtherTool"); got != "" {
		t.Errorf("rule scoped to Bash fired for SomeOtherTool: %q", got)
	}
	if got := FallbackEvaluate(rules, "denylist", args, "Bash"); got == "" {
		t.Error("rule scoped to Bash should fire for Bash")
	}
}

func TestFallbackEvaluateRespectsToolPatternOnAllow(t *testing.T) {
	rules := []PolicyRule{{
		ID:              "read-only-allow",
		Effect:          "ALLOW",
		ToolPattern:     "Read",
		PathConstraints: pathSet("/tmp/*"),
	}}
	args := map[string]interface{}{
		"path": "/tmp/notes.txt",
	}

	// whitelist mode: a Bash request must NOT be authorized by Read's allow rule
	if got := FallbackEvaluate(rules, "whitelist", args, "Bash"); got == "" {
		t.Error("allow rule scoped to Read authorized Bash in whitelist mode")
	}
	if got := FallbackEvaluate(rules, "whitelist", args, "Read"); got != "" {
		t.Errorf("allow rule scoped to Read should authorize Read: %q", got)
	}
}

func TestToolPatternGlobSemantics(t *testing.T) {
	rules := []PolicyRule{{
		ID:                 "suffix-wildcard",
		Effect:             "DENY",
		ToolPattern:        "*Write",
		CommandConstraints: listPtr("rm*"),
	}}
	args := map[string]interface{}{"command": "rm -rf /"}

	if got := FallbackEvaluate(rules, "denylist", args, "FileWrite"); got == "" {
		t.Error("*Write glob should match FileWrite")
	}
	if got := FallbackEvaluate(rules, "denylist", args, "WriteFiles"); got != "" {
		t.Errorf("*Write glob should not match WriteFiles: %q", got)
	}
}

// PR #209 made the fallback path honor ToolPattern via MatchGlob, which folds
// case. The Rego path (generateToolPatternCondition) compares input.tool_name
// case-sensitively, so a mixed-case pattern must not match a differently-cased
// tool name in the fallback path either, or the two evaluators disagree.
func TestToolPatternIsCaseSensitive(t *testing.T) {
	rules := []PolicyRule{{
		ID:                 "exact-bash",
		Effect:             "DENY",
		ToolPattern:        "bash",
		CommandConstraints: listPtr("rm*"),
	}}
	args := map[string]interface{}{"command": "rm -rf /"}

	if got := FallbackEvaluate(rules, "denylist", args, "Bash"); got != "" {
		t.Errorf("ToolPattern %q should not match differently-cased tool name %q: %q", "bash", "Bash", got)
	}
	if got := FallbackEvaluate(rules, "denylist", args, "bash"); got == "" {
		t.Error("ToolPattern \"bash\" should match exact tool name \"bash\"")
	}
}
