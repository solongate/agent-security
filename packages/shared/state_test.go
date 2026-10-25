// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package shared

import (
	"encoding/json"
	"testing"
)

func TestPolicyAppliesTo(t *testing.T) {
	var nilPolicy *Policy
	if !nilPolicy.AppliesTo("claude-code") {
		t.Error("a nil policy should apply to everything")
	}

	empty := &Policy{}
	if !empty.AppliesTo("claude-code") {
		t.Error("a policy with no agents listed should apply to everything")
	}

	wildcard := &Policy{Agents: []string{"*"}}
	if !wildcard.AppliesTo("anything") {
		t.Error("a wildcard agent entry should match any client")
	}

	scoped := &Policy{Agents: []string{"claude-code"}}
	if !scoped.AppliesTo("claude-code") {
		t.Error("expected an exact client match to apply")
	}
	if scoped.AppliesTo("cursor") {
		t.Error("expected a non-matching client to not apply")
	}
}

func TestPolicyCacheUnmarshalTracksHasSecurity(t *testing.T) {
	withSecurity := []byte(`{"_ts":1,"policy":null,"security":{"requireSandbox":true}}`)
	var c PolicyCache
	if err := json.Unmarshal(withSecurity, &c); err != nil {
		t.Fatal(err)
	}
	if !c.HasSecurity {
		t.Error("expected HasSecurity=true when the security field is present")
	}
	if c.Security == nil || !c.Security.RequireSandbox {
		t.Errorf("expected security to be decoded, got %+v", c.Security)
	}

	withoutSecurity := []byte(`{"_ts":1,"policy":null}`)
	var c2 PolicyCache
	if err := json.Unmarshal(withoutSecurity, &c2); err != nil {
		t.Fatal(err)
	}
	if c2.HasSecurity {
		t.Error("expected HasSecurity=false when the security field is absent")
	}
}

func TestPolicyCacheUnmarshalRejectsInvalidJSON(t *testing.T) {
	var c PolicyCache
	if err := json.Unmarshal([]byte(`not json`), &c); err == nil {
		t.Error("expected an error for invalid JSON")
	}
}
