// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"testing"
)

// THE SAME CONSTRAINT, ONCE PER TOOL CLASS, IS TWO RULES.
//
// The dedupe key was effect + tool pattern + constraints, and permission was not
// in it. So a path denied for READ and the same path denied for WRITE collapsed
// to one rule, and the second add answered "Equivalent DENY rule already
// present" -- a success line for a rule that had been thrown away. The policy
// then looked complete while the write half of it did not exist.
func TestARuleScopedToADifferentPermissionIsNotADuplicate(t *testing.T) {
	read := PolicyRule{
		Effect: "DENY", ToolPattern: "*",
		PathConstraints: &PathConstraint{Denied: []string{"/forbidden/*"}},
		Permission:      json.RawMessage(`["READ"]`),
	}
	write := read
	write.Permission = json.RawMessage(`["WRITE"]`)

	if permissionKey(read) == permissionKey(write) {
		t.Fatal("READ and WRITE produced the same dedupe key, so one of the two rules is silently dropped")
	}
}

// Scoping is not the same as not scoping. An unscoped rule covers every class,
// so it is a broader rule and a distinct one.
func TestAnUnscopedRuleIsNotADuplicateOfAScopedOne(t *testing.T) {
	scoped := PolicyRule{Effect: "DENY", Permission: json.RawMessage(`["READ"]`)}
	unscoped := PolicyRule{Effect: "DENY"}

	if permissionKey(scoped) == permissionKey(unscoped) {
		t.Fatal("a READ-scoped rule deduped against an unscoped one, which covers strictly more")
	}
	if got := permissionKey(unscoped); got != "" {
		t.Errorf("an unscoped rule keyed as %q, want the empty key", got)
	}
}

// ORDER IS NOT MEANING. READ,WRITE and WRITE,READ are one scope; keying them
// apart would let two rules that shadow each other both into the list.
func TestThePermissionKeyIgnoresOrder(t *testing.T) {
	a := PolicyRule{Permission: json.RawMessage(`["READ","WRITE"]`)}
	b := PolicyRule{Permission: json.RawMessage(`["WRITE","READ"]`)}
	if permissionKey(a) != permissionKey(b) {
		t.Fatalf("%q and %q are the same scope written two ways", permissionKey(a), permissionKey(b))
	}
}

// The field arrives as a bare string as well as an array, and both spellings
// have to key the same or a rule written one way duplicates one written the other.
func TestABareStringPermissionKeysLikeAOneElementArray(t *testing.T) {
	one := PolicyRule{Permission: json.RawMessage(`"READ"`)}
	arr := PolicyRule{Permission: json.RawMessage(`["READ"]`)}
	if permissionKey(one) != permissionKey(arr) {
		t.Fatalf(`"READ" keyed as %q but ["READ"] as %q`, permissionKey(one), permissionKey(arr))
	}
}
