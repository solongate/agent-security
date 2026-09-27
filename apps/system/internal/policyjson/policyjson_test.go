package policyjson

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// These tests are about ONE number: the SHA-256 the policy routes store, list
// and hand to the guard. Every case below is a place where Go's encoding/json
// and JavaScript's JSON.stringify produce different bytes for the same value,
// which would produce a different hash for the same policy.

func TestKeyOrderIsInsertionOrderNotSorted(t *testing.T) {
	o, ok := ParseObject([]byte(`{"name":"P","id":"p","rules":[]}`))
	if !ok {
		t.Fatal("that is an object")
	}
	if got, want := Stringify(o, nil), `{"name":"P","id":"p","rules":[]}`; got != want {
		t.Errorf("Stringify = %s, want %s — Go sorts map keys and JavaScript does not, "+
			"so a sorted round trip rehashes every policy", got, want)
	}
}

func TestAngleBracketsAndAmpersandsAreNotEscaped(t *testing.T) {
	o, _ := ParseObject([]byte(`{"command":"sh -c 'a && b > c'"}`))
	got := Stringify(o, nil)
	want := `{"command":"sh -c 'a && b > c'"}`
	if got != want {
		t.Errorf("Stringify = %s, want %s — Go's encoder rewrites < > & as \\u00xx "+
			"and JSON.stringify never has; policy rules are full of all three", got, want)
	}
}

// The one that is genuinely surprising. `JSON.stringify(body,
// Object.keys(body).sort())` is not "serialise with sorted keys". The array is
// a property ALLOW-LIST, applied at EVERY level — so the rules nested inside
// the policy are filtered down to whichever of their own fields happen to share
// a name with a top-level key of the policy.
func TestArrayReplacerIsAnAllowListAtEveryLevel(t *testing.T) {
	o, _ := ParseObject([]byte(`{"id":"p","name":"P","rules":[{"id":"r1","effect":"DENY","name":"x"}]}`))

	got := Stringify(o, o.SortedKeys())
	want := `{"id":"p","name":"P","rules":[{"id":"r1","name":"x"}]}`
	if got != want {
		t.Errorf("Stringify with a property list = %s, want %s.\n"+
			"The nested rule keeps only `id` and `name` because those are the only "+
			"top-level policy keys it also has; `effect` is filtered out. Serialising "+
			"the whole object instead would change the hash of every stored policy.",
			got, want)
	}
}

func TestPropertyListOrdersTheOutput(t *testing.T) {
	o, _ := ParseObject([]byte(`{"z":1,"a":2}`))
	if got, want := Stringify(o, o.SortedKeys()), `{"a":2,"z":1}`; got != want {
		t.Errorf("Stringify = %s, want %s", got, want)
	}
}

func TestUndefinedIsOmittedFromObjectsAndNulledInArrays(t *testing.T) {
	o := NewObject()
	o.Set("a", Undef)
	o.Set("b", float64(1))
	if got, want := Stringify(o, nil), `{"b":1}`; got != want {
		t.Errorf("Stringify = %s, want %s — an undefined property is omitted, not null", got, want)
	}
	if got, want := Stringify([]any{Undef, float64(1)}, nil), `[null,1]`; got != want {
		t.Errorf("Stringify = %s, want %s — an undefined ELEMENT is null, not a gap", got, want)
	}
}

func TestNumbersFollowECMAScriptToString(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{-0, "0"},
		{1, "1"},
		{100, "100"},
		{1.5, "1.5"},
		{-2.25, "-2.25"},
		{10000, "10000"},
		{1e20, "100000000000000000000"},
		{1e21, "1e+21"},
		{0.000001, "0.000001"},
		{1e-7, "1e-7"},
		{1.5e-7, "1.5e-7"},
	}
	for _, c := range cases {
		if got := NumberString(c.in); got != c.want {
			t.Errorf("NumberString(%v) = %q, want %q — this is the boundary where "+
				"Go's formatter and JavaScript's disagree", c.in, got, c.want)
		}
	}
}

func TestControlCharactersUseTheNamedEscapes(t *testing.T) {
	o := NewObject()
	o.Set("s", "a\nb\tc\u0001d")
	// \n and \t take their named escapes; anything else below 0x20 takes the
	// four-digit form, in LOWERCASE hex, as JSON.stringify writes it.
	if got, want := Stringify(o, nil), `{"s":"a\nb\tc\u0001d"}`; got != want {
		t.Errorf("Stringify = %s, want %s", got, want)
	}
}

// An absent `permission` and an explicit null are different values and both
// have to survive normalisation unchanged: absent stays absent, null stays
// null. Collapsing them rewrites every stored policy.
func TestNormalizeRulesKeepsAbsentAndNullPermissionApart(t *testing.T) {
	rules, _ := Array(mustParse(t, `[{"id":"a"},{"id":"b","permission":null}]`))
	got := Stringify(NormalizeRules(rules), nil)
	want := `[{"id":"a","enabled":true},{"id":"b","permission":null,"enabled":true}]`
	if got != want {
		t.Errorf("NormalizeRules = %s, want %s", got, want)
	}
}

func TestSetKeepsAnExistingKeysPosition(t *testing.T) {
	o, _ := ParseObject([]byte(`{"a":1,"rules":[],"z":2}`))
	o.Set("rules", []any{float64(1)})
	if got, want := Stringify(o, nil), `{"a":1,"rules":[1],"z":2}`; got != want {
		t.Errorf("Stringify = %s, want %s — replacing `rules` must not move it to the end, "+
			"or a policy nobody edited gets a new hash", got, want)
	}
}

// ── normalizeRules ──────────────────────────────────────────────────────────

func TestNormalizeRulesDropsAPermissionListThatCoversEverything(t *testing.T) {
	rules, _ := Array(mustParse(t, `[{"id":"r","permission":["READ","WRITE","EXECUTE","NETWORK"]}]`))
	out := NormalizeRules(rules)
	got := Stringify(out, nil)
	want := `[{"id":"r","enabled":true}]`
	if got != want {
		t.Errorf("NormalizeRules = %s, want %s — a rule scoped to every permission is "+
			"not scoped by permission, and it has to become UNDEFINED rather than null: "+
			"null would read as 'scoped to no permission at all'", got, want)
	}
}

func TestNormalizeRulesUnwrapsASinglePermission(t *testing.T) {
	rules, _ := Array(mustParse(t, `[{"id":"r","permission":["READ"]}]`))
	if got, want := Stringify(NormalizeRules(rules), nil), `[{"id":"r","permission":"READ","enabled":true}]`; got != want {
		t.Errorf("NormalizeRules = %s, want %s", got, want)
	}
}

func TestNormalizeRulesOnlyDisablesOnLiteralFalse(t *testing.T) {
	rules, _ := Array(mustParse(t, `[{"id":"a"},{"id":"b","enabled":false},{"id":"c","enabled":0}]`))
	got := Stringify(NormalizeRules(rules), nil)
	want := `[{"id":"a","enabled":true},{"id":"b","enabled":false},{"id":"c","enabled":true}]`
	if got != want {
		t.Errorf("NormalizeRules = %s, want %s — `r.enabled !== false` is strict, so 0 "+
			"and a missing field both mean enabled", got, want)
	}
}

func TestNormalizeRulesKeepsEnabledInPlace(t *testing.T) {
	rules, _ := Array(mustParse(t, `[{"enabled":true,"id":"r"}]`))
	if got, want := Stringify(NormalizeRules(rules), nil), `[{"enabled":true,"id":"r"}]`; got != want {
		t.Errorf("NormalizeRules = %s, want %s", got, want)
	}
}

// A whole-policy hash, end to end, so the two spellings the routes use are
// exercised together rather than only their pieces.
func TestPolicyHashIsStableAcrossTheTwoSpellings(t *testing.T) {
	o, _ := ParseObject([]byte(`{"id":"p","name":"P","description":"d","rules":[{"id":"r","effect":"DENY","enabled":true}]}`))

	withList := sha256Hex(Stringify(o, o.SortedKeys()))
	whole := sha256Hex(Stringify(o, nil))
	if withList == whole {
		t.Error("the two hashes must differ — POST/PUT hash through a property list and " +
			"the rules routes do not, and collapsing them would silently rewrite one of the two")
	}
	// Recomputing must be deterministic; a policy that rehashes differently on
	// every save makes the guard treat an unchanged policy as changed.
	if sha256Hex(Stringify(o, o.SortedKeys())) != withList {
		t.Error("the hash is not stable across two serialisations of the same value")
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func mustParse(t *testing.T, s string) any {
	t.Helper()
	v, err := Parse([]byte(s))
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return v
}
