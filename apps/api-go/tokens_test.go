package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/codeyevsky/solongate/api/internal/policyjson"
)

// What these tests are for.
//
// The capability token is a wire format shared with a service that is still
// running, so the thing worth pinning is not "does it round-trip through this
// file" — it would round-trip through any self-consistent format — but "is it
// the SAME bytes jose produces". The goldens below were computed by node
// against the installed jose 5.10.0, using src/lib/security.ts's
// generateCapabilityToken with the clock and the nonce fixed:
//
//	new jose.SignJWT({tool, scope, nonce, projectId})
//	  .setProtectedHeader({alg:'HS256'})
//	  .setIssuedAt(iat).setExpirationTime(exp).setIssuer('solongate')
//	  .sign(new TextEncoder().encode(secret))
//
// They are recorded as SHA-256 of the token rather than the token itself so a
// grep for a JWT in this repository never turns up a real-looking one.
//
// If one of these fails, the port has stopped producing tokens the live service
// can verify. That is a cutover outage, not a test to update.

const (
	goldenTokenHashA = "02e26e096d443fd472f6effedb472b69fc9c42cbd2b03df8341894eb7a56b7b2"
	goldenTokenHashB = "4e8e59860dce848df2d57974f7ea811693bda7c314942cbb4fac1660f4f16f3a"
)

func TestCapabilityTokenMatchesJose(t *testing.T) {
	cases := []struct {
		name   string
		claims capabilityClaims
		secret string
		want   string
	}{
		{
			// The angle brackets and the ampersand are the point: Go's JSON
			// encoder escapes all three by default and JSON.stringify does not,
			// so a token for a tool named like this is where the two
			// implementations diverge first.
			name: "characters Go would escape",
			claims: capabilityClaims{
				Tool: "read_file<x>&y", Scope: "READ:read_file<x>&y",
				Nonce: "5a1a4d3c-0000-4000-8000-000000000abc", ProjectID: "p-golden",
				IssuedAt: 1700000000, ExpiresAt: 1700000030, Issuer: capabilityIssuer,
			},
			secret: "golden-secret",
			want:   goldenTokenHashA,
		},
		{
			name: "an ordinary token",
			claims: capabilityClaims{
				Tool: "plain", Scope: "EXECUTE:plain",
				Nonce: "11111111-2222-4333-8444-555555555555", ProjectID: "p1",
				IssuedAt: 1785700000, ExpiresAt: 1785700030, Issuer: capabilityIssuer,
			},
			secret: "s3cr3t",
			want:   goldenTokenHashB,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := encodeCapability(tc.claims, tc.secret)
			if err != nil {
				t.Fatalf("encodeCapability: %v", err)
			}
			sum := sha256.Sum256([]byte(token))
			if got := hex.EncodeToString(sum[:]); got != tc.want {
				t.Errorf("token hash = %s, want %s — this token will not verify in the Node service", got, tc.want)
			}
		})
	}
}

// The protected header is a constant and it has to stay a constant: one extra
// member changes the signing input for every token.
func TestCapabilityHeaderIsAlgOnly(t *testing.T) {
	raw, err := base64.RawURLEncoding.DecodeString(capabilityHeader)
	if err != nil {
		t.Fatalf("header is not base64url: %v", err)
	}
	if string(raw) != `{"alg":"HS256"}` {
		t.Errorf("protected header = %s, want {\"alg\":\"HS256\"}", raw)
	}
}

// The claim ORDER. jose spreads the constructor payload and appends iat, exp
// and iss in call order; encoding/json emits struct fields in declaration
// order, and the two have to agree for the goldens above to hold at all.
func TestCapabilityClaimOrder(t *testing.T) {
	body, err := marshalNoEscape(capabilityClaims{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	claims, ok := policyjson.ParseObject(body)
	if !ok {
		t.Fatalf("claims are not an object: %s", body)
	}
	want := []string{"tool", "scope", "nonce", "projectId", "iat", "exp", "iss"}
	got := claims.Keys()
	if len(got) != len(want) {
		t.Fatalf("claims = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("claims = %v, want %v", got, want)
		}
	}
}

// ── the evaluator ───────────────────────────────────────────────────────────

// The quirks, each one a rule that would match differently if the port had
// tidied it up. Every expectation here was confirmed against the TypeScript by
// running both over the same policy; see the differential in the scratchpad.
func TestValidateEvaluatePolicyQuirks(t *testing.T) {
	const document = `{"rules":[
		{"id":"disabled","effect":"ALLOW","priority":1,"toolPattern":"*","minimumTrustLevel":"UNTRUSTED","enabled":false},
		{"id":"null-enabled","effect":"DENY","priority":5,"toolPattern":"secret_*","minimumTrustLevel":"UNTRUSTED","enabled":null},
		{"id":"empty-permission","effect":"ALLOW","priority":6,"toolPattern":"empty_perm","permission":[],"minimumTrustLevel":"UNTRUSTED"},
		{"id":"suffix","effect":"ALLOW","priority":10,"toolPattern":"*_file","permission":["READ","WRITE"],"minimumTrustLevel":"VERIFIED"},
		{"id":"star-literal","effect":"ALLOW","priority":11,"toolPattern":"we*ird","minimumTrustLevel":"UNTRUSTED"},
		{"id":"trusted-only","effect":"ALLOW","priority":20,"toolPattern":"admin_*","permission":"EXECUTE","minimumTrustLevel":"TRUSTED"},
		{"id":"bad-trust","effect":"ALLOW","priority":30,"toolPattern":"weird_trust","minimumTrustLevel":"SUPER"},
		{"id":"no-priority","effect":"ALLOW","toolPattern":"nopriority","minimumTrustLevel":"UNTRUSTED"},
		{"id":"catch-all","effect":"DENY","priority":10000,"toolPattern":"*","minimumTrustLevel":"UNTRUSTED"}
	]}`

	policy, ok := policyjson.ParseObject([]byte(document))
	if !ok {
		t.Fatal("test policy is not an object")
	}
	rules, _ := policyjson.Array(policy.Get("rules"))

	cases := []struct {
		name       string
		tool       string
		permission any
		trust      string
		wantEffect string
		wantRule   string
	}{
		{"a disabled rule never fires", "anything", "EXECUTE", "VERIFIED", "DENY", "catch-all"},
		{"enabled null is still enabled", "secret_dump", "EXECUTE", "TRUSTED", "DENY", "null-enabled"},
		{"an empty permission list matches nothing", "empty_perm", "READ", "TRUSTED", "DENY", "catch-all"},
		{"a suffix pattern", "read_file", "READ", "VERIFIED", "ALLOW", "suffix"},
		{"a permission outside the rule's list", "read_file", "EXECUTE", "VERIFIED", "DENY", "catch-all"},
		{"trust below the rule's minimum", "read_file", "READ", "UNTRUSTED", "DENY", "catch-all"},
		{"a star in the middle is literal", "we*ird", "EXECUTE", "UNTRUSTED", "ALLOW", "star-literal"},
		{"and matches nothing else", "weird", "EXECUTE", "UNTRUSTED", "DENY", "catch-all"},
		{"an unrecognised minimum trust matches everyone", "weird_trust", "EXECUTE", "UNTRUSTED", "ALLOW", "bad-trust"},
		{"a rule with no priority keeps its place", "nopriority", "EXECUTE", "UNTRUSTED", "ALLOW", "no-priority"},
		{"a prefix pattern needs the trust", "admin_reset", "EXECUTE", "VERIFIED", "DENY", "catch-all"},
		{"and matches with it", "admin_reset", "EXECUTE", "TRUSTED", "ALLOW", "trusted-only"},
		{"a permission of the wrong TYPE is not the same value", "read_file", 1.0, "VERIFIED", "DENY", "catch-all"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision, err := validateEvaluatePolicy(tc.tool, tc.permission, tc.trust, rules)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if decision.effect != tc.wantEffect {
				t.Errorf("effect = %v, want %s", decision.effect, tc.wantEffect)
			}
			if decision.matchedRuleID != tc.wantRule {
				t.Errorf("matched rule = %q, want %q (reason %q)", decision.matchedRuleID, tc.wantRule, decision.reason)
			}
			if string(decision.matchedRule) == "" {
				t.Error("matched_rule is empty; the dashboard renders the whole rule")
			}
		})
	}
}

// A policy the live evaluator would have thrown on must not quietly evaluate
// here. The skipped rule could be the DENY that was holding something back.
func TestValidateEvaluatePolicyRefusesBrokenRules(t *testing.T) {
	broken := []string{
		`{"rules":[{"id":"r","effect":"ALLOW","priority":1,"minimumTrustLevel":"UNTRUSTED"}]}`,
		`{"rules":[{"id":"r","effect":"ALLOW","priority":1,"toolPattern":5,"minimumTrustLevel":"UNTRUSTED"}]}`,
		`{"rules":["not an object"]}`,
		`{"rules":[null]}`,
	}
	for _, document := range broken {
		policy, ok := policyjson.ParseObject([]byte(document))
		if !ok {
			t.Fatalf("test policy is not an object: %s", document)
		}
		rules, _ := policyjson.Array(policy.Get("rules"))
		if _, err := validateEvaluatePolicy("anything", "EXECUTE", "TRUSTED", rules); err == nil {
			t.Errorf("evaluated %s without complaint; the live route answers 500", document)
		}
	}
}

// The default when nothing matches is DENY with no rule, and the reason string
// is one a dashboard filter matches on.
func TestValidateEvaluatePolicyDefaultDeny(t *testing.T) {
	decision, err := validateEvaluatePolicy("anything", "EXECUTE", "TRUSTED", nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision.effect != "DENY" || decision.matchedRule != nil ||
		decision.reason != "No matching policy rule (default deny)" {
		t.Errorf("empty policy gave %v / %q, want a default deny", decision.effect, decision.reason)
	}
}

// The stored default-deny document has to parse and evaluate, because it is
// what every project with no policy is judged by.
func TestDefaultDenyPolicyEvaluates(t *testing.T) {
	policy, ok := policyjson.ParseObject([]byte(policyDefaultDenyPolicy))
	if !ok {
		t.Fatal("policyDefaultDenyPolicy is not an object")
	}
	rules, isArray := policyjson.Array(policy.Get("rules"))
	if !isArray {
		t.Fatal("policyDefaultDenyPolicy has no rules array")
	}
	for _, tc := range []struct {
		tool, permission, trust, want, rule string
	}{
		{"read_file", "READ", "VERIFIED", "ALLOW", "allow-verified-read"},
		{"run_build", "EXECUTE", "VERIFIED", "ALLOW", "allow-verified-execute"},
		{"run_build", "EXECUTE", "UNTRUSTED", "DENY", "deny-all-execute"},
		// NETWORK is in ALL_PERMISSIONS and in no rule of this document, so it
		// falls through to the default rather than to a DENY rule.
		{"anything", "NETWORK", "TRUSTED", "DENY", ""},
	} {
		decision, err := validateEvaluatePolicy(tc.tool, tc.permission, tc.trust, rules)
		if err != nil {
			t.Fatalf("evaluate %s: %v", tc.tool, err)
		}
		if decision.effect != tc.want || decision.matchedRuleID != tc.rule {
			t.Errorf("%s/%s/%s gave %v via %q, want %s via %q",
				tc.tool, tc.permission, tc.trust, decision.effect, decision.matchedRuleID, tc.want, tc.rule)
		}
	}
}

// The trust map, including the prototype-chain names. See
// validateTrustUnrecognised: mapping those to VERIFIED would allow calls the
// live service denies.
func TestValidateTrustLevel(t *testing.T) {
	for raw, want := range map[any]string{
		"low": "UNTRUSTED", "untrusted": "UNTRUSTED", "UNTRUSTED": "UNTRUSTED",
		"medium": "VERIFIED", "verified": "VERIFIED", "VERIFIED": "VERIFIED",
		"high": "TRUSTED", "trusted": "TRUSTED", "TRUSTED": "TRUSTED",
		"nonsense": "VERIFIED", "": "VERIFIED", nil: "VERIFIED", 7.0: "VERIFIED",
		"toString": validateTrustUnrecognised, "constructor": validateTrustUnrecognised,
	} {
		if got := validateTrustLevel(raw); got != want {
			t.Errorf("trust %v = %q, want %q", raw, got, want)
		}
	}
	if validateTrustIndex(validateTrustUnrecognised) != -1 {
		t.Error("the unrecognised sentinel must not rank as a trust level")
	}
}

// `${v}` for the values a claim or a rule id can hold.
func TestCapabilityTemplate(t *testing.T) {
	if got := capabilityTemplate(nil, true); got != "undefined" {
		t.Errorf("missing = %q, want undefined", got)
	}
	for _, tc := range []struct {
		in   any
		want string
	}{
		{nil, "null"},
		{"x", "x"},
		{true, "true"},
		{1.5, "1.5"},
		{2.0, "2"},
		{[]any{1.0, nil, 2.0}, "1,,2"},
		{policyjson.NewObject(), "[object Object]"},
	} {
		if got := capabilityTemplate(tc.in, false); got != tc.want {
			t.Errorf("template(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The pattern matcher is four branches and one of them surprises people: only a
// LEADING or TRAILING star is a wildcard.
func TestValidateMatchesPattern(t *testing.T) {
	for _, tc := range []struct {
		tool, pattern string
		want          bool
	}{
		{"anything", "*", true},
		{"read_file", "read_*", true},
		{"read_file", "*_file", true},
		{"read_file", "read_file", true},
		{"read_file", "write_*", false},
		{"read_file", "*_dir", false},
		// A star in the MIDDLE is not a wildcard: neither the leading nor the
		// trailing branch fires, so the pattern is compared literally.
		{"a*b", "a*b", true},
		{"axb", "a*b", false},
		{"a*bc", "a*b", false},
		{"a*b", "a*", true},
	} {
		if got := validateMatchesPattern(tc.tool, tc.pattern); got != tc.want {
			t.Errorf("matches(%q, %q) = %v, want %v", tc.tool, tc.pattern, got, tc.want)
		}
	}
}

// The three routes this file owns are registered, so a rename cannot silently
// leave one answering the 501 stub. That failure has happened in this package
// before: a file whose name Go read as a build constraint compiled and tested
// clean while its route was never registered at all.
func TestCapabilityRoutesRegistered(t *testing.T) {
	for _, pattern := range []string{
		"POST /api/v1/tokens",
		"POST /api/v1/tokens/verify",
		"POST /api/v1/validate",
	} {
		if _, ok := routeHandlers[pattern]; !ok {
			t.Errorf("%s has no handler; it would answer 501", pattern)
		}
	}
}
