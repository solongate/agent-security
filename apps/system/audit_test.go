package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/policyjson"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// The tests for the audit and agents slice.
//
// They are aimed at the things a deployed client would notice and nobody would
// see in review: the order of keys in a re-serialised object, a hash computed
// over the wrong document, a signal derived from the wrong evidence, and a
// duplicate check that answers differently for block than for whitelist.
//
// The secret-shaped fixtures are ASSEMBLED at run time rather than written out.
// A literal one in this file would be a real detection for every scanner that
// reads the repository — including SolonGate's own, which refuses to write a
// file containing one.

func awsKeyFixture() string { return "AK" + "IA" + strings.Repeat("A", 16) }

// ruleFixture is one policy rule as findDuplicate receives it: a decoded
// ordered object, not raw bytes, because that is what the policy has been
// parsed into by the time the duplicate check runs.
func ruleFixture(t *testing.T, raw string) []any {
	t.Helper()
	rule, ok := policyjson.ParseObject([]byte(raw))
	if !ok {
		t.Fatalf("rule fixture did not decode: %s", raw)
	}
	return []any{rule}
}

// auditTestKey is the KeyInfo a handler would have been handed. Only the two
// fields the audit write reads are set; the rest are absent on purpose, so a
// test that starts depending on one fails loudly rather than on a placeholder.
func auditTestKey() apiauth.KeyInfo {
	return apiauth.KeyInfo{ProjectID: "proj-1", KeyID: "key-1", KeyName: "CI", IsLive: true}
}

func TestSliceClaimsItsRoutes(t *testing.T) {
	// Register's key has to be the route table's spelling exactly. A key that
	// does not match leaves the table entry answering 501 while the handler is
	// mounted separately as an "extra" — so the endpoint would be simultaneously
	// ported and not ported, and only the startup log would say so.
	for _, pattern := range []string{
		"POST /api/v1/audit-logs",
		"GET /api/v1/audit-logs",
		"POST /api/v1/audit-logs/{id}/block",
		"POST /api/v1/audit-logs/{id}/whitelist",
	} {
		if _, ok := routeHandlers[pattern]; !ok {
			t.Errorf("%s is not registered", pattern)
		}
	}

	// And nothing under those two trees may still be a stub.
	claimed := map[string]bool{}
	for p := range routeHandlers {
		claimed[p] = true
	}
	for _, rt := range routes {
		if !strings.HasPrefix(rt.path, "/api/v1/audit-logs") && !strings.HasPrefix(rt.path, "/api/v1/agents") {
			continue
		}
		for _, m := range rt.methods {
			if !claimed[m+" "+rt.path] {
				t.Errorf("%s %s is in this slice and still a stub", m, rt.path)
			}
		}
	}
}

// The audit log is append-only, and this is what holds it there.
//
// The check is on the registration rather than on a response code, because the
// two ways the delete could come back look nothing alike from the outside: a
// handler mounted under the old pattern, or a DELETE put back in the route
// table, which would answer 501 from the not-ported stub and read like a
// feature on its way rather than one that was taken out on purpose.
func TestThereIsNoWayToDeleteAnAuditLog(t *testing.T) {
	if _, ok := routeHandlers["DELETE /api/v1/audit-logs"]; ok {
		t.Error("a delete handler is registered: the audit log must be append-only")
	}
	for _, rt := range routes {
		if rt.path != "/api/v1/audit-logs" {
			continue
		}
		for _, m := range rt.methods {
			if m == http.MethodDelete {
				t.Error("the route table lists DELETE /api/v1/audit-logs, which would answer 501 as if it were merely unbuilt")
			}
		}
	}
}

func TestArgumentOrderSurvivesRoundTrip(t *testing.T) {
	// The dashboard renders arguments in the order they arrive. A Go map would
	// sort them, so the same call would display differently after the port.
	body := json.RawMessage(`{"zeta":1,"command":"ls -la","alpha":"x"}`)
	_, summary := summariseArguments(body)

	if summary != `{"zeta":1,"command":"ls -la","alpha":"x"}` {
		t.Fatalf("summary = %s, want the original key order", summary)
	}
}

func TestArgumentHashIsStableAndSixteenHex(t *testing.T) {
	body := json.RawMessage(`{"command":"echo hi"}`)
	first, _ := summariseArguments(body)
	second, _ := summariseArguments(body)

	if first != second {
		t.Fatalf("hash is not stable: %q then %q", first, second)
	}
	if len(first) != 16 {
		t.Fatalf("hash = %q, want 16 hex characters", first)
	}
	if strings.ContainsAny(first, "ghijklmnopqrstuvwxyz") {
		t.Errorf("hash = %q, want lowercase hex", first)
	}
}

func TestLongArgumentIsClippedButHashIsOverTheWhole(t *testing.T) {
	long := strings.Repeat("a", maxArgumentValue+50)
	body := json.RawMessage(`{"command":"` + long + `"}`)

	hash, summary := summariseArguments(body)
	if !strings.HasSuffix(summary, argumentEllipsis+`"}`) {
		t.Errorf("summary tail = %q, want the ellipsis the live route appends", tail(summary, 10))
	}
	// The hash must NOT be the hash of the clipped copy: a truncated summary
	// still has to identify the call exactly.
	clippedHash, _ := summariseArguments(json.RawMessage(summary))
	if hash == clippedHash {
		t.Error("hash was computed over the clipped copy, not the full arguments")
	}
}

func tail(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

func TestNonObjectArgumentsAreIgnored(t *testing.T) {
	for _, raw := range []string{`null`, `[1,2]`, `"text"`, ``} {
		hash, summary := summariseArguments(json.RawMessage(raw))
		if hash != "" || summary != "" {
			t.Errorf("arguments %q produced hash=%q summary=%q, want both empty", raw, hash, summary)
		}
	}
}

func TestPolicyHashIsOverThePrunedDocument(t *testing.T) {
	// The live policy hash is `JSON.stringify(policy, Object.keys(policy).sort())`
	// and an ARRAY replacer is a property allowlist applied at every level, not a
	// sort. `effect` is not a top-level key, so it does not survive inside the
	// rule — the hash is over a pruned document, and reproducing that is what
	// makes a policy hashed here equal to the same policy hashed by POST
	// /policies. Both write to the same table.
	policy, ok := policyjson.ParseObject([]byte(`{"id":"p1","rules":[{"id":"r1","effect":"DENY"}]}`))
	if !ok {
		t.Fatal("policy did not decode")
	}
	pruned := policyjson.Stringify(policy, policy.SortedKeys())
	if pruned != `{"id":"p1","rules":[{"id":"r1"}]}` {
		t.Fatalf("stringify = %s, want the nested effect pruned by the property list", pruned)
	}
	if len(policyHash(policy)) != 64 {
		t.Errorf("hash = %q, want a full sha256 in hex", policyHash(policy))
	}
}

func TestPolicyHashIgnoresTopLevelKeyOrder(t *testing.T) {
	// The property list is sorted, so two policies that differ only in the
	// order their keys were written must hash the same.
	first, ok := policyjson.ParseObject([]byte(`{"id":"p","name":"n","rules":[]}`))
	if !ok {
		t.Fatal("policy did not decode")
	}
	second, ok := policyjson.ParseObject([]byte(`{"rules":[],"name":"n","id":"p"}`))
	if !ok {
		t.Fatal("policy did not decode")
	}
	if policyHash(first) != policyHash(second) {
		t.Errorf("hashes differ on key order alone: %s vs %s", policyHash(first), policyHash(second))
	}
}

func TestRulesArrayKeepsItsPositionInThePolicy(t *testing.T) {
	// `{...policy, rules: [...]}` keeps an existing key where it was. A policy
	// that came back with its fields reordered is a diff nobody made — and its
	// hash would move with them.
	policy, ok := policyjson.ParseObject([]byte(`{"id":"p","rules":[{"id":"old"}],"mode":"allowlist"}`))
	if !ok {
		t.Fatal("policy did not decode")
	}
	existing, _ := policyjson.Array(policy.Get("rules"))
	newRule := policyjson.NewObject()
	newRule.Set("id", "new")

	updated := policy.Clone()
	updated.Set("rules", append([]any{newRule}, existing...))

	want := `{"id":"p","rules":[{"id":"new"},{"id":"old"}],"mode":"allowlist"}`
	if got := policyjson.Stringify(updated, nil); got != want {
		t.Fatalf("updated = %s\nwant     = %s", got, want)
	}
}

func TestRulesArrayIsAppendedWhenThePolicyHasNone(t *testing.T) {
	policy, ok := policyjson.ParseObject([]byte(`{"id":"p"}`))
	if !ok {
		t.Fatal("policy did not decode")
	}
	newRule := policyjson.NewObject()
	newRule.Set("id", "new")
	updated := policy.Clone()
	updated.Set("rules", []any{newRule})

	if got := policyjson.Stringify(updated, nil); got != `{"id":"p","rules":[{"id":"new"}]}` {
		t.Fatalf("updated = %s", got)
	}
}

func TestExtractTargetPrefersCommandThenPathThenURL(t *testing.T) {
	cases := []struct {
		summary string
		kind    string
		value   string
	}{
		{`{"command":"  rm -rf /  ","url":"https://x.test"}`, "command", "rm -rf /"},
		{`{"cmd":"ls"}`, "command", "ls"},
		// A path becomes its BASENAME: a rule naming somebody's home directory
		// would not match the same file on another machine.
		{`{"file_path":"/Users/me/secrets.env"}`, "filename", "secrets.env"},
		{`{"path":"C:\\Users\\me\\notes.txt"}`, "filename", "notes.txt"},
		{`{"url":"https://api.test/x"}`, "url", "https://api.test/x"},
	}
	for _, c := range cases {
		got := extractTarget(c.summary)
		if got == nil {
			t.Errorf("%s: no target extracted", c.summary)
			continue
		}
		if got.kind != c.kind || got.value != c.value {
			t.Errorf("%s: got %s=%q, want %s=%q", c.summary, got.kind, got.value, c.kind, c.value)
		}
	}
}

func TestExtractTargetToleratesATruncatedSummary(t *testing.T) {
	// arguments_summary is cut at 16384 characters on write, so a fragment in
	// that column is expected. It must downgrade the rule scope, not fail.
	if got := extractTarget(`{"command":"echo `); got != nil {
		t.Errorf("got %+v from a truncated summary, want nil", got)
	}
}

func TestBlockAndWhitelistDedupeDifferentlyAtToolScope(t *testing.T) {
	// A rule carrying only an `allowed` list counts as an unconstrained DENY for
	// block's test, and does NOT count as an unconstrained ALLOW for
	// whitelist's. The asymmetry is the live app's and changing it would change
	// which clicks are no-ops.
	denyWithAllowList := ruleFixture(t, `{"effect":"DENY","toolPattern":"Bash","commandConstraints":{"allowed":["ls"]}}`)
	if findDuplicate(grantDeny, denyWithAllowList, "Bash", nil, "tool") == nil {
		t.Error("block: a DENY with no denied lists should be an unconstrained duplicate")
	}

	allowWithAllowList := ruleFixture(t, `{"effect":"ALLOW","toolPattern":"Bash","commandConstraints":{"allowed":["ls"]}}`)
	if findDuplicate(grantAllow, allowWithAllowList, "Bash", nil, "tool") != nil {
		t.Error("whitelist: a rule with any constraint object is not an unconstrained duplicate")
	}
}

func TestEmptyConstraintListIsStillAList(t *testing.T) {
	// JavaScript's `r.commandConstraints?.denied` is truthy for an empty array,
	// so `denied: []` means "has a denied list" and is not a tool-scope match.
	rule := ruleFixture(t, `{"effect":"DENY","toolPattern":"Bash","commandConstraints":{"denied":[]}}`)
	if findDuplicate(grantDeny, rule, "Bash", nil, "tool") != nil {
		t.Error("an empty denied list must not read as no denied list")
	}
}

func TestDisabledRuleIsNeverADuplicate(t *testing.T) {
	rule := ruleFixture(t, `{"effect":"ALLOW","toolPattern":"Bash","enabled":false}`)
	if findDuplicate(grantAllow, rule, "Bash", nil, "tool") != nil {
		t.Error("a disabled rule must not suppress a new one")
	}
}

func TestExactDuplicateIsFoundByConstraintValue(t *testing.T) {
	rule := ruleFixture(t, `{"effect":"ALLOW","toolPattern":"Bash","commandConstraints":{"allowed":["ls -la"]}}`)
	target := &ruleTarget{kind: "command", value: "ls -la"}
	if findDuplicate(grantAllow, rule, "Bash", target, "exact") == nil {
		t.Error("an identical exact rule must be deduped")
	}
	other := &ruleTarget{kind: "command", value: "rm -rf /"}
	if findDuplicate(grantAllow, rule, "Bash", other, "exact") != nil {
		t.Error("a different command must not be deduped against")
	}
}

func TestGrantedRuleWinsThePriorityCascade(t *testing.T) {
	rule := []byte(policyjson.Stringify(
		buildGrantRule(grantAllow, "Bash", &ruleTarget{kind: "command", value: "ls"}, "exact"), nil))
	var decoded struct {
		ID          string `json:"id"`
		ToolPattern string `json:"toolPattern"`
		Effect      string `json:"effect"`
		Priority    int    `json:"priority"`
		Enabled     bool   `json:"enabled"`
		Constraints struct {
			Allowed []string `json:"allowed"`
		} `json:"commandConstraints"`
	}
	if err := json.Unmarshal(rule, &decoded); err != nil {
		t.Fatal(err)
	}
	// Priority 1 against the default 100: the generated Rego is a
	// priority-ordered chain and a granted rule that lost to the rule that
	// caused the entry would do nothing at all.
	if decoded.Priority != 1 {
		t.Errorf("priority = %d, want 1", decoded.Priority)
	}
	if decoded.Effect != "ALLOW" || !decoded.Enabled {
		t.Errorf("rule = %s, want an enabled ALLOW", rule)
	}
	if !strings.HasPrefix(decoded.ID, "allow-") {
		t.Errorf("id = %q, want the allow- prefix", decoded.ID)
	}
	if len(decoded.Constraints.Allowed) != 1 || decoded.Constraints.Allowed[0] != "ls" {
		t.Errorf("rule = %s, want the command constrained", rule)
	}
}

func TestToolScopedRuleCarriesNoConstraint(t *testing.T) {
	rule := policyjson.Stringify(
		buildGrantRule(grantDeny, "Bash", &ruleTarget{kind: "command", value: "ls"}, "tool"), nil)
	if strings.Contains(rule, "commandConstraints") {
		t.Errorf("rule = %s, want no constraint at tool scope", rule)
	}
}

func TestPolicySelectionIsDeterministicOnTies(t *testing.T) {
	// Equal createdAt, two wildcard policies. A Go map's iteration order would
	// pick a different one on different requests, and a granted rule would land
	// somewhere new each time.
	rows := []store.ActivePolicyRow{
		{Version: 2, PolicyData: json.RawMessage(`{"id":"first","agents":["*"]}`), CreatedAt: 100},
		{Version: 1, PolicyData: json.RawMessage(`{"id":"second","agents":["*"]}`), CreatedAt: 100},
	}
	for i := 0; i < 20; i++ {
		picked := pickPolicyForAgent(latestPerPolicyID(rows), "claude-code")
		if picked == nil || picked.policyID != "first" {
			t.Fatalf("iteration %d picked %v, want the first row inserted", i, picked)
		}
	}
}

func TestPolicySelectionPrefersDirectThenSpecificThenWildcard(t *testing.T) {
	rows := []store.ActivePolicyRow{
		{Version: 3, PolicyData: json.RawMessage(`{"id":"wild","agents":["*"]}`), CreatedAt: 300},
		{Version: 2, PolicyData: json.RawMessage(`{"id":"named","agents":["claude-code"]}`), CreatedAt: 200},
		{Version: 1, PolicyData: json.RawMessage(`{"id":"claude-code","agents":["*"]}`), CreatedAt: 100},
	}
	idx := latestPerPolicyID(rows)
	if got := pickPolicyForAgent(idx, "claude-code"); got == nil || got.policyID != "claude-code" {
		t.Errorf("got %v, want the policy whose own id is the agent id", got)
	}
	if got := pickPolicyForAgent(idx, "codex"); got == nil || got.policyID != "wild" {
		t.Errorf("got %v, want the wildcard policy for an unnamed agent", got)
	}
}

func TestEmptyAgentListMeansEveryAgent(t *testing.T) {
	// `agents: []` is "*" in the live app's `length > 0` test. Reading it as "no
	// agents" would make a policy that applies to everything apply to nothing.
	agents := policyAgents(json.RawMessage(`{"id":"p","agents":[]}`))
	if len(agents) != 1 || agents[0] != "*" {
		t.Errorf("agents = %v, want the wildcard default", agents)
	}
}

func TestLatestVersionPerPolicyIsPerLogicalID(t *testing.T) {
	rows := []store.ActivePolicyRow{
		{Version: 9, PolicyData: json.RawMessage(`{"id":"a"}`)},
		{Version: 4, PolicyData: json.RawMessage(`{"id":"b"}`)},
		{Version: 2, PolicyData: json.RawMessage(`{"id":"a"}`)},
	}
	idx := latestPerPolicyID(rows)
	if got := idx.maxVersionOf("a"); got != 9 {
		t.Errorf("maxVersionOf(a) = %d, want 9", got)
	}
	if got := idx.maxVersionOf("b"); got != 4 {
		t.Errorf("maxVersionOf(b) = %d, want 4", got)
	}
	// An id nothing carries yields 0, so the next version is 1 — which is what
	// the live app's json_extract query does with a NULL MAX.
	if got := idx.maxVersionOf(anonymousPolicyID); got != 0 {
		t.Errorf("maxVersionOf(anonymous) = %d, want 0", got)
	}
}

// ── derived signals ─────────────────────────────────────────────────────────

func testLayers() store.SecurityLayers { return store.DefaultSecurityLayers() }

func TestDLPFallsBackToTheRedactionMarker(t *testing.T) {
	// A redacted hit leaves no secret to re-scan and no denial to quote. The
	// marker is the only evidence, and this was the case that used to read as
	// clean — the one mode where DLP does its job silently.
	s := newDLPScanner(testLayers())
	got := s.dlpMatchesOf(`{"command":"echo [REDACTED:Anthropic key]"}`, "allowed")
	if len(got) != 1 || got[0] != "Anthropic key" {
		t.Errorf("matches = %v, want the pattern name out of the marker", got)
	}
}

func TestDLPFallsBackToTheDenialReason(t *testing.T) {
	s := newDLPScanner(testLayers())
	got := s.dlpMatchesOf("", "Security layer (DLP): blocked - arguments contain a Anthropic key.")
	if len(got) != 1 || got[0] != "Anthropic key" {
		t.Errorf("matches = %v, want the pattern name out of the reason", got)
	}
}

func TestDLPScanBeatsBothFallbacks(t *testing.T) {
	s := newDLPScanner(testLayers())
	summary := `{"k":"` + awsKeyFixture() + `","note":"[REDACTED:GitHub token]"}`
	got := s.dlpMatchesOf(summary, "Security layer (DLP): contains something else.")
	if len(got) != 1 || got[0] != "AWS access key" {
		t.Errorf("matches = %v, want the re-scan to win", got)
	}
}

func TestDLPMatchesIsAlwaysAnArray(t *testing.T) {
	// The dashboard maps over it. A nil slice would serialise as null.
	s := newDLPScanner(testLayers())
	b, err := json.Marshal(s.dlpMatchesOf(`{"k":"nothing here"}`, "allowed"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "[]" {
		t.Errorf("dlp_matches = %s, want an empty array", b)
	}
}

func TestDisabledDLPPatternIsNotScanned(t *testing.T) {
	layers := testLayers()
	layers.DLP.Patterns = []string{"GitHub token"}
	s := newDLPScanner(layers)
	if got := s.scan(`{"k":"` + awsKeyFixture() + `"}`); len(got) != 0 {
		t.Errorf("matches = %v, want none: the project disabled that pattern", got)
	}
}

func TestBrokenCustomPatternIsSkippedNotFatal(t *testing.T) {
	// A custom pattern is typed into a settings form, and RE2 refuses some
	// expressions JavaScript accepts. One bad pattern must cost that detector,
	// not the audit page.
	layers := testLayers()
	layers.DLP.Patterns = nil
	layers.DLP.Custom = []store.CustomPattern{
		{Name: "broken", Re: `(?=lookahead)`},
		{Name: "good", Re: `CONFIDENTIAL-?MARK`},
	}
	s := newDLPScanner(layers)
	got := s.scan(`{"k":"CONFIDENTIALMARK"}`)
	if len(got) != 1 || got[0] != "good" {
		t.Errorf("matches = %v, want only the pattern that compiled", got)
	}
}

func TestRateLimitLimitAtUsesTheLimitInForceAtTheTime(t *testing.T) {
	// A project that lowered its limit must not have last week's traffic
	// re-judged against today's number.
	layers := testLayers()
	layers.RateLimit.PerMinute = 10
	history := []store.RateLimitChange{
		{TS: 1_000_000, Minute: 500},
		{TS: 2_000_000, Minute: 10},
	}
	if got := limitAt(1_500_000, history, layers); got != 500 {
		t.Errorf("limit at the earlier moment = %d, want 500", got)
	}
	if got := limitAt(2_500_000, history, layers); got != 10 {
		t.Errorf("limit after the change = %d, want 10", got)
	}
	// Before any recorded change, the current configuration applies.
	if got := limitAt(500_000, history, layers); got != 10 {
		t.Errorf("limit before any history = %d, want the configured 10", got)
	}
}

func TestRateLimitOffMeansNoLimitToExceed(t *testing.T) {
	layers := testLayers()
	layers.RateLimit.Mode = store.LayerOff
	layers.RateLimit.PerMinute = 10
	if got := limitAt(1_000, nil, layers); got != 0 {
		t.Errorf("limit = %d, want 0 when the layer is off", got)
	}
}

func TestBurstBucketsAreAgentAndMinute(t *testing.T) {
	// Two calls in the same minute share a bucket; the next minute does not.
	if burstKey("a", 120) != burstKey("a", 179) {
		t.Error("calls in the same minute must share a bucket")
	}
	if burstKey("a", 120) == burstKey("a", 180) {
		t.Error("the next minute is a different bucket")
	}
	// An entry with no agent falls into the shared bucket rather than getting
	// an unlimited budget by omitting an identity.
	if !strings.HasPrefix(burstKey("", 0), unknownAgent) {
		t.Errorf("nameless agent key = %q, want the shared bucket", burstKey("", 0))
	}
}

func TestDenialForRateLimitIsABurstOnItsOwn(t *testing.T) {
	// The calls that would have proved the burst were refused, so the denial is
	// the only evidence left.
	if !deniedForRateLimit("DENY", "Rate limit exceeded: 120/min") {
		t.Error("a rate-limit denial must carry the burst flag")
	}
	if deniedForRateLimit("ALLOW", "Rate limit exceeded: 120/min") {
		t.Error("an allowed call is not a rate-limit denial")
	}
}

func TestSelfProtectionDenialIsClassifiedApart(t *testing.T) {
	// A policy deny is somebody's rules working; a self-protection deny is an
	// agent trying to disable the guard.
	if got := classifyDenyLayer("SolonGate: tamper protection blocked this"); got != "SELF_PROTECTION" {
		t.Errorf("layer = %q, want SELF_PROTECTION", got)
	}
	if got := classifyDenyLayer("Denied by rule bash-guard"); got != "POLICY" {
		t.Errorf("layer = %q, want POLICY", got)
	}
}

func TestMatchedRuleIDPrefersTheColumn(t *testing.T) {
	if got := matchedRuleID("rule-7", "denied by rule other-1"); got != "rule-7" {
		t.Errorf("got %q, want the stored column", got)
	}
	if got := matchedRuleID("  ", `Blocked by rule "deny-writes".`); got != "deny-writes" {
		t.Errorf("got %q, want the id recovered from the reason", got)
	}
	if got := matchedRuleID("", "blocked by policy"); got != "" {
		t.Errorf("got %q, want nothing when no rule is named", got)
	}
}

// ── the response contract ───────────────────────────────────────────────────

func TestAuditEntryNullsMatchTheLiveShape(t *testing.T) {
	// The store flattens a NULL text column to "". Emitting "" where a year of
	// stored responses carry null is a silent contract change.
	b, err := marshalNoEscape(auditListEntry{ID: "x", DLPMatches: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"session_id":null`, `"server_name":null`, `"matched_rule_id":null`,
		`"reason":null`, `"agent_id":null`, `"api_key_name":null`,
		`"matched_rule":null`, `"arguments_summary":null`,
	} {
		if !strings.Contains(string(b), field) {
			t.Errorf("entry is missing %s\ngot %s", field, b)
		}
	}
}

func TestResponseJSONDoesNotEscapeHTML(t *testing.T) {
	// A command constraint like `sh -c 'a && b'` must come back byte-identical:
	// the guard hashes the bytes it receives.
	b, err := marshalNoEscape(map[string]string{"command": "a && b < c"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `\u0026`) || strings.Contains(string(b), `\u003c`) {
		t.Errorf("body = %s, want the characters JSON.stringify leaves alone", b)
	}
}

// ── the POST body ───────────────────────────────────────────────────────────

func decodeAuditBody(t *testing.T, raw string) auditPostBody {
	t.Helper()
	var b auditPostBody
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		t.Fatalf("body did not decode: %v", err)
	}
	return b
}

func TestGuardBodyIsAcceptedUnchanged(t *testing.T) {
	// This is the exact body packages/guard-go/audit.go sends, from a detached
	// child that never reads the answer.
	body := decodeAuditBody(t, `{
		"tool":"Bash",
		"arguments":{"command":"rm -rf /"},
		"decision":"DENY",
		"reason":"Blocked by SolonGate",
		"permission":"EXECUTE",
		"source":"claude-code-guard",
		"agent_id":"claude-code",
		"agent_name":"Claude Code",
		"session_id":"sess-1",
		"evaluation_time_ms":12
	}`)
	entry := body.toAuditLog(auditTestKey())

	if entry.ToolName != "Bash" || entry.Decision != "DENY" {
		t.Errorf("entry = %+v", entry)
	}
	if entry.ServerName != "claude-code-guard" {
		t.Errorf("server_name = %q, want the guard's source", entry.ServerName)
	}
	if entry.SessionID != "sess-1" || entry.AgentID != "claude-code" {
		t.Errorf("entry = %+v, want the agent and session recorded", entry)
	}
	if entry.EvaluationTimeMs == nil || *entry.EvaluationTimeMs != 12 {
		t.Errorf("evaluation_time_ms = %v, want 12", entry.EvaluationTimeMs)
	}
	if entry.ArgumentsHash == "" {
		t.Error("arguments were not fingerprinted")
	}
}

func TestAuditHookCamelCaseFieldsAreAccepted(t *testing.T) {
	// The audit hook spells it evaluationTimeMs and one version spells the
	// session sessionId. Both are installed and neither will be redeployed.
	body := decodeAuditBody(t, `{"tool":"Read","evaluationTimeMs":7,"sessionId":"sess-2"}`)
	entry := body.toAuditLog(auditTestKey())

	if entry.EvaluationTimeMs == nil || *entry.EvaluationTimeMs != 7 {
		t.Errorf("evaluation_time_ms = %v, want the camelCase field read", entry.EvaluationTimeMs)
	}
	if entry.SessionID != "sess-2" {
		t.Errorf("session_id = %q, want the camelCase field read", entry.SessionID)
	}
}

func TestDefaultsMatchTheLiveRoute(t *testing.T) {
	body := decodeAuditBody(t, `{"tool":"Read"}`)
	entry := body.toAuditLog(auditTestKey())

	if entry.ServerName != "proxy" || entry.Permission != "EXECUTE" ||
		entry.TrustLevel != "UNTRUSTED" || entry.Decision != "ALLOW" {
		t.Errorf("entry = %+v, want the live defaults", entry)
	}
	if entry.RequestID == "" {
		t.Error("a request id must be generated when the client sends none")
	}
}

func TestPromptInjectionNullIsNotFalse(t *testing.T) {
	// NULL is "the scanner did not run" and false is "it ran and found
	// nothing". Collapsing them makes every call from a client with detection
	// disabled look checked and cleared.
	absent := decodeAuditBody(t, `{"tool":"Read"}`).toAuditLog(auditTestKey())
	if absent.PiDetected != nil {
		t.Errorf("pi_detected = %v, want NULL when nothing reported it", *absent.PiDetected)
	}

	ran := decodeAuditBody(t, `{"tool":"Read","promptInjection":{"detected":false}}`).toAuditLog(auditTestKey())
	if ran.PiDetected == nil || *ran.PiDetected {
		t.Errorf("pi_detected = %v, want false when the scanner ran", ran.PiDetected)
	}
}

func TestPromptInjectionScoreIsClamped(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want float64
	}{
		{`{"tool":"R","promptInjection":{"trustScore":1.7}}`, 1},
		{`{"tool":"R","promptInjection":{"trustScore":-3}}`, 0},
		{`{"tool":"R","promptInjection":{"trustScore":"nonsense"}}`, 0},
		{`{"tool":"R","pi_trust_score":0.25}`, 0.25},
	} {
		entry := decodeAuditBody(t, c.raw).toAuditLog(auditTestKey())
		if entry.PiTrustScore == nil || *entry.PiTrustScore != c.want {
			t.Errorf("%s: score = %v, want %v", c.raw, entry.PiTrustScore, c.want)
		}
	}
}

func TestPromptInjectionCategoriesRejectNonStrings(t *testing.T) {
	ok := decodeAuditBody(t, `{"tool":"R","promptInjection":{"matchedCategories":["a","b"]}}`).toAuditLog(auditTestKey())
	if ok.PiCategories != `["a","b"]` {
		t.Errorf("categories = %q", ok.PiCategories)
	}
	mixed := decodeAuditBody(t, `{"tool":"R","promptInjection":{"matchedCategories":["a",3]}}`).toAuditLog(auditTestKey())
	if mixed.PiCategories != "" {
		t.Errorf("categories = %q, want the whole list rejected", mixed.PiCategories)
	}
}

func TestDoubleEncodedPiFieldsAreUnwrapped(t *testing.T) {
	// One version of the hook stringified these twice.
	entry := decodeAuditBody(t, `{"tool":"R","pi_categories":"[\"jailbreak\"]"}`).toAuditLog(auditTestKey())
	if entry.PiCategories != `["jailbreak"]` {
		t.Errorf("categories = %q, want the inner JSON", entry.PiCategories)
	}
}

func TestStageScoresAreAlwaysThreeClampedNumbers(t *testing.T) {
	// The dashboard's three-bar display reads all three; a missing key renders
	// as a bar of NaN.
	entry := decodeAuditBody(t, `{"tool":"R","promptInjection":{"stageScores":{"rules":2}}}`).toAuditLog(auditTestKey())
	var got map[string]float64
	if err := json.Unmarshal([]byte(entry.PiStageScores), &got); err != nil {
		t.Fatalf("stage scores = %q: %v", entry.PiStageScores, err)
	}
	if len(got) != 3 || got["rules"] != 1 || got["embedding"] != 0 || got["classifier"] != 0 {
		t.Errorf("stage scores = %v", got)
	}
}

func TestFieldsAreClippedOnRuneBoundaries(t *testing.T) {
	// s[:n] on bytes would cut a multi-byte character in half and store invalid
	// UTF-8 under a name nobody can search for.
	long := strings.Repeat("é", maxToolName+20)
	entry := decodeAuditBody(t, `{"tool":"`+long+`"}`).toAuditLog(auditTestKey())
	if !json.Valid([]byte(`"` + entry.ToolName + `"`)) {
		t.Fatal("tool name is not valid UTF-8 after clipping")
	}
	if n := len([]rune(entry.ToolName)); n != maxToolName {
		t.Errorf("tool name = %d runes, want %d", n, maxToolName)
	}
}

func TestNumberToolNameIsStringifiedNotRejected(t *testing.T) {
	// The live route reads these through String(x || ''), so a client sending a
	// number gets it stringified rather than a 400.
	entry := decodeAuditBody(t, `{"tool":123,"agent_id":7}`).toAuditLog(auditTestKey())
	if entry.ToolName != "123" || entry.AgentID != "7" {
		t.Errorf("entry = %+v, want the numbers stringified", entry)
	}
}
