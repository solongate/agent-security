package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/policyjson"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// The policy slice's tests.
//
// They do not touch a database. What they check is the part of these endpoints
// that a database cannot: the SHAPE of what an installed guard receives, and
// the selection logic that decides which policy it receives. Both are contracts
// with software that is already deployed, and both are pure functions of data
// this file can construct.

func TestPolicyRoutesAreAllClaimed(t *testing.T) {
	// Every path the route table lists under /api/v1/policies, minus the two
	// this slice was not given. If one of mine falls out of routeHandlers it
	// silently goes back to answering 501, which reads to a deployed client as
	// "this endpoint is gone".
	notMine := map[string]bool{
		"/api/v1/policies/{id}/wasm": true,
		"/api/v1/policies/learn":     true,
	}
	for _, path := range PathsUnderPrefix("/api/v1/policies") {
		if notMine[path] {
			continue
		}
		claimed := false
		for pattern := range routeHandlers {
			if strings.HasSuffix(pattern, " "+path) {
				claimed = true
				break
			}
		}
		if !claimed {
			t.Errorf("%s has no handler registered and would answer 501", path)
		}
	}
}

// The four fields the guard reads, all present, on the branch where the project
// has NO policy at all.
//
// This is the branch that matters most and the easiest one to get wrong. A
// project with no policy still has DLP, rate limits, ghost paths and local
// logging, and the guard REPLACES its cached security block with whatever
// arrives — so leaving the key out here would freeze a stale configuration on
// every laptop in that project forever.
func TestActivePolicyAlwaysCarriesTheGuardsFourFields(t *testing.T) {
	layers := store.DefaultSecurityLayers()
	security := store.GuardEnforcementConfig(layers)
	local := store.LocalLogsConfig{}
	security.LocalLogs = &local

	body, err := json.Marshal(activePolicyResponse{
		SelfProtectionEnabled: true,
		Security:              &security,
		HookVersions:          activeHookVersionsNow(),
	})
	if err != nil {
		t.Fatal(err)
	}

	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	for _, key := range []string{"policy", "self_protection_enabled", "security", "hook_versions"} {
		if _, ok := probe[key]; !ok {
			t.Errorf("%q is missing from a no-policy response; the guard reads all four", key)
		}
	}
	if string(probe["policy"]) != "null" {
		t.Errorf("policy = %s, want null", probe["policy"])
	}

	// And inside `security`, the six members. `null` is an answer here — "this
	// project does not block on secrets" — and has to stay distinguishable from
	// a key the API did not send. sgshared.PolicyCache carries a HasSecurity
	// flag for exactly that distinction.
	var sec map[string]json.RawMessage
	if err := json.Unmarshal(probe["security"], &sec); err != nil {
		t.Fatalf("security is not an object: %v", err)
	}
	for _, key := range []string{"rateLimit", "rateLimitObserve", "dlpBlock", "dlpRedact", "ghost", "localLogs"} {
		if _, ok := sec[key]; !ok {
			t.Errorf("security.%s is missing; a missing key and a null are not the same answer", key)
		}
	}
}

// The version, hash and matched_by fields appear only when a policy was
// selected. The CLI declares them omitempty and the guard ignores them, but a
// `"version": 0` on a no-policy response would be a policy version nobody can
// fetch.
func TestActivePolicyOmitsVersionWhenThereIsNoPolicy(t *testing.T) {
	security := store.GuardEnforcementConfig(store.DefaultSecurityLayers())
	body, _ := json.Marshal(activePolicyResponse{Security: &security})
	for _, key := range []string{`"version"`, `"hash"`, `"matched_by"`} {
		if strings.Contains(string(body), key) {
			t.Errorf("%s must not appear when no policy was selected: %s", key, body)
		}
	}
}

// hook_versions has to be the same table /v1/hooks/{name} serves. A number
// higher than what that route will hand over makes every device try to
// self-update on every tool call, forever, and never succeed.
func TestHookVersionsComeFromTheBundlesThatAreServed(t *testing.T) {
	hv := activeHookVersionsNow()
	if hv.Guard <= 0 || hv.Audit <= 0 || hv.Shield <= 0 {
		t.Fatalf("hook_versions = %+v, want the embedded bundle versions", hv)
	}
}

// ── selection ───────────────────────────────────────────────────────────────

func policyRow(t *testing.T, version int64, createdAt int64, body string) store.ActivePolicyRow {
	t.Helper()
	return store.ActivePolicyRow{
		Version:    version,
		PolicyData: json.RawMessage(body),
		Hash:       "h",
		CreatedAt:  createdAt,
	}
}

func TestSelectionTakesTheNewestVersionOfEachPolicy(t *testing.T) {
	rows := []store.ActivePolicyRow{
		policyRow(t, 3, 300, `{"id":"a","name":"A v3"}`),
		policyRow(t, 2, 200, `{"id":"b","name":"B"}`),
		policyRow(t, 1, 100, `{"id":"a","name":"A v1"}`),
	}
	latest := policyLatestPerID(rows)
	got, ok := latest.get("a")
	if !ok || got.Version != 3 {
		t.Errorf("policy a resolved to %+v, want version 3", got)
	}
	if _, ok := latest.get("b"); !ok {
		t.Error("policy b must be its own candidate, not collapsed into a's version number")
	}
}

// The three tiers, in order. `policy-id` is the "Use in terminal" button: the
// dashboard puts a POLICY id into SOLONGATE_AGENT_ID and the guard sends it as
// agent_id, so a policy whose own id equals the agent_id wins outright.
func TestSelectionPrefersPolicyIdThenAgentThenWildcard(t *testing.T) {
	rows := []store.ActivePolicyRow{
		policyRow(t, 3, 300, `{"id":"wild","agents":["*"]}`),
		policyRow(t, 2, 200, `{"id":"scoped","agents":["claude-code"]}`),
		policyRow(t, 1, 100, `{"id":"pinme","agents":["other"]}`),
	}
	latest := policyLatestPerID(rows)

	if row, by := policySelectForAgent(latest, "pinme"); by != "policy-id" || row.Version != 1 {
		t.Errorf("got %q / %+v, want the policy whose own id is the agent_id", by, row)
	}
	if row, by := policySelectForAgent(latest, "claude-code"); by != "agent" || row.Version != 2 {
		t.Errorf("got %q / %+v, want the agent-scoped policy", by, row)
	}
	if row, by := policySelectForAgent(latest, "nobody"); by != "wildcard" || row.Version != 3 {
		t.Errorf("got %q / %+v, want the wildcard policy", by, row)
	}
}

// A policy with no `agents` array applies everywhere. Reading a missing array
// as "no agents" would leave a fleet with no policy at all.
func TestAPolicyWithNoAgentsListIsAWildcard(t *testing.T) {
	rows := []store.ActivePolicyRow{policyRow(t, 1, 100, `{"id":"p"}`)}
	if row, by := policySelectForAgent(policyLatestPerID(rows), "anything"); by != "wildcard" || row == nil {
		t.Errorf("got %q / %+v, want a wildcard match", by, row)
	}
}

func TestSelectionIgnoresAVersionWithNoPolicyData(t *testing.T) {
	rows := []store.ActivePolicyRow{
		policyRow(t, 2, 200, `null`),
		policyRow(t, 1, 100, `{"id":"good"}`),
	}
	row, by := policySelectForAgent(policyLatestPerID(rows), "")
	if by != "wildcard" || row == nil || row.Version != 1 {
		t.Errorf("got %q / %+v, want the readable policy", by, row)
	}
}

// ── rules ───────────────────────────────────────────────────────────────────

func TestBuildRulePutsTheConstraintOnTheRightSide(t *testing.T) {
	deny := policyBuildRule(ruleSpec{Kind: "command", Value: "rm -rf /", Effect: "DENY"}, true)
	got := policyjson.Stringify(deny, nil)
	if !strings.Contains(got, `"effect":"DENY"`) || !strings.Contains(got, `"commandConstraints":{"denied":["rm -rf /"]}`) {
		t.Errorf("rule = %s", got)
	}
	if !strings.HasPrefix(policyjson.Str(deny.Get("id")), "deny-") {
		t.Errorf("id = %v, want a deny- prefix", deny.Get("id"))
	}

	allow := policyBuildRule(ruleSpec{Kind: "url", Value: "https://ok.example/*", Effect: "ALLOW"}, false)
	if !strings.Contains(policyjson.Stringify(allow, nil), `"urlConstraints":{"allowed":["https://ok.example/*"]}`) {
		t.Errorf("rule = %s", policyjson.Stringify(allow, nil))
	}
}

// `path` and `filename` are different matchers and the difference is the whole
// rule: a path constraint names a DIRECTORY and everything under it, a filename
// constraint matches the last segment only.
//
// This wrote filenameConstraints until 0.83.36. `solongate policy deny --path
// '*secrets*'` therefore produced a rule that did not match
// `secrets/session.key`: the file sits in the directory the operator named, and
// its NAME contains no "secrets". The rule listed fine in `policy show`, looked
// correct, and enforced nothing. The case was missing from the test above,
// which is how it survived.
func TestBuildRuleWritesAPathConstraintForAPath(t *testing.T) {
	rule := policyBuildRule(ruleSpec{Kind: "path", Value: "*secrets*", Effect: "DENY"}, true)
	got := policyjson.Stringify(rule, nil)

	if !strings.Contains(got, `"pathConstraints":{"denied":["*secrets*"]}`) {
		t.Errorf("--path must write pathConstraints, got %s", got)
	}
	if strings.Contains(got, "filenameConstraints") {
		t.Errorf("--path must not write filenameConstraints, got %s", got)
	}
}

// A rule copied in twice must not write a second version. The dedupe is what
// makes the dashboard's "block this" button idempotent.
func TestDuplicateDetection(t *testing.T) {
	existing, _ := policyjson.Array(mustParseValue(t, `[
		{"id":"r1","effect":"DENY","toolPattern":"*","enabled":true,
		 "commandConstraints":{"denied":["rm -rf /"]}},
		{"id":"r2","effect":"ALLOW","toolPattern":"Bash","enabled":false},
		{"id":"r3","effect":"ALLOW","toolPattern":"Read"}
	]`))

	if !policyRuleAlreadyPresent(existing, ruleSpec{Kind: "command", Value: "rm -rf /", Effect: "DENY"}) {
		t.Error("the same command on the same side must dedupe")
	}
	if policyRuleAlreadyPresent(existing, ruleSpec{Kind: "command", Value: "rm -rf /tmp", Effect: "DENY"}) {
		t.Error("a different command must not dedupe")
	}
	// r2 is disabled, so an unconstrained ALLOW for Bash is NOT a duplicate —
	// re-adding something previously turned off has to write a live rule.
	if policyRuleAlreadyPresent(existing, ruleSpec{Kind: "tool", ToolPattern: "Bash", Effect: "ALLOW"}) {
		t.Error("a disabled rule must not count as present")
	}
	if !policyRuleAlreadyPresent(existing, ruleSpec{Kind: "tool", ToolPattern: "Read", Effect: "ALLOW"}) {
		t.Error("an enabled unconstrained rule for the same tool must dedupe")
	}
}

// The dedupe has to read the same constraint the builder writes, or every
// `--path` would append a second identical rule forever.
func TestDuplicateDetectionReadsPathConstraints(t *testing.T) {
	existing, _ := policyjson.Array(mustParseValue(t, `[
		{"id":"r1","effect":"DENY","toolPattern":"*","enabled":true,
		 "pathConstraints":{"denied":["*secrets*"]}}
	]`))

	if !policyRuleAlreadyPresent(existing, ruleSpec{Kind: "path", Value: "*secrets*", Effect: "DENY"}) {
		t.Error("the same path on the same side must dedupe")
	}
	if policyRuleAlreadyPresent(existing, ruleSpec{Kind: "path", Value: "*config*", Effect: "DENY"}) {
		t.Error("a different path must not dedupe")
	}
	// A rule carrying only a pathConstraint is CONSTRAINED. Reading it as
	// unconstrained would make a bare `deny <tool>` dedupe against it and
	// silently do nothing.
	if policyRuleAlreadyPresent(existing, ruleSpec{Kind: "tool", ToolPattern: "*", Effect: "DENY"}) {
		t.Error("a path-constrained rule must not count as an unconstrained one")
	}
}

// ── query parsing ───────────────────────────────────────────────────────────

func TestParseIntIsJavaScriptsParseInt(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"12", 12, true},
		{"12abc", 12, true},
		{" -7 ", -7, true},
		{"abc", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := policyParseIntOK(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("policyParseIntOK(%q) = (%d, %v), want (%d, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestReplayWindowConvertsMillisecondsToTheColumnsSeconds(t *testing.T) {
	// The wire carries Date.now(); the column stores Math.floor(ms/1000).
	if got := policyMillisToSeconds(float64(1_700_000_001_999)); got != 1_700_000_001 {
		t.Errorf("policyMillisToSeconds = %d, want the floored second", got)
	}
	// `if (body.from)` is a truthiness test, so an explicit zero is NO bound
	// rather than the epoch.
	if got := policyMillisToSeconds(float64(0)); got != 0 {
		t.Errorf("policyMillisToSeconds(0) = %d, want no bound", got)
	}
}

// ── the gate ────────────────────────────────────────────────────────────────

// Every route in this group authenticates before it does any work. A policy is
// a document naming somebody's paths, commands and internal URLs; an
// unauthenticated read of one is a map of their infrastructure.
func TestEveryPolicyRouteRefusesWithoutAKey(t *testing.T) {
	srv := &server{
		cfg:  config{allowedOrigins: []string{"https://dashboard.solongate.com"}},
		auth: apiauth.New(nil, apiauth.NewLimiter()),
	}
	mux := srv.routes()

	for _, probe := range []struct{ method, path string }{
		{"GET", "/api/v1/policies"},
		{"POST", "/api/v1/policies"},
		{"GET", "/api/v1/policies/active"},
		{"POST", "/api/v1/policies/active"},
		{"GET", "/api/v1/policies/p1"},
		{"PUT", "/api/v1/policies/p1"},
		{"DELETE", "/api/v1/policies/p1"},
		{"POST", "/api/v1/policies/p1/rules"},
		{"DELETE", "/api/v1/policies/p1/rules/r1"},
		{"GET", "/api/v1/policies/p1/rego"},
		{"POST", "/api/v1/policies/dry-run"},
		{"POST", "/api/v1/policies/backtest"},
	} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(probe.method, probe.path, strings.NewReader("{}")))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401 before any work", probe.method, probe.path, rec.Code)
		}
	}
}

// The raw-JSON bodies this slice builds have to reach the wire unchanged.
//
// They are built with internal/policyjson precisely so their bytes match what
// JavaScript would have written, and then handed to apiauth.JSON as a
// json.RawMessage. If that writer re-escaped them — Go's encoder rewrites < > &
// by default — every policy carrying a shell operator or a URL would come back
// different from the one that was hashed.
func TestRawPolicyBodiesReachTheWireUnescaped(t *testing.T) {
	body := `{"command":"sh -c 'a && b > c'","url":"https://x.example?a=1&b=2"}`
	rec := httptest.NewRecorder()
	apiauth.JSON(rec, http.StatusOK, json.RawMessage(body))

	if got := rec.Body.String(); got != body {
		t.Errorf("body = %s, want %s — the response writer must not re-escape a policy", got, body)
	}
}

func mustParseValue(t *testing.T, s string) any {
	t.Helper()
	v, err := policyjson.Parse([]byte(s))
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return v
}

// Permission scoping was dataroom-only, so a rule set could not be written down
// as commands. The builder has to put it where the guard reads it.
func TestBuildRuleCarriesPermissionScoping(t *testing.T) {
	rule := policyBuildRule(ruleSpec{
		Kind: "path", Value: "*secrets*", Effect: "DENY", Permission: []string{"READ", "WRITE"},
	}, true)
	got := policyjson.Stringify(rule, nil)

	if !strings.Contains(got, `"permission":["READ","WRITE"]`) {
		t.Errorf("permission not written: %s", got)
	}

	// Absent means every class, which is what a rule without it has always meant.
	plain := policyjson.Stringify(policyBuildRule(ruleSpec{Kind: "path", Value: "*x*", Effect: "DENY"}, true), nil)
	if strings.Contains(plain, "permission") {
		t.Errorf("an unscoped rule must not grow a permission field: %s", plain)
	}
}

// Two rules over the same target scoped to DIFFERENT classes of call are not
// the same rule. Deduping them is worse than a wasted write: the second is
// silently not created, the CLI reports success, and the policy keeps enforcing
// the scope the user just replaced.
func TestDuplicateDetectionSeparatesPermissionScopes(t *testing.T) {
	existing, _ := policyjson.Array(mustParseValue(t, `[
		{"id":"r1","effect":"DENY","toolPattern":"*","enabled":true,
		 "permission":["WRITE"],"pathConstraints":{"denied":["*data*"]}}
	]`))

	if !policyRuleAlreadyPresent(existing, ruleSpec{
		Kind: "path", Value: "*data*", Effect: "DENY", Permission: []string{"WRITE"},
	}) {
		t.Error("the same scope over the same path must dedupe")
	}
	if policyRuleAlreadyPresent(existing, ruleSpec{
		Kind: "path", Value: "*data*", Effect: "DENY", Permission: []string{"EXECUTE"},
	}) {
		t.Error("a different scope must NOT dedupe; the new rule would never be written")
	}
	// Unscoped covers every class, so it is a different rule from a scoped one.
	if policyRuleAlreadyPresent(existing, ruleSpec{Kind: "path", Value: "*data*", Effect: "DENY"}) {
		t.Error("an unscoped rule must not dedupe against a scoped one")
	}
}

func TestPermissionComparisonIgnoresOrderAndTreatsEmptyAsUnscoped(t *testing.T) {
	both, _ := policyjson.Array(mustParseValue(t, `[["READ","WRITE"]]`))
	if !policySamePermission(both[0], []string{"WRITE", "READ"}) {
		t.Error("order must not matter")
	}
	if policySamePermission(both[0], []string{"READ"}) {
		t.Error("a subset is not the same scope")
	}
	// Absent, empty and null all mean every class.
	for _, stored := range []any{nil, []any{}} {
		if !policySamePermission(stored, nil) {
			t.Errorf("%v should read as unscoped", stored)
		}
		if policySamePermission(stored, []string{"READ"}) {
			t.Errorf("%v must not match a scoped rule", stored)
		}
	}
}
