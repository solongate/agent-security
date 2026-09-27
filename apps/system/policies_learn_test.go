package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/policyjson"
	"github.com/codeyevsky/solongate/system/internal/policysynth"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// Tests for POST /v1/policies/learn and POST /v1/setup.
//
// The ones at the top need no database. The ones at the bottom need a real one
// and are SKIPPED without it, because the queries are the half of these routes
// that reading cannot check — a column that is not there compiles perfectly.
// tools/local-db.mjs builds a database with the real schema in about four
// seconds; point the two variables at it:
//
//	node tools/local-db.mjs
//	cd apps/system && SOLONGATE_TEST_DB=$PWD/../../.local-db/solongate.sqlite \
//	  SOLONGATE_TEST_KEY=$(cat ../../.local-db/api-key.txt) go test -run Learn ./...
//
// The database-backed tests write their own audit rows and delete them again,
// so they must only ever be pointed at a scratch database.

func TestLearnAndSetupAreRegistered(t *testing.T) {
	for _, pattern := range []string{"POST /api/v1/policies/learn", "POST /api/v1/setup"} {
		if _, ok := routeHandlers[pattern]; !ok {
			t.Errorf("%s is not registered", pattern)
		}
	}
}

// The limit expression is `Number(body.limit) || 1000` clamped to 1..5000, and
// the `||` swallows zero as well as NaN. A caller asking for no rows gets a
// thousand, and one asking for a million gets five thousand — the ceiling is
// what keeps this endpoint from being a way to stream audit_logs.
func TestLearnLimitMatchesTheLiveClamp(t *testing.T) {
	cases := []struct {
		in   any
		want int
	}{
		{nil, 1000},
		{float64(0), 1000},
		{"", 1000},
		{"not a number", 1000},
		{float64(-5), 1},
		{float64(1), 1},
		{float64(2500), 2500},
		{"2500", 2500},
		{float64(1e9), 5000},
	}
	for _, c := range cases {
		if got := learnLimit(c.in); got != c.want {
			t.Errorf("learnLimit(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

// `body.agent_id ? String(body.agent_id) : null`. The case that matters is the
// last one: a truthy value with no string form must still NARROW the query. If
// it fell through to "no filter" a request scoped to one agent would be answered
// with the whole project's history.
func TestLearnAgentFilterNarrowsOrStaysEmpty(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, ""},
		{"", ""},
		{float64(0), ""},
		{false, ""},
		{"claude-code", "claude-code"},
		{float64(7), "7"},
		{policyjson.NewObject(), "[object Object]"},
	}
	for _, c := range cases {
		if got := learnAgentID(c.in); got != c.want {
			t.Errorf("learnAgentID(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The rules the response carries are the shape packages/sgpolicy compiles, in
// the order the original writes them. Both halves matter: a renamed field is a
// rule the compiler reads as empty, and a reordered object is a different hash
// for the same policy once somebody saves it.
func TestLearnedRuleSerialisesInTheCompilersShape(t *testing.T) {
	rule := policysynth.Rule{
		ID: "learn-bash-execute", Description: "Learned: allow Bash (EXECUTE) from 3 observed calls",
		Effect: "ALLOW", Priority: 10, ToolPattern: "Bash", Permission: "EXECUTE",
		MinimumTrustLevel: "VERIFIED", Enabled: true,
		CommandConstraints: &policysynth.Constraint{Allowed: []string{"git *"}},
		SampleCount:        3, LowConfidence: false,
	}
	raw, err := json.Marshal(learnRuleView{Rule: rule, CreatedAt: "t", UpdatedAt: "t"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(raw)
	want := `{"id":"learn-bash-execute","description":"Learned: allow Bash (EXECUTE) from 3 observed calls",` +
		`"effect":"ALLOW","priority":10,"toolPattern":"Bash","permission":"EXECUTE",` +
		`"minimumTrustLevel":"VERIFIED","enabled":true,"commandConstraints":{"allowed":["git *"]},` +
		`"createdAt":"t","updatedAt":"t"}`
	if got != want {
		t.Errorf("rule =\n%s\nwant\n%s", got, want)
	}
	// _sampleCount and _lowConfidence are stripped from the policy — they go out
	// in rules_meta instead, so a policy saved straight from this response does
	// not carry two fields the compiler ignores and the hash includes.
	if bytes.Contains(raw, []byte("ampleCount")) || bytes.Contains(raw, []byte("owConfidence")) {
		t.Error("the synthesis metadata must not be serialised into the policy")
	}
}

// ── the database-backed half ────────────────────────────────────────────────

// learnTestEnv is the scratch database and the key to reach it with, or a skip.
func learnTestEnv(t *testing.T) (*server, string) {
	t.Helper()
	path, key := os.Getenv("SOLONGATE_TEST_DB"), os.Getenv("SOLONGATE_TEST_KEY")
	if path == "" || key == "" {
		t.Skip("SOLONGATE_TEST_DB and SOLONGATE_TEST_KEY are unset; see the file note")
	}
	st, err := store.Open("file:" + path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &server{
		cfg:   config{allowedOrigins: []string{"https://dashboard.solongate.com"}},
		store: st,
		auth:  apiauth.New(st, apiauth.NewLimiter()),
	}, key
}

// learnSeed writes a small history for the key's project and removes it again
// when the test ends.
func learnSeed(t *testing.T, srv *server, key string) string {
	t.Helper()
	ctx := context.Background()
	req := httptest.NewRequest("POST", "/api/v1/policies/learn", nil)
	req.Header.Set("X-API-Key", key)
	info, err := srv.auth.Validate(ctx, req)
	if err != nil {
		t.Fatalf("the key in SOLONGATE_TEST_KEY does not authenticate: %v", err)
	}

	rows := []struct {
		id, tool, perm, trust, decision, args, agent string
	}{
		{"learn-t1", "Bash", "EXECUTE", "TRUSTED", "ALLOW", `{"command":"git status --porcelain"}`, "claude-code"},
		{"learn-t2", "Bash", "EXECUTE", "VERIFIED", "ALLOW", `{"command":"git log -n 5"}`, "claude-code"},
		{"learn-t3", "Read", "READ", "TRUSTED", "ALLOW", `{"file_path":"/srv/app/src/index.ts"}`, "claude-code"},
		{"learn-t4", "Read", "READ", "UNTRUSTED", "ALLOW", `{"file_path":"/srv/app/src/util.ts"}`, "claude-code"},
		{"learn-t5", "Write", "WRITE", "TRUSTED", "ALLOW", `{"file_path":"/srv/app/out/report.txt"}`, "codex"},
		{"learn-t6", "Bash", "EXECUTE", "UNTRUSTED", "DENY", `{"command":"rm -rf /"}`, "claude-code"},
		// arguments_summary is truncated on write, so a fragment is an expected
		// state of the column and must parse to no arguments rather than a 500.
		{"learn-t7", "Grep", "READ", "TRUSTED", "ALLOW", `{"pattern":"tok`, "claude-code"},
	}
	ids := make([]string, 0, len(rows))
	now := store.Now()
	for i, r := range rows {
		ids = append(ids, r.id)
		if err := srv.store.InsertAuditLog(ctx, store.AuditLog{
			ID: r.id, ProjectID: info.ProjectID, RequestID: r.id, ToolName: r.tool,
			Permission: r.perm, TrustLevel: r.trust, Decision: r.decision,
			ArgumentsSummary: r.args, AgentID: r.agent, AgentName: r.agent,
			CreatedAt: now - int64(i),
		}); err != nil {
			t.Fatalf("seed %s: %v", r.id, err)
		}
	}
	t.Cleanup(func() {
		if _, err := srv.store.DeleteAuditLogsByIDs(context.Background(), info.ProjectID, ids); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	return info.ProjectID
}

func learnPost(t *testing.T, srv *server, key, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/policies/learn", bytes.NewBufferString(body))
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	out := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, out
}

func TestLearnDerivesRulesFromRealRows(t *testing.T) {
	srv, key := learnTestEnv(t)
	learnSeed(t, srv, key)

	// An empty body is the dashboard's "learn" button: no fields at all.
	code, body := learnPost(t, srv, key, "")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%v)", code, body)
	}
	if body["tightness"] != "balanced" {
		t.Errorf("tightness = %v, want balanced by default", body["tightness"])
	}

	policy := body["policy"].(map[string]any)
	if policy["mode"] != "whitelist" || policy["id"] != "learned-policy" {
		t.Errorf("policy = %v, want the whitelist proposal shape", policy)
	}
	rules := map[string]map[string]any{}
	for _, r := range policy["rules"].([]any) {
		rule := r.(map[string]any)
		rules[rule["id"].(string)] = rule
	}

	bash, ok := rules["learn-bash-execute"]
	if !ok {
		t.Fatalf("no rule for the two allowed Bash calls; rules = %v", rules)
	}
	// The two allowed Bash calls ran at TRUSTED and VERIFIED, so the rule demands
	// the LOWER of them. Taking the higher would refuse a call the sample shows
	// being allowed.
	if bash["minimumTrustLevel"] != "VERIFIED" {
		t.Errorf("minimumTrustLevel = %v, want VERIFIED (the lowest level observed)", bash["minimumTrustLevel"])
	}
	cmd := bash["commandConstraints"].(map[string]any)["allowed"].([]any)
	if len(cmd) != 1 || cmd[0] != "git *" {
		t.Errorf("commandConstraints = %v, want the two git calls generalised to one glob", cmd)
	}
	// The DENIED `rm -rf /` must not have contributed a constraint.
	for _, v := range cmd {
		if v == "rm *" {
			t.Error("a denied call contributed a rule constraint")
		}
	}
	read := rules["learn-read-read"]
	paths := read["pathConstraints"].(map[string]any)["allowed"].([]any)
	if len(paths) != 1 || paths[0] != "/srv/app/src/**" {
		t.Errorf("pathConstraints = %v, want the two files generalised to their directory", paths)
	}
	// The unparseable summary still produces a rule — with no constraints, since
	// there were no arguments to read.
	grep, ok := rules["learn-grep-read"]
	if !ok {
		t.Fatal("a row with a truncated arguments_summary produced no rule")
	}
	if _, has := grep["pathConstraints"]; has {
		t.Errorf("grep rule = %v, want no constraints from an unparseable summary", grep)
	}

	// The proposal has to allow the traffic it was derived from; that is all
	// self_consistent claims, and the field is checked because a whitelist that
	// blocks its own training data is broken rather than strict.
	validation := body["validation"].(map[string]any)
	if validation["self_consistent"] != true || validation["newly_blocked"].(float64) != 0 {
		t.Errorf("validation = %v, want the sample to survive its own rules", validation)
	}
	// The denied call is reported separately rather than silently dropped.
	denies := body["deny_summary"].([]any)
	if len(denies) == 0 {
		t.Fatal("deny_summary is empty; the denied call must still be reported")
	}
	first := denies[0].(map[string]any)
	if first["tool"] != "Bash" || first["permission"] != "EXECUTE" {
		t.Errorf("deny_summary[0] = %v, want the denied Bash call", first)
	}
}

// tight keeps the observed value, loose drops constraints entirely. The second
// is the one worth a test: a loose policy is scoped by tool and permission only,
// which is a much weaker rule than the page's wording suggests.
func TestLearnTightnessChangesTheConstraints(t *testing.T) {
	srv, key := learnTestEnv(t)
	learnSeed(t, srv, key)

	_, tight := learnPost(t, srv, key, `{"tightness":"tight"}`)
	rules := tight["policy"].(map[string]any)["rules"].([]any)
	found := false
	for _, r := range rules {
		rule := r.(map[string]any)
		if rule["id"] != "learn-read-read" {
			continue
		}
		found = true
		paths := rule["pathConstraints"].(map[string]any)["allowed"].([]any)
		if len(paths) != 2 || paths[0] != "/srv/app/src/index.ts" {
			t.Errorf("tight pathConstraints = %v, want the observed files themselves", paths)
		}
	}
	if !found {
		t.Fatal("no Read rule at tight")
	}

	_, loose := learnPost(t, srv, key, `{"tightness":"loose"}`)
	for _, r := range loose["policy"].(map[string]any)["rules"].([]any) {
		rule := r.(map[string]any)
		for _, kind := range []string{"pathConstraints", "commandConstraints", "urlConstraints"} {
			if _, has := rule[kind]; has {
				t.Errorf("loose rule %v carries %s; loose emits none", rule["id"], kind)
			}
		}
	}
	if loose["tightness"] != "loose" {
		t.Errorf("tightness = %v, want it echoed back", loose["tightness"])
	}
	// An unrecognised value is balanced, not a 400.
	_, odd := learnPost(t, srv, key, `{"tightness":"TIGHT"}`)
	if odd["tightness"] != "balanced" {
		t.Errorf("tightness = %v, want balanced for an unrecognised value", odd["tightness"])
	}
}

// agent_id narrows the sample WITHIN the project. The assertion is that it is a
// filter and not a scope: it cannot reach another project's rows, and it does
// not stop the project clause from applying.
func TestLearnAgentFilterIsAppliedInsideTheProject(t *testing.T) {
	srv, key := learnTestEnv(t)
	learnSeed(t, srv, key)

	_, body := learnPost(t, srv, key, `{"agent_id":"codex"}`)
	rules := body["policy"].(map[string]any)["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("rules = %v, want only the one tool that agent used", rules)
	}
	if id := rules[0].(map[string]any)["id"]; id != "learn-write-write" {
		t.Errorf("rule id = %v, want the codex row's tool", id)
	}

	// An agent nobody has reported produces an empty proposal rather than the
	// project's whole history.
	_, none := learnPost(t, srv, key, `{"agent_id":"no-such-agent"}`)
	if got := none["stats"].(map[string]any)["sampled"].(float64); got != 0 {
		t.Errorf("sampled = %v for an unknown agent, want 0", got)
	}
}

func TestLearnRefusesWithoutAKey(t *testing.T) {
	srv, _ := learnTestEnv(t)
	code, body := learnPost(t, srv, "", `{}`)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	if e, _ := body["error"].(map[string]any); e == nil || e["code"] != "AUTHENTICATION_ERROR" {
		t.Errorf("error = %v, want the live AUTHENTICATION_ERROR shape", body["error"])
	}
}

// The sample must never cross a project boundary. A key resolves to one project
// and the query's WHERE carries it; this asserts the store query rather than the
// handler, because the handler has no other way to be wrong about it.
func TestLearnSampleIsProjectScoped(t *testing.T) {
	srv, key := learnTestEnv(t)
	projectID := learnSeed(t, srv, key)

	ctx := context.Background()
	mine, err := srv.store.LearnSample(ctx, projectID, "", 5000)
	if err != nil {
		t.Fatalf("LearnSample: %v", err)
	}
	if len(mine) == 0 {
		t.Fatal("the seeded rows are not readable")
	}
	other, err := srv.store.LearnSample(ctx, "not-this-project", "", 5000)
	if err != nil {
		t.Fatalf("LearnSample: %v", err)
	}
	if len(other) != 0 {
		t.Errorf("a different project id returned %d rows", len(other))
	}
}
