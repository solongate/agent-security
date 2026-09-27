package main

// Tests for the auth, keys and organisation slice.
//
// Almost nothing here touches a database. The handlers all reach one, so what
// is testable without inventing a fake store is the part where a port actually
// goes wrong: the value coercions that stand in for JavaScript's, the two
// things that are hashed, and whether the routes were claimed at all. The
// golden vectors below were produced by running the TypeScript this replaces
// under node, which is the only way to prove the two agree rather than to
// assert that this file agrees with itself.
//
// The exception is the session route, at the bottom. It runs against a scratch
// sqlite file because the question there is not what a function returns but
// what the route WROTE, and because it is the route every account in the
// product signs in through: a change to it that reads fine and provisions
// wrongly is an outage nobody can log in to report.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeyevsky/solongate/system/internal/store"

	_ "modernc.org/sqlite"
)

// authSlicePatterns is every route this slice is responsible for. A pattern
// that falls out of an init() stops being served and starts answering 501,
// which is a change nothing else would notice.
var authSlicePatterns = []string{
	"POST /api/v1/auth",
	"GET /api/v1/auth/me",
	"GET /api/v1/auth/profile",
	"PUT /api/v1/auth/profile",
	"POST /api/v1/auth/session",
	"GET /api/v1/keys",
	"POST /api/v1/keys",
	"PATCH /api/v1/keys/{id}",
	"DELETE /api/v1/keys/{id}",
	"GET /api/v1/orgs",
	"POST /api/v1/orgs",
	"GET /api/v1/orgs/{id}",
	"PUT /api/v1/orgs/{id}",
	"DELETE /api/v1/orgs/{id}",
	"GET /api/v1/orgs/{id}/members",
	"POST /api/v1/orgs/{id}/members",
	"DELETE /api/v1/orgs/{id}/members",
}

func TestAuthSliceClaimsEveryRoute(t *testing.T) {
	for _, pattern := range authSlicePatterns {
		if _, ok := routeHandlers[pattern]; !ok {
			t.Errorf("%s is not registered; it would answer 501", pattern)
		}
	}
}

func TestAuthSlicePatternsAreInTheRouteTable(t *testing.T) {
	// A handler registered under a pattern the table does not list is served
	// anyway, but only after a log line nobody reads. This catches the typo.
	table := map[string]bool{}
	for _, p := range RoutePatterns() {
		table[p] = true
	}
	for _, pattern := range authSlicePatterns {
		if !table[pattern] {
			t.Errorf("%s is registered but is not a route the table declares", pattern)
		}
	}
}

// ── passwords ───────────────────────────────────────────────────────────────

// The vectors are node's, produced by running src/app/api/v1/auth/route.ts's
// hashPassword against a fixed salt. The second one matters more than the
// first: a password outside ASCII is where a UTF-16 implementation and a UTF-8
// one produce different digests, which is the bug sgshared exists because of.
// Everyone with a non-ASCII password would have been locked out and the cause
// would have looked like anything but an encoding.
func TestPasswordHashMatchesTheNodeImplementation(t *testing.T) {
	cases := []struct{ password, salt, want string }{
		{
			password: "correct horse battery staple",
			salt:     "0123456789abcdef0123456789abcdef",
			want:     "pbkdf2:100000:0123456789abcdef0123456789abcdef:69a26fc4b1624cd29ecc2b2444aa876251575c65deb4af9effbd9eadbd4195c6",
		},
		{
			password: "pässwörd-ünïcode-🔐",
			salt:     "aabbccddeeff00112233445566778899",
			want:     "fccf233f9736e4cfaebb919cc2e76272adac9de32bac73b6ca46cde545d1711e",
		},
	}
	for _, c := range cases {
		got, err := authHashPassword(c.password, c.salt)
		if err != nil {
			t.Fatalf("hashing %q: %v", c.password, err)
		}
		if !strings.HasSuffix(got, c.want) {
			t.Errorf("hash of %q = %q, want it to end in %q", c.password, got, c.want)
		}
		if !authVerifyPassword(c.password, got) {
			t.Errorf("a hash of %q does not verify against itself", c.password)
		}
		if authVerifyPassword(c.password+"x", got) {
			t.Errorf("a wrong password verified against the hash of %q", c.password)
		}
	}
}

func TestPasswordHashSaltsEachCall(t *testing.T) {
	a, err := authHashPassword("hunter22", "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := authHashPassword("hunter22", "")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two hashes of the same password are identical; the salt is not random")
	}
	if !authVerifyPassword("hunter22", a) || !authVerifyPassword("hunter22", b) {
		t.Error("a freshly salted hash does not verify")
	}
}

func TestPasswordVerifyRejectsMalformedStoredValues(t *testing.T) {
	// Every one of these is a row that cannot match any password. None of them
	// may be an error, and none may accidentally return true: the empty-salt
	// case in particular re-enters the "mint a salt" branch.
	for _, stored := range []string{
		"", "pbkdf2", "pbkdf2:100000:salt", "scrypt:100000:salt:00",
		"pbkdf2:100000::00", "pbkdf2:100000:salt:notahexdigest",
	} {
		if authVerifyPassword("anything", stored) {
			t.Errorf("verify accepted the stored value %q", stored)
		}
	}
}

// ── the starter policy ──────────────────────────────────────────────────────

// The golden document is JSON.stringify's output for starterPolicy() with the
// ids replaced by a counter. It pins KEY ORDER, which a Go map would sort and a
// struct preserves — and key order is what the stored hash is over, so a
// reordering would be invisible in every test that parses the JSON first.
const starterPolicyGolden = `{"id":"00000000-0000-4000-8000-000000000000","name":"Starter protection","description":"Destructive commands, credential files and known exfiltration targets.","mode":"denylist","rules":[{"id":"00000000-0000-4000-8000-000000000001","description":"Destructive filesystem commands wipe work that cannot be recovered.","effect":"DENY","priority":10,"toolPattern":"*","minimumTrustLevel":"UNTRUSTED","enabled":true,"commandConstraints":{"denied":["rm*","*rm -rf*","*mkfs*","*dd if=*"]}},{"id":"00000000-0000-4000-8000-000000000002","description":"Privilege escalation lets a mistake reach the whole machine.","effect":"DENY","priority":20,"toolPattern":"*","minimumTrustLevel":"UNTRUSTED","enabled":true,"commandConstraints":{"denied":["sudo*","*chmod 777*"]}},{"id":"00000000-0000-4000-8000-000000000003","description":"Credential files are the highest-value thing an agent can read.","effect":"DENY","priority":30,"toolPattern":"*","minimumTrustLevel":"UNTRUSTED","enabled":true,"filenameConstraints":{"denied":["*.env",".env.*","*.pem","*.key","id_rsa","id_ed25519","*credentials*"]}},{"id":"00000000-0000-4000-8000-000000000004","description":"Credential directories hold keys for every service you use.","effect":"DENY","priority":40,"toolPattern":"*","minimumTrustLevel":"UNTRUSTED","enabled":true,"pathConstraints":{"denied":["*/.ssh/*","*/.aws/*","*/.gnupg/*","*/.kube/*"]}},{"id":"00000000-0000-4000-8000-000000000005","description":"Cloud metadata endpoints hand out live machine credentials.","effect":"DENY","priority":50,"toolPattern":"*","minimumTrustLevel":"UNTRUSTED","enabled":true,"urlConstraints":{"denied":["*169.254.169.254*","*metadata.google.internal*"]}},{"id":"00000000-0000-4000-8000-000000000006","description":"Paste sites and webhook catchers are where leaked data goes.","effect":"DENY","priority":60,"toolPattern":"*","minimumTrustLevel":"UNTRUSTED","enabled":true,"urlConstraints":{"denied":["*pastebin.com*","*requestbin*","*webhook.site*","*ngrok.io*"]}}]}`

// starterPolicyGoldenHash is sha256 over those bytes, computed by node. A
// project seeded by either implementation stores the same document and the same
// hash, so the guard's cached-policy comparison keeps working across the
// cutover.
const starterPolicyGoldenHash = "f57b092db3590024a6cde61996c4910ed201ce53ddd4ef829928e8f253ab6da2"

func countingIDs() func() string {
	n := 0
	return func() string {
		id := "00000000-0000-4000-8000-" + strings.Repeat("0", 12-len(itoa(n))) + itoa(n)
		n++
		return id
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestStarterPolicySerialisesLikeJSONStringify(t *testing.T) {
	policy, ok := authStarterPolicy(countingIDs())
	if !ok {
		t.Fatal("the starter policy could not be built")
	}
	got, err := authEncodePolicy(policy)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if string(got) != starterPolicyGolden {
		t.Errorf("serialisation differs from JSON.stringify's.\n got %s\nwant %s", got, starterPolicyGolden)
	}
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != starterPolicyGoldenHash {
		t.Errorf("hash = %s, want %s", hex.EncodeToString(sum[:]), starterPolicyGoldenHash)
	}
}

func TestStarterPolicyRefusesWhenAnIDCannotBeMinted(t *testing.T) {
	// authNewID returns empty when the CSPRNG refuses, and a policy carrying an
	// empty rule id is a policy the editor cannot address.
	if _, ok := authStarterPolicy(func() string { return "" }); ok {
		t.Fatal("a policy was built from empty ids")
	}
}

// ── the JavaScript coercions ────────────────────────────────────────────────

func TestUTF16LenCountsCodeUnitsNotRunesOrBytes(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 3},
		// Two bytes in UTF-8, one code unit in UTF-16. Counting bytes would
		// refuse a name the live app accepts.
		{"é", 1},
		// Outside the basic plane: one rune, one code point, TWO code units.
		// Counting runes would accept a password the live app refuses.
		{"🔐", 2},
		{"a🔐b", 4},
	}
	for _, c := range cases {
		if got := authUTF16Len(c.in); got != c.want {
			t.Errorf("authUTF16Len(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSlugifyMatchesTheOriginalReplacements(t *testing.T) {
	cases := []struct{ in, want string }{
		{"My Project", "my-project"},
		{"Ada's Project", "ada-s-project"},
		// A run of non-alphanumerics collapses to ONE hyphen, so a name that
		// begins and ends with punctuation loses exactly one at each end —
		// `/^-|-$/g` can match at most once per anchor however long the run was.
		{"a   ---   b", "a-b"},
		{"!!hello!!", "hello"},
		{"!hello!", "hello"},
		{"a!", "a"},
		{"!a", "a"},
		{"---", ""},
		{"", ""},
		// Accented letters are not transliterated. The result is ugly and it is
		// what is already in the slug column.
		{"héllo wörld", "h-llo-w-rld"},
	}
	for _, c := range cases {
		if got := authSlugify(c.in); got != c.want {
			t.Errorf("authSlugify(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestJSTruthyAndStringMatchJavaScript(t *testing.T) {
	// These stand in for `body.name || 'API Key'` and `String(body.name)`, which
	// is why a number has to survive rather than become a 400.
	if authJSTruthy(nil) || authJSTruthy("") || authJSTruthy(false) || authJSTruthy(float64(0)) {
		t.Error("a falsy JSON value was treated as truthy")
	}
	if !authJSTruthy("a") || !authJSTruthy(true) || !authJSTruthy(float64(1)) {
		t.Error("a truthy JSON value was treated as falsy")
	}
	if got := authJSString(float64(123)); got != "123" {
		t.Errorf("authJSString(123) = %q, want \"123\"", got)
	}
	if got := authJSString(true); got != "true" {
		t.Errorf("authJSString(true) = %q, want \"true\"", got)
	}
	if got := authJSString(nil); got != "" {
		t.Errorf("authJSString(nil) = %q, want \"\"", got)
	}
}

func TestEmailRegexIsTheOriginalOne(t *testing.T) {
	valid := []string{"a@b.c", "someone@example.com", "a.b+c@sub.domain.co.uk"}
	invalid := []string{"", "nope", "a@b", "a b@c.d", "@b.c", "a@.c", "a@b c.d"}
	for _, v := range valid {
		if !authEmailRE.MatchString(v) {
			t.Errorf("%q was refused and the live app accepts it", v)
		}
	}
	for _, v := range invalid {
		if authEmailRE.MatchString(v) {
			t.Errorf("%q was accepted and the live app refuses it", v)
		}
	}
	// A newline must not sneak an address past the anchors. Go's `$` without
	// (?m) matches at end of text only, as JavaScript's does without /m.
	if authEmailRE.MatchString("a@b.c\nnot-an-address") {
		t.Error("the anchors are matching per line")
	}
}

func TestNullableRendersAnAbsentNameAsJSONNull(t *testing.T) {
	if authNullable("") != nil {
		t.Error("an empty name must render as null, which is what the column holds")
	}
	if authNullable("Ada") != any("Ada") {
		t.Error("a name must render as itself")
	}
}

// ── the session route ───────────────────────────────────────────────────────

// This is the one part of the slice that does touch a database, and it is worth
// the scratch file: /v1/auth/session is how every browser and every CLI signs
// in, and the thing under test is whether a request WITHOUT the new field still
// behaves exactly as it did. That question cannot be answered by a unit test of
// a coercion — it is about what the route wrote and what it sent back.
//
// The tables are the four the route writes plus system_settings, copied from
// internal/store/baseschema.sql. They are declared here rather than by running it
// because it is a Turso dump of forty tables with foreign keys into all of them,
// and a test that needs the whole schema to prove one branch is a test nobody
// will keep working.
const authSessionSchema = `
CREATE TABLE users (
	id text PRIMARY KEY NOT NULL,
	email text NOT NULL,
	name text,
	password_hash text,
	created_at integer NOT NULL,
	updated_at integer NOT NULL
);
CREATE TABLE projects (
	id text PRIMARY KEY NOT NULL,
	owner_id text NOT NULL,
	org_id text,
	name text NOT NULL,
	slug text NOT NULL,
	description text DEFAULT '',
	token_secret text NOT NULL,
	created_at integer NOT NULL,
	updated_at integer NOT NULL
);
CREATE UNIQUE INDEX projects_slug_unique ON projects (slug);
CREATE TABLE policy_versions (
	id text PRIMARY KEY NOT NULL,
	project_id text NOT NULL,
	version integer NOT NULL,
	policy_data text NOT NULL,
	hash text NOT NULL,
	reason text,
	created_by text,
	rego_source text,
	wasm_bundle text,
	variant_artifacts text,
	created_at integer NOT NULL
);
CREATE TABLE api_keys (
	id text PRIMARY KEY NOT NULL,
	project_id text NOT NULL,
	key_prefix text NOT NULL,
	key_hash text NOT NULL,
	name text NOT NULL,
	is_live integer DEFAULT false NOT NULL,
	user_id text,
	last_used_at integer,
	revoked_at integer,
	created_at integer NOT NULL
);
CREATE TABLE system_settings (
	key text PRIMARY KEY NOT NULL,
	value text NOT NULL,
	description text,
	updated_by text,
	updated_at integer NOT NULL
);`

func authSessionServer(t *testing.T) *server {
	t.Helper()
	// Unset, both spellings, so the route takes its unverified branch and reads
	// the address off the body. With either of them set the test would depend on
	// a Supabase this machine cannot reach.
	t.Setenv("SUPABASE_URL", "")
	t.Setenv("NEXT_PUBLIC_SUPABASE_URL", "")

	path := t.TempDir() + "/auth.db"
	base, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("opening the scratch database: %v", err)
	}
	if _, err := base.Exec(authSessionSchema); err != nil {
		t.Fatalf("creating the tables: %v", err)
	}
	if err := base.Close(); err != nil {
		t.Fatalf("closing the scratch database: %v", err)
	}

	st, err := store.Open("file:" + path)
	if err != nil {
		t.Fatalf("opening the scratch database: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// A stub verifier, and an OIDC issuer so authIdentityConfigured agrees this
	// deployment can prove who somebody is. The route reads the address off the
	// token now and never off the body, so a test that wants to BE somebody
	// presents a token whose value is their address — which is also why these
	// bodies carry an access_token rather than an email.
	t.Setenv("SG_OIDC_ISSUER", "https://idp.test")
	return &server{
		store: st,
		verifyAccessToken: func(_ context.Context, token string) (string, bool) {
			if token == "" || !strings.Contains(token, "@") {
				return "", false
			}
			return token, true
		},
	}
}

// authSessionAnswer is the response as a caller reads it. The two pointers are
// the point of the type: they tell an absent or null field apart from an empty
// string, which is the whole difference between "here is your workspace" and
// "you have none".
type authSessionAnswer struct {
	APIKey  *string `json:"api_key"`
	Project *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"project"`
}

// authSessionPost returns the decoded answer and the bytes it was decoded from,
// because one test is about the shape on the wire rather than about what a Go
// decoder can be talked into producing.
func authSessionPost(t *testing.T, s *server, body string) (int, authSessionAnswer, string) {
	t.Helper()
	r := httptest.NewRequest("POST", "/api/v1/auth/session", strings.NewReader(body))
	w := httptest.NewRecorder()
	s.authSession(w, r)

	var out authSessionAnswer
	if w.Code == 200 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("the response is not the documented shape: %v\n%s", err, w.Body.String())
		}
	}
	return w.Code, out, strings.TrimSpace(w.Body.String())
}

func authSessionCount(t *testing.T, s *server, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.store.DB().QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("counting: %v", err)
	}
	return n
}

// The default is the contract with every caller that has ever made this call.
// The CLI, the device flow and any dashboard still deployed send no
// create_project, and all of them are unusable the moment this answers without
// a project or without a key.
func TestAuthSessionCreatesAProjectWhenTheFieldIsAbsent(t *testing.T) {
	s := authSessionServer(t)

	status, out, _ := authSessionPost(t, s, `{"access_token":"ada@example.com","project_name":"Ada's Project"}`)
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	if out.Project == nil || out.Project.ID == "" {
		t.Fatal("no project came back; every existing caller signs in expecting one")
	}
	if out.Project.Name != "Ada's Project" {
		t.Errorf("project name = %q, want the one that was asked for", out.Project.Name)
	}
	if out.APIKey == nil || *out.APIKey == "" {
		t.Fatal("no api_key came back; the dashboard has nothing to call the API with")
	}

	if n := authSessionCount(t, s, `SELECT count(*) FROM projects`); n != 1 {
		t.Errorf("%d projects were written, want 1", n)
	}
	// The starter policy is not decoration. A project with none means an
	// installed guard that permits everything, so it is part of what "created a
	// project" has to mean.
	if n := authSessionCount(t, s, `SELECT count(*) FROM policy_versions`); n != 1 {
		t.Errorf("%d policies were seeded, want 1", n)
	}
	if n := authSessionCount(t, s,
		`SELECT count(*) FROM api_keys WHERE name = ? AND revoked_at IS NULL`, authSessionKeyName); n != 1 {
		t.Errorf("%d live session keys, want 1", n)
	}
}

// An explicit true is the same request as an absent field. It exists so a
// caller can say what it wants rather than rely on the default staying put.
func TestAuthSessionCreatesAProjectWhenTheFieldIsTrue(t *testing.T) {
	s := authSessionServer(t)

	status, out, _ := authSessionPost(t, s, `{"access_token":"ada@example.com","create_project":true}`)
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	if out.Project == nil || out.Project.ID == "" || out.APIKey == nil {
		t.Fatal("create_project:true did not create one")
	}
}

// WHICH WORKSPACE, ASKED FOR AND CHECKED.
//
// This route answered with the account's most recent project and nothing else,
// so an account with two workspaces had one it could reach: making a second one
// silently moved the whole dashboard into it, the switcher changed a name in the
// chrome and not a single call under it, and the workspace with all the history
// in it read as one whose data had been deleted.
func TestAuthSessionAnswersForTheWorkspaceThatWasAskedFor(t *testing.T) {
	s := authSessionServer(t)

	// One workspace from signing in, and a second made the way the dashboard
	// makes them - so the newer one is the "latest" this route used to hand
	// back no matter which one anybody was looking at.
	_, first, _ := authSessionPost(t, s, `{"access_token":"ada@example.com","project_name":"First"}`)
	if first.Project == nil {
		t.Fatal("the fixture did not produce a workspace")
	}
	older := first.Project.ID
	owner, err := s.store.ProjectOwner(context.Background(), older)
	if err != nil {
		t.Fatal(err)
	}
	now := store.Now()
	if err := s.store.CreateProject(context.Background(), store.Project{
		ID: "p-second", OwnerID: owner, Name: "Second", Slug: "second-0001",
		TokenSecret: "secret", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	// Asking for the second one by name answers with the second one, which is
	// the whole point: with nothing asked for this route picks by created_at and
	// the caller has no say at all.
	if _, other, _ := authSessionPost(t, s,
		`{"access_token":"ada@example.com","create_project":false,"project_id":"p-second"}`); other.Project == nil || other.Project.ID != "p-second" {
		t.Fatalf("asking for the newer workspace answered with %+v", other.Project)
	}

	status, out, _ := authSessionPost(t, s,
		`{"access_token":"ada@example.com","create_project":false,"project_id":"`+older+`"}`)
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	if out.Project == nil || out.Project.ID != older {
		t.Fatalf("asking for %q answered with %+v", older, out.Project)
	}
	if out.APIKey == nil || *out.APIKey == "" {
		t.Fatal("no key came back for a workspace that was asked for by id")
	}

	// AN ID IS NOT A PERMISSION. Somebody else's workspace falls back to this
	// account's own rather than handing over a key to it.
	_, mallory, _ := authSessionPost(t, s, `{"access_token":"mallory@example.com","project_name":"Mallory's"}`)
	if mallory.Project == nil {
		t.Fatal("the second account has no workspace to be stolen from")
	}
	_, stolen, _ := authSessionPost(t, s,
		`{"access_token":"ada@example.com","create_project":false,"project_id":"`+mallory.Project.ID+`"}`)
	if stolen.Project != nil && stolen.Project.ID == mallory.Project.ID {
		t.Fatal("a key was minted for somebody else's workspace, for the asking")
	}
	// And a workspace that does not exist is not an error: it is the answer this
	// route gave before anybody could ask.
	_, gone, _ := authSessionPost(t, s,
		`{"access_token":"ada@example.com","create_project":false,"project_id":"no-such-project"}`)
	if gone.Project == nil || gone.Project.ID == "" {
		t.Error("a stale id in a cookie signs somebody out of their own account")
	}
}

// The opt-out, which is what the dashboard sends. An account that has just been
// made owns nothing, and nothing is what it must be given.
func TestAuthSessionOptOutCreatesNoProjectAndNoKey(t *testing.T) {
	s := authSessionServer(t)

	status, out, raw := authSessionPost(t, s, `{"access_token":"ada@example.com","create_project":false}`)
	if status != 200 {
		t.Fatalf("status = %d, want 200 — having no workspace is not a failed sign-in", status)
	}
	// Pinned as bytes: a caller reading this answer is a browser and a CLI, not
	// a Go struct, and "the field is null" is the thing they branch on.
	if raw != `{"api_key":null,"project":null}` {
		t.Errorf("the answer is %s, want both fields present and null", raw)
	}
	if out.Project != nil {
		t.Errorf("a project came back: %+v", *out.Project)
	}
	if out.APIKey != nil {
		t.Error("an api_key came back for an account with no project to scope it to")
	}

	// The account itself IS created. That is the half of the route the opt-out
	// does not touch: the person exists, they simply have nowhere to work yet.
	if n := authSessionCount(t, s, `SELECT count(*) FROM users`); n != 1 {
		t.Errorf("%d users, want 1", n)
	}
	if n := authSessionCount(t, s, `SELECT count(*) FROM projects`); n != 0 {
		t.Errorf("%d projects were written, want none", n)
	}
	if n := authSessionCount(t, s, `SELECT count(*) FROM policy_versions`); n != 0 {
		t.Errorf("%d policies were seeded for a project that does not exist", n)
	}
	// The mint is the dangerous one: a row here would be a live credential
	// scoped to the empty string, which no screen in the product can show and
	// no owner can revoke.
	if n := authSessionCount(t, s, `SELECT count(*) FROM api_keys`); n != 0 {
		t.Errorf("%d keys were minted with no project", n)
	}
}

// The opt-out suppresses CREATION and nothing else. Every account that already
// has a workspace signs in through this branch on every page load, and it is
// the one that must not change.
func TestAuthSessionOptOutStillReturnsAProjectThatExists(t *testing.T) {
	s := authSessionServer(t)

	if _, out, _ := authSessionPost(t, s, `{"access_token":"ada@example.com"}`); out.Project == nil {
		t.Fatal("the first sign-in made no project to test against")
	}

	status, out, _ := authSessionPost(t, s, `{"access_token":"ada@example.com","create_project":false}`)
	if status != 200 {
		t.Fatalf("status = %d, want 200", status)
	}
	if out.Project == nil || out.Project.ID == "" {
		t.Fatal("an account with a workspace was told it has none")
	}
	if out.APIKey == nil || *out.APIKey == "" {
		t.Fatal("no key for a project that exists; every page behind this renders empty")
	}
	if n := authSessionCount(t, s, `SELECT count(*) FROM projects`); n != 1 {
		t.Errorf("%d projects, want the one that was already there", n)
	}
	// The previous session key is retired by the second sign-in, which is what
	// keeps a revoked browser tab from going on working.
	if n := authSessionCount(t, s,
		`SELECT count(*) FROM api_keys WHERE name = ? AND revoked_at IS NULL`, authSessionKeyName); n != 1 {
		t.Errorf("%d live session keys after two sign-ins, want 1", n)
	}
}

// ── ids ─────────────────────────────────────────────────────────────────────

func TestNewIDIsAVersion4UUID(t *testing.T) {
	id := authNewID()
	if len(id) != 36 {
		t.Fatalf("id %q is %d characters, want 36", id, len(id))
	}
	if id[14] != '4' {
		t.Errorf("id %q is not version 4", id)
	}
	if c := id[19]; c != '8' && c != '9' && c != 'a' && c != 'b' {
		t.Errorf("id %q does not carry the RFC 4122 variant", id)
	}
	if authNewID() == id {
		t.Error("two ids are identical")
	}
}

// ── who a sign-in belongs to ────────────────────────────────────────────────

// A BODY CANNOT NAME AN ACCOUNT. This is the hole the route had, and the reason
// it is worth a test of its own rather than a line in another one.
//
// The gate used to be `if authSupabaseBase() != ""`, which asked the wrong
// question twice: a deployment on OIDC has no Supabase, so the token was never
// verified — and with neither configured the route logged "running unverified"
// and provisioned whatever address the request body named. A credential for any
// account, to anybody who could reach the port.
func TestAuthSessionWillNotTakeAnAddressFromTheBody(t *testing.T) {
	s := authSessionServer(t)

	// The old shape: an address and no token. It must not mint anything.
	status, out, body := authSessionPost(t, s, `{"email":"boss@example.com","project_name":"Theirs"}`)
	if status == 200 {
		t.Fatalf("a body-named address signed in and got %s", body)
	}
	if status != 401 {
		t.Errorf("status = %d, want 401", status)
	}
	if out.APIKey != nil {
		t.Error("a credential was issued")
	}
	// And nothing was created on the way to refusing.
	if n := authSessionCount(t, s, `SELECT count(*) FROM users WHERE email = ?`, "boss@example.com"); n != 0 {
		t.Errorf("the refusal still provisioned %d account(s)", n)
	}
}

// A token the provider will not vouch for is a 401, not an account.
func TestAuthSessionRefusesAnUnverifiableToken(t *testing.T) {
	s := authSessionServer(t)

	// The stub verifier refuses anything without an "@"; production refuses
	// anything the provider's keys do not sign.
	status, out, _ := authSessionPost(t, s, `{"access_token":"not-a-real-token"}`)
	if status != 401 {
		t.Errorf("status = %d, want 401", status)
	}
	if out.APIKey != nil {
		t.Error("a credential was issued for an unverifiable token")
	}
}

// With no provider configured there is nothing to verify against, so the route
// refuses instead of trusting the caller.
//
// 503 rather than 401: the caller did nothing wrong and nothing they can send
// will help. It is the deployment that is unfinished, and the message says which
// variable finishes it.
func TestAuthSessionRefusesWhenNoProviderIsConfigured(t *testing.T) {
	s := authSessionServer(t)
	t.Setenv("SG_OIDC_ISSUER", "")
	t.Setenv("SUPABASE_URL", "")
	t.Setenv("NEXT_PUBLIC_SUPABASE_URL", "")

	status, _, body := authSessionPost(t, s, `{"access_token":"ada@example.com"}`)
	if status != 503 {
		t.Errorf("status = %d, want 503", status)
	}
	if !strings.Contains(body, "SG_OIDC_ISSUER") {
		t.Errorf("the refusal does not name what to configure: %s", body)
	}
}
