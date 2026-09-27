package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// POST /v1/setup is the most exposed endpoint in the service — no API key, a
// per-IP limit and nothing else — so what is tested here is mostly what it
// REFUSES. The database-backed test at the bottom follows the same skip rule as
// the Learn Mode ones; see the note in policies_learn_test.go.

// `body.project_name.length` in JavaScript is UTF-16 code units, an array has a
// length too, and everything else has none — in which case both comparisons are
// false and the live route falls through to a TypeError. All three answers are
// reproduced, because a name that is not a string must never reach the insert.
func TestSetupLengthIsJavaScriptsLength(t *testing.T) {
	cases := []struct {
		in         any
		want       int
		measurable bool
	}{
		{"ab", 2, true},
		{"", 0, true},
		// One rune, two UTF-16 units — the live route counts two, and a byte or
		// rune count here would refuse a name the live app accepts.
		{"😀", 2, true},
		{"日本", 2, true},
		{[]any{"ab", "cd", "ef"}, 3, true},
		{true, 0, false},
		{float64(12345), 0, false},
		{nil, 0, false},
	}
	for _, c := range cases {
		got, measurable := setupLength(c.in)
		if got != c.want || measurable != c.measurable {
			t.Errorf("setupLength(%v) = (%d, %v), want (%d, %v)", c.in, got, measurable, c.want, c.measurable)
		}
	}
}

// The address gate. The last case is the reason this function exists rather than
// a bare regexp match: Go's `\s` is five ASCII characters and JavaScript's also
// covers U+00A0 and the Unicode separators, so without the extra scan this route
// would provision for addresses the live app refuses.
func TestSetupEmailGateIsNoLooserThanJavaScript(t *testing.T) {
	valid := []string{"a@b.co", "ada.lovelace+tag@example.co.uk", "UPPER@Example.COM"}
	for _, v := range valid {
		if !setupValidEmail(v) {
			t.Errorf("setupValidEmail(%q) = false, want true", v)
		}
	}
	invalid := []string{
		"", "not-an-email", "a@b", "a@@b.co", "a b@c.co", "a@b .co",
		"a\u00a0b@c.co", // non-breaking space: JavaScript's \s, not Go's
		"a@b\u2003.co",  // em space
		"a@b.co\ufeff",  // zero-width no-break space
	}
	for _, v := range invalid {
		if setupValidEmail(v) {
			t.Errorf("setupValidEmail(%q) = true, want false", v)
		}
	}
}

// The 201 body is read by the onboarding page and by `solongate init`. The key
// order is the original's; the two keys are the only copies that will ever
// exist, which is what the warning says.
func TestSetupResponseShape(t *testing.T) {
	raw, err := json.Marshal(setupResponse{
		Project: setupProject{ID: "p", Name: "Demo", Slug: "demo-0011"},
		APIKeys: setupKeys{Live: "sg_live_x", Test: "sg_test_x"},
		Warning: setupKeyWarning,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"project":{"id":"p","name":"Demo","slug":"demo-0011"},` +
		`"api_keys":{"live":"sg_live_x","test":"sg_test_x"},` +
		`"_warning":"Store these API keys securely. They will not be shown again."}`
	if string(raw) != want {
		t.Errorf("body =\n%s\nwant\n%s", raw, want)
	}
}

// The slug is the live route's two replacements: everything outside [a-z0-9]
// collapses to one dash and a leading or trailing one goes. A name of nothing
// but punctuation slugs to the empty string, so the row is named by its random
// suffix alone — which is the live behaviour and is why the suffix exists.
func TestSetupSlugMatchesTheLiveDerivation(t *testing.T) {
	cases := map[string]string{
		"My New Project!": "my-new-project",
		"  spaced  out  ": "spaced-out",
		"Ünicode Name":    "nicode-name",
		"!!!":             "",
		"😀":               "",
		"already-a-slug":  "already-a-slug",
	}
	for in, want := range cases {
		if got := authSlugify(in); got != want {
			t.Errorf("authSlugify(%q) = %q, want %q", in, got, want)
		}
	}
}

// ── the database-backed half ────────────────────────────────────────────────

func setupPost(t *testing.T, srv *server, ip, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/setup", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	// A fresh IP per call: the limit is five a minute per address and the point
	// of these cases is the validation, not the limiter.
	req.Header.Set("X-Real-IP", ip)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	out := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, out
}

func TestSetupRefusesBeforeItProvisions(t *testing.T) {
	srv, _ := learnTestEnv(t)
	cases := []struct {
		name, body, message string
		status              int
	}{
		{"no fields", `{}`, "Missing required fields: email, project_name", 400},
		{"empty email", `{"email":"","project_name":"Demo"}`, "Missing required fields: email, project_name", 400},
		{"no project name", `{"email":"a@b.co"}`, "Missing required fields: email, project_name", 400},
		{"bad address", `{"email":"nope","project_name":"Demo"}`, "Invalid email format", 400},
		{"name too short", `{"email":"a@b.co","project_name":"D"}`, "Project name must be 2-50 characters", 400},
		{"name too long", `{"email":"a@b.co","project_name":"` + strings50plus + `"}`, "Project name must be 2-50 characters", 400},
		{"array name", `{"email":"a@b.co","project_name":["ab"]}`, "Project name must be 2-50 characters", 400},
		// A non-string name is a TypeError in the live route, which its catch
		// renders as handleApiError's 500. Never a provisioned project.
		{"boolean name", `{"email":"a@b.co","project_name":true}`, "An internal error occurred. Please try again later.", 500},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, body := setupPost(t, srv, "203.0.113."+string(rune('a'+i)), c.body)
			if code != c.status {
				t.Fatalf("status = %d, want %d (%v)", code, c.status, body)
			}
			e, _ := body["error"].(map[string]any)
			if e == nil || e["message"] != c.message {
				t.Errorf("error = %v, want %q", body["error"], c.message)
			}
			if _, provisioned := body["api_keys"]; provisioned {
				t.Error("a refused request returned API keys")
			}
		})
	}
}

const strings50plus = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD" // 51

// The whole endpoint, once: a user, a project, two keys, and a live key that
// authenticates for the project it was just minted for and nothing else.
func TestSetupProvisionsAndTheKeyWorks(t *testing.T) {
	srv, _ := learnTestEnv(t)

	code, body := setupPost(t, srv, "198.51.100.7",
		`{"email":"setup-test@example.invalid","project_name":"Setup Test Project","description":"from a test"}`)
	if code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (%v)", code, body)
	}
	project := body["project"].(map[string]any)
	keys := body["api_keys"].(map[string]any)
	projectID := project["id"].(string)
	t.Cleanup(func() {
		if err := srv.store.DeleteProjectCascade(context.Background(), projectID); err != nil {
			t.Errorf("cleanup: %v", err)
		}
		// The user row is left behind on purpose: /v1/setup reuses an existing
		// account by design, and the address is fixed so a re-run finds it rather
		// than accumulating rows.
	})

	if body["_warning"] == nil {
		t.Error("the response must carry the store-these-keys warning")
	}
	live, _ := keys["live"].(string)
	test, _ := keys["test"].(string)
	if len(live) != 56 || live[:8] != "sg_live_" || len(test) != 56 || test[:8] != "sg_test_" {
		t.Fatalf("keys = %v, want an sg_live_ and an sg_test_ key", keys)
	}

	// The key resolves to THIS project, which is the only thing that makes the
	// response useful and the only thing that would make it dangerous if wrong.
	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+live)
	info, err := srv.auth.Validate(context.Background(), req)
	if err != nil {
		t.Fatalf("the returned key does not authenticate: %v", err)
	}
	if info.ProjectID != projectID {
		t.Errorf("key resolves to project %s, want the one it was minted for (%s)", info.ProjectID, projectID)
	}

	// The plaintext is not recoverable: the row stores a hash and a prefix.
	stored, err := srv.store.ListAPIKeys(context.Background(), projectID)
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("stored %d keys, want the default live and test pair", len(stored))
	}
	for _, k := range stored {
		if k.KeyPrefix != live[:16] && k.KeyPrefix != test[:16] {
			t.Errorf("stored prefix %q belongs to neither returned key", k.KeyPrefix)
		}
	}
}

// The 409 branch: its query, not its HTTP path. A slug carries eight random hex
// characters, so a collision cannot be provoked from outside — which is also why
// the check is a courtesy rather than a lock.
func TestSetupSlugCollisionIsDetected(t *testing.T) {
	srv, key := learnTestEnv(t)
	ctx := context.Background()
	req := httptest.NewRequest("POST", "/api/v1/setup", nil)
	req.Header.Set("X-API-Key", key)
	info, err := srv.auth.Validate(ctx, req)
	if err != nil {
		t.Fatalf("the key in SOLONGATE_TEST_KEY does not authenticate: %v", err)
	}
	existing, err := srv.store.ProjectSummaryByID(ctx, info.ProjectID)
	if err != nil {
		t.Fatalf("ProjectSummaryByID: %v", err)
	}
	taken, err := srv.store.ProjectSlugTaken(ctx, existing.Slug)
	if err != nil {
		t.Fatalf("ProjectSlugTaken: %v", err)
	}
	if !taken {
		t.Errorf("ProjectSlugTaken(%q) = false for a slug that exists", existing.Slug)
	}
	free, err := srv.store.ProjectSlugTaken(ctx, existing.Slug+"-no-such-suffix")
	if err != nil {
		t.Fatalf("ProjectSlugTaken: %v", err)
	}
	if free {
		t.Error("ProjectSlugTaken reported a free slug as taken")
	}
}
