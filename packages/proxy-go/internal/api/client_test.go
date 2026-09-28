package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

const testKey = "sg_live_0123456789abcdef"

// newTestClient points a client at a stub server with a credential on disk, so
// the credential resolution the real client uses is exercised too rather than
// injected around.
func newTestClient(t *testing.T, h http.Handler) *Client {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SOLONGATE_API_KEY", "")
	t.Setenv("SOLONGATE_API_URL", "")
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	writeCredential(t, testKey, srv.URL)
	// A working directory with no .env, so the last credential source cannot
	// quietly supply a key the test did not put there.
	chdirTemp(t)
	return New()
}

func writeCredential(t *testing.T, key, url string) {
	t.Helper()
	b, err := json.Marshal(config.Credential{APIKey: key, APIURL: url})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.CredentialPath(), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// writePolicyFile puts a policy document on the machine the test is pretending
// to be. The CLI and the guard both read this file, so a test that seeds it is
// testing the real path rather than a shape invented for the test.
func writePolicyFile(t *testing.T, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(PolicyPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(PolicyPath(), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func chdirTemp(t *testing.T) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}

func TestRequestSendsCredentialAndPath(t *testing.T) {
	var gotAuth, gotPath, gotQuery, gotCT string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotCT = r.Header.Get("Content-Type")
		_, _ = w.Write([]byte(`{"policies":[]}`))
	}))

	// Do rather than a namespace: the namespaces read this machine now, and what
	// is under test here is the transport the MCP proxy still uses.
	var out struct{}
	if err := c.Do(context.Background(), http.MethodGet, "/policies", RequestOptions{}, &out); err != nil {
		t.Fatal(err)
	}
	if want := "Bearer " + testKey; gotAuth != want {
		t.Errorf("Authorization header did not carry the resolved key")
	}
	if gotPath != "/api/v1/policies" {
		t.Errorf("path = %q, want the v1 prefix", gotPath)
	}
	// A GET with no body must not claim to carry JSON.
	if gotCT != "" {
		t.Errorf("Content-Type on a bodyless GET = %q", gotCT)
	}
	if gotQuery != "" {
		t.Errorf("query = %q, want none", gotQuery)
	}
}

// Empty filters must be absent, not sent as "". An empty `tool=` is a filter
// the API still has to interpret.
func TestQuerySkipsEmptyValues(t *testing.T) {
	var got string
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"entries":[]}`))
	}))
	var out struct{}
	q := Query(map[string]any{
		"filter": "DENY", "limit": 20,
		"tool": "", "search": "", "signal": "", "offset": 0, "from": int64(0), "to": int64(0),
	})
	if err := c.Do(context.Background(), http.MethodGet, "/audit-logs", RequestOptions{Query: q}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "filter=DENY") || !strings.Contains(got, "limit=20") {
		t.Errorf("query = %q, want the set filters", got)
	}
	for _, absent := range []string{"tool=", "search=", "signal=", "offset=", "from=", "to="} {
		if strings.Contains(got, absent) {
			t.Errorf("query = %q, should not contain %q", got, absent)
		}
	}
}

// A transient failure on a GET is retried; a mutation is not, because a POST
// that arrived and whose response was lost would be sent twice.
func TestGetRetriesAndMutationDoesNot(t *testing.T) {
	var gets, posts int32
	drop := func(w http.ResponseWriter) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		if conn, _, err := hj.Hijack(); err == nil {
			_ = conn.Close()
		}
	}
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Closing without answering is the shape of a socket the OS or a
			// NAT dropped while the session was idle.
			if atomic.AddInt32(&gets, 1) < 3 {
				drop(w)
				return
			}
			_, _ = w.Write([]byte(`{"policies":[]}`))
			return
		}
		atomic.AddInt32(&posts, 1)
		drop(w)
	}))

	var out struct{}
	if err := c.Do(context.Background(), http.MethodGet, "/policies", RequestOptions{}, &out); err != nil {
		t.Fatalf("a GET should have survived two dropped connections: %v", err)
	}
	if gets != 3 {
		t.Errorf("GET attempts = %d, want 3", gets)
	}

	err := c.Do(context.Background(), http.MethodPost, "/policies/active",
		RequestOptions{Body: map[string]any{"policyId": "p1"}}, nil)
	if err == nil {
		t.Fatal("expected the mutation to fail rather than retry")
	}
	if posts != 1 {
		t.Errorf("POST attempts = %d, want exactly 1", posts)
	}
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Code != "NETWORK_ERROR" {
		t.Errorf("error = %#v, want a NETWORK_ERROR", err)
	}
}

func TestErrorEnvelopes(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantCode string
		wantMsg  string
	}{
		{"standard envelope", 400, `{"error":{"code":"BAD_INPUT","message":"toolPattern is required"}}`,
			"BAD_INPUT", "toolPattern is required"},
		{"bare string envelope", 400, `{"error":"policy not found"}`,
			"ERROR", "policy not found"},
		{"401 with no body", 401, ``,
			"AUTHENTICATION_ERROR", "Invalid API key. Run `solongate` and log in from the Accounts panel."},
		{"429 with no body", 429, ``,
			"RATE_LIMITED", "Rate limited by the API. Slow down and retry."},
		{"500 with no body", 500, ``,
			"SERVER_ERROR", "SolonGate API had a problem (server error). Please try again in a moment."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			var out struct{}
			err := c.Do(context.Background(), http.MethodGet, "/policies", RequestOptions{}, &out)
			var apiErr *Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("error = %#v, want *api.Error", err)
			}
			if apiErr.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", apiErr.Code, tc.wantCode)
			}
			if apiErr.Message != tc.wantMsg {
				t.Errorf("message = %q, want %q", apiErr.Message, tc.wantMsg)
			}
			if apiErr.Status != tc.status {
				t.Errorf("status = %d, want %d", apiErr.Status, tc.status)
			}
		})
	}
}

// Nothing this package produces may carry the key. A transport error carries
// the request URL, and a message quoting it is the most likely thing to end up
// in a support paste.
func TestErrorsNeverCarryTheKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SOLONGATE_API_KEY", "")
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Port 1 refuses immediately, which is the fastest way to a transport error.
	writeCredential(t, testKey, "http://127.0.0.1:1")
	chdirTemp(t)

	var out struct{}
	err := New().Do(context.Background(), http.MethodGet, "/policies", RequestOptions{}, &out)
	if err == nil {
		t.Fatal("expected a connection failure")
	}
	if strings.Contains(err.Error(), testKey) {
		t.Fatal("the API key leaked into an error message")
	}
}

// A missing credential has to be recognisable as such, not as a 401 from a
// request that was never worth sending.
func TestNoCredentialIsNotAuthenticated(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SOLONGATE_API_KEY", "")
	chdirTemp(t)

	c := New()
	if c.Authenticated() {
		t.Error("Authenticated() reported true with no key anywhere")
	}
	var out struct{}
	if err := c.Do(context.Background(), http.MethodGet, "/policies", RequestOptions{}, &out); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("error = %#v, want ErrNotAuthenticated", err)
	}
}

// One malformed rule must not blank the whole policy. Reading none while the file
// holds three would make a read-modify-write SAVE that emptiness — and the guard,
// reading the same file, is still enforcing the rules the CLI just lost.
func TestOneBadRuleDoesNotBlankThePolicy(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	writePolicyFile(t, `{"id":"p1","name":"P","mode":"denylist",
	  "rules":[
	    {"id":"r1","effect":"DENY","toolPattern":"Bash","priority":10,"enabled":true},
	    {"id":"r2","effect":"DENY","toolPattern":"Read","priority":"not-a-number"},
	    {"id":"r3","effect":"ALLOW","toolPattern":"*","priority":9999,"enabled":true}
	  ]}`)
	list, err := c.Policies.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("policies = %d", len(list))
	}
	rules := list[0].Rules
	if len(rules.Items) != 2 {
		t.Errorf("readable rules = %d, want the two that decode", len(rules.Items))
	}
	if rules.Unreadable != 1 {
		t.Errorf("unreadable = %d, want 1 so the caller can say so", rules.Unreadable)
	}
	if len(rules.Raw) != 3 {
		t.Errorf("raw rules = %d, want all three preserved", len(rules.Raw))
	}

	// The bytes survive a round trip, so a write-back does not drop the rule
	// this version could not read.
	out, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"r2"`) {
		t.Errorf("the unreadable rule was dropped on re-marshal: %s", out)
	}
}

// permission is a string on some rules and an array on others, and which one it
// is changes the Rego the API compiles. Reading it must not depend on guessing.
func TestPermissionReadsBothShapes(t *testing.T) {
	var one, many, none PolicyRule
	if err := json.Unmarshal([]byte(`{"permission":"READ"}`), &one); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"permission":["READ","WRITE"]}`), &many); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"id":"r"}`), &none); err != nil {
		t.Fatal(err)
	}
	if got := one.Permissions(); len(got) != 1 || got[0] != "READ" {
		t.Errorf("single permission = %v", got)
	}
	if got := many.Permissions(); len(got) != 2 || got[0] != "READ" || got[1] != "WRITE" {
		t.Errorf("permission list = %v", got)
	}
	if got := none.Permissions(); got != nil {
		t.Errorf("absent permission = %v, want nil", got)
	}
	// The raw bytes are kept verbatim so a write-back cannot turn a string into
	// a one-element array, which compiles to different Rego.
	if string(one.Permission) != `"READ"` {
		t.Errorf("raw permission = %s", one.Permission)
	}
}

// `security: null` in the active-policy response is an answer, and has to stay
// distinguishable from a field the API did not send.
// `"security": null` in the file is an ANSWER — this machine configures no layers
// — and every layer has to read as off rather than as some default.
func TestActivePolicyNullSecurity(t *testing.T) {
	c := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	writePolicyFile(t, `{"policy":{"id":"p1","name":"P","mode":"denylist","rules":[]},"security":null}`)
	ap, err := c.Policies.Active(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if ap.Security.RateLimit != nil || ap.Security.DLPBlock != nil || ap.Security.DLPRedact != nil {
		t.Errorf("a null security block enabled a layer: %+v", ap.Security)
	}
	// Self-protection defaults ON: a file that says nothing leaves it on, because
	// the failure mode of guessing wrong the other way is a guard that can be
	// edited out of the way.
	if !ap.SelfProtectionEnabled {
		t.Error("self-protection defaulted off for a file that said nothing")
	}
}
