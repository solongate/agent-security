package api

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What this file used to test was an HTTP client: that a request carried the
// credential and landed on the right path, that empty query values were skipped,
// that a GET retried on a dropped socket and a mutation did not, that three
// different error envelopes decoded to one Error, and that no error message ever
// carried the key. Those five tests described the transport, and the transport is
// gone with the service. Everything below is about the FILE, which is where a
// policy lives now.

// newTestClient gives a client a machine of its own: an empty HOME and an empty
// working directory, so the only policy it can find is one the test wrote.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SOLONGATE_API_KEY", "")
	chdirTemp(t)
	return New()
}

// writePolicyFile puts a policy document on the machine the test is pretending to
// be. The CLI and the guard both read this file, so a test that seeds it is testing
// the real path rather than a shape invented for the test.
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

// A machine with no policy file has no policies and that is not an error. The old
// answer here was ErrNotAuthenticated — "not logged in" — for a machine that is
// simply new.
func TestNoPolicyFileIsEmptyNotAnError(t *testing.T) {
	c := newTestClient(t)

	list, err := c.Policies.List(context.Background())
	if err != nil {
		t.Fatalf("a missing policy file is not an error: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("policies = %d, want none", len(list))
	}

	ap, err := c.Policies.Active(context.Background(), "")
	if err != nil {
		t.Fatalf("Active on a bare machine: %v", err)
	}
	if ap.Policy != nil {
		t.Errorf("a bare machine resolved a policy: %+v", ap.Policy)
	}
}

// One malformed rule must not blank the whole policy. Reading none while the file
// holds three would make a read-modify-write SAVE that emptiness — and the guard,
// reading the same file, is still enforcing the rules the CLI just lost.
func TestOneBadRuleDoesNotBlankThePolicy(t *testing.T) {
	c := newTestClient(t)
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
	c := newTestClient(t)
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

// AN ENVELOPE WITH A NULL POLICY IS STILL AN ENVELOPE.
//
// `{"policy": null, "security": {...}}` says two things: no rules, and these layers.
// Deciding "envelope or bare document?" by whether the policy VALUE is usable threw
// the whole file away here and silently switched off the DLP it configured — while
// the JS guard, which decides on the presence of the key, honoured it. Same file,
// two behaviours, depending only on which binary a machine happens to have.
func TestNullPolicyInAnEnvelopeKeepsTheLayers(t *testing.T) {
	c := newTestClient(t)
	writePolicyFile(t, `{"policy":null,`+
		`"security":{"dlpBlock":{"patterns":["aws-access-key"]},"dlpRedact":{"patterns":["aws-access-key"]}},`+
		`"selfProtect":false}`)

	ap, err := c.Policies.Active(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if ap.Policy != nil {
		t.Errorf("a null policy resolved rules: %+v", ap.Policy)
	}
	if ap.Security == nil || ap.Security.DLPBlock == nil {
		t.Fatalf("the security block was thrown away with the null policy: %+v", ap.Security)
	}
	if len(ap.Security.DLPBlock.Patterns) != 1 || ap.Security.DLPBlock.Patterns[0] != "aws-access-key" {
		t.Errorf("patterns = %v, want the one the file names", ap.Security.DLPBlock.Patterns)
	}
	if ap.SelfProtectionEnabled {
		t.Error("selfProtect:false was not honoured")
	}
}

// A BARE POLICY DOCUMENT HAS NO `policy` KEY, and the two spellings must not be told
// apart by anything else. A document whose own id happens to be "policy" is still a
// bare document.
func TestABarePolicyDocumentIsNotReadAsAnEnvelope(t *testing.T) {
	c := newTestClient(t)
	writePolicyFile(t, `{"id":"policy","name":"P","mode":"denylist",
	  "rules":[{"id":"r1","effect":"DENY","toolPattern":"Bash","priority":1,"enabled":true}]}`)

	ap, err := c.Policies.Active(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if ap.Policy == nil {
		t.Fatal("a bare document resolved no policy")
	}
	if len(ap.Policy.Rules.Items) != 1 {
		t.Errorf("rules = %d, want the one in the file", len(ap.Policy.Rules.Items))
	}
	// Self-protection defaults ON for a bare document: it says nothing about layers,
	// and guessing the other way leaves a guard that can be edited out of the way.
	if !ap.SelfProtectionEnabled {
		t.Error("self-protection defaulted off for a bare document")
	}
}

// The CLI must read the file the GUARD reads. They are one machine's configuration,
// and a CLI that edits a different path than the one being enforced is worse than no
// CLI: it reports success and changes nothing.
func TestPolicyPathIsTheFileTheGuardReads(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	want := filepath.Join(".solongate", "policy.json")
	if got := PolicyPath(); !strings.HasSuffix(got, want) {
		t.Errorf("PolicyPath() = %q, want it to end in %q", got, want)
	}
}
