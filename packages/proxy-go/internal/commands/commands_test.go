// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/proxy-go/internal/api"
	"github.com/solongate/agent-security/packages/proxy-go/internal/config"
)

// machine gives a command a machine of its own: an empty HOME, an empty working
// directory, and none of the environment a developer's shell carries.
//
// It was machine(t): it started an httptest server, wrote a credential
// naming it, and handed back a client pointed there — so a test could assert which
// route a command called and with what. There are no routes. Every caller now seeds the
// FILE a command reads (seedPolicy, seedAudit) and the handlers they used to pass are
// gone; the ones that asserted "nothing was PUT" could no longer fail, because nothing
// can send anything.
func machine(t *testing.T) *api.Client {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SOLONGATE_API_KEY", "")
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o700); err != nil {
		t.Fatal(err)
	}

	// A working directory with no .env and no policy file of its own, so nothing a
	// test did not put there can be found.
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	return api.New()
}

// seedPolicy writes the policy document on the machine the test is pretending to
// be. This is the file the CLI reads AND the file the guard reads, so a test that
// seeds it exercises the path that actually runs.
func seedPolicy(t *testing.T, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(api.PolicyPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(api.PolicyPath(), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// seedAuditLog writes lines in the shape the hooks append, newest LAST, so the
// ids a test refers to are the line numbers the CLI will report.
func seedAuditLog(t *testing.T, lines ...string) {
	t.Helper()
	dir := config.LocalLogsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "solongate-audit.jsonl"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// readPolicyFile is the whole file, verbatim. A command that fails must leave it
// byte for byte as it was: a read-modify-write that half-succeeded is how a policy
// loses rules, and the guard reads this file on every tool call.
func readPolicyFile(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(api.PolicyPath())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// jsonHandler stood here: it turned a map of route → body into an http.Handler, so a
// test could say what the service would answer with. Nothing answers anything.

func TestPolicyListJSONPutsNothingButJSONOnStdout(t *testing.T) {
	c := machine(t)
	seedPolicy(t, `{"id":"pol-1","name":"Default","mode":"denylist","rules":[]}`)

	o, e := capture(t, func() {
		code, err := runPolicy(context.Background(), c, parse([]string{"list", "--json"}))
		if err != nil || code != 0 {
			t.Fatalf("policy list --json: code=%d err=%v", code, err)
		}
	})
	if e != "" {
		t.Fatalf("--json must leave stderr empty for a successful read, got %q", e)
	}
	var back []map[string]any
	if err := json.Unmarshal([]byte(o), &back); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, o)
	}
	if len(back) != 1 || back[0]["id"] != "pol-1" {
		t.Fatalf("unexpected document: %s", o)
	}
}

func TestPolicyListHumanOutputStaysOffStdout(t *testing.T) {
	c := machine(t)
	seedPolicy(t, `{"id":"pol-1","name":"Default","mode":"whitelist","rules":[
	  {"id":"r1","effect":"DENY","toolPattern":"Bash","priority":10,"enabled":true},
	  {"id":"r2","effect":"DENY","toolPattern":"Read","priority":11,"enabled":true},
	  {"id":"r3","effect":"DENY","toolPattern":"Write","priority":12,"enabled":true}
	]}`)
	o, e := capture(t, func() {
		if code, err := runPolicy(context.Background(), c, parse([]string{"list"})); err != nil || code != 0 {
			t.Fatalf("policy list: code=%d err=%v", code, err)
		}
	})
	if o != "" {
		t.Fatalf("the human table belongs on stderr, stdout got %q", o)
	}
	plain := ansi.ReplaceAllString(e, "")
	if !strings.Contains(plain, "pol-1") || !strings.Contains(plain, "whitelist") {
		t.Fatalf("table is missing content: %q", plain)
	}
	// The rule count comes from the array in the FILE, not from the rules this
	// version managed to decode.
	if !strings.Contains(plain, " 3 ") {
		t.Fatalf("rule count not rendered: %q", plain)
	}
}

func TestRateLimitSetKeepsTheWindowsItWasNotGiven(t *testing.T) {
	c := machine(t)
	// The layers as the GUARD reads them: a redact-mode DLP config is `dlpRedact`
	// with no `dlpBlock`, and a block-mode rate limit is `rateLimit`.
	seedPolicy(t, `{"policy":{"id":"p1","name":"P","mode":"denylist","rules":[]},
	  "security":{
	    "rateLimit":{"perMinute":10,"perHour":100,"perDay":1000},
	    "dlpRedact":{"patterns":["AWS access key"],"custom":[]}
	  }}`)

	if _, e := capture(t, func() {
		if code, err := runRateLimit(context.Background(), c, parse([]string{"set", "--minute", "25"})); err != nil || code != 0 {
			t.Fatalf("ratelimit set: code=%d err=%v", code, err)
		}
	}); e == "" {
		t.Fatal("the confirmation line is missing")
	}

	got, err := c.Settings.GetSecurityLayers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Layers.RateLimit.PerMinute != 25 {
		t.Fatalf("perMinute not applied: %d", got.Layers.RateLimit.PerMinute)
	}
	// The write REPLACES the layers document. Sending only the rate limit would
	// switch DLP off on the way past, and the guard reads the same file.
	if got.Layers.RateLimit.PerHour != 100 || got.Layers.RateLimit.PerDay != 1000 {
		t.Fatalf("untouched windows were reset: %+v", got.Layers.RateLimit)
	}
	if got.Layers.DLP.Mode != api.LayerRedact || len(got.Layers.DLP.Patterns) != 1 {
		t.Fatalf("editing the rate limit disarmed DLP: %+v", got.Layers.DLP)
	}
}

// A TYPO MUST NOT BECOME A LIMIT OF ZERO, and the file must be untouched.
//
// This used to stub a PUT route and assert nothing was sent to it. Nothing can be
// sent, so that assertion could not fail — and the thing it stood for is now
// checkable directly: the policy file before and the policy file after.
func TestRateLimitSetRefusesAnUnparseableNumber(t *testing.T) {
	c := machine(t)
	seedPolicy(t, `{"policy":{"id":"p1","name":"P","mode":"denylist","rules":[]},`+
		`"security":{"rateLimit":{"perMinute":10,"perHour":100,"perDay":1000}}}`)
	before := readPolicyFile(t)

	_, e := capture(t, func() {
		code, err := runRateLimit(context.Background(), c, parse([]string{"set", "--minute", "oops"}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if code != 1 {
			t.Fatalf("a typo has to fail loudly, got exit %d", code)
		}
	})
	if got := readPolicyFile(t); got != before {
		t.Fatalf("the file was rewritten by a command that failed:\n have %s\n want %s", got, before)
	}
	if !strings.Contains(e, "Usage:") {
		t.Fatalf("want the usage line, got %q", e)
	}
}

// A PATTERN NAME THE GUARD CANNOT LOOK UP MUST NOT BE SAVED.
//
// The names are matched exactly by every implementation, so `AWS Access Key` enables
// nothing: it would sit in the policy file looking enabled and protect nothing. The
// list to check against used to arrive from a service as `availablePatterns`, which
// this test stubbed; it is the built-in list now (see dlppatterns.go and
// src/dlp-patterns.ts, held in step by test/dlp-parity.mjs), so the stub is gone and
// the real list is what refuses.
func TestDLPRefusesAPatternTheGuardCannotLookUp(t *testing.T) {
	c := machine(t)
	seedPolicy(t, `{"policy":{"id":"p1","name":"P","mode":"denylist","rules":[]},`+
		`"security":{"dlpBlock":{"patterns":[],"custom":[]}}}`)
	before := readPolicyFile(t)

	_, e := capture(t, func() {
		code, _ := runDLP(context.Background(), c, parse([]string{"enable", "AWS Access Key"}))
		if code != 1 {
			t.Fatalf("an unknown pattern must fail, got %d", code)
		}
	})
	if got := readPolicyFile(t); got != before {
		t.Fatalf("a pattern the guard cannot look up was written anyway:\n have %s\n want %s", got, before)
	}
	if !strings.Contains(e, "AWS access key") {
		t.Fatalf("the available list has to be shown, got %q", e)
	}
}

func TestAuditWhitelistDefaultsToTheNarrowScope(t *testing.T) {
	c := machine(t)
	seedPolicy(t, `{"id":"pol-1","name":"P","mode":"denylist","rules":[]}`)
	// An entry's id is its LINE NUMBER, which is what makes this work against a
	// file: the log is append-only, so line 1 stays line 1.
	seedAuditLog(t,
		`{"ts":"2026-01-01T00:00:00.000Z","tool":"Bash","decision":"DENY","reason":"Blocked by policy","arguments":{"command":"rm -rf /tmp/x"}}`)

	_, e := capture(t, func() {
		if code, err := runAudit(context.Background(), c, parse([]string{"whitelist", "1"})); err != nil || code != 0 {
			t.Fatalf("audit whitelist: code=%d err=%v", code, err)
		}
	})

	// A whitelist that widened to the whole tool by default would be a very
	// quiet way to disarm a policy. So the rule it wrote has to name the COMMAND
	// that entry carried, not just its tool.
	got, err := c.Policies.Get(context.Background(), "local", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules.Items) != 1 {
		t.Fatalf("rules written = %d, want 1", len(got.Rules.Items))
	}
	rule := got.Rules.Items[0]
	if rule.Effect != "ALLOW" || rule.ToolPattern != "Bash" {
		t.Fatalf("rule is not an ALLOW on that tool: %+v", rule)
	}
	if rule.CommandConstraints == nil || len(rule.CommandConstraints.Allowed) != 1 ||
		rule.CommandConstraints.Allowed[0] != "rm -rf /tmp/x" {
		t.Fatalf("the default scope widened past that call: %+v", rule.CommandConstraints)
	}
	if !strings.Contains(ansi.ReplaceAllString(e, ""), "pol-1") {
		t.Fatalf("the resulting policy is part of the confirmation: %q", e)
	}
}

func TestUnknownCommandIsNotSilent(t *testing.T) {
	_, e := capture(t, func() {
		if code := Run("nonesuch", nil); code != 1 {
			t.Fatalf("want exit 1, got %d", code)
		}
	})
	if !strings.Contains(e, "Unknown command: nonesuch") {
		t.Fatalf("got %q", e)
	}
}

// The SUBcommand equivalent of the test above, which only covered the top
// level. A mistyped subcommand used to print the usage block and nothing else,
// which reads as though the command has no default rather than as an error.
//
// `dlp -g` is the shape that made it obvious: parse() treats only `--x` as a
// flag, so a single-dash token arrives as a subcommand and gets here.
func TestUnknownSubcommandNamesWhatWasTyped(t *testing.T) {
	for _, tc := range []struct{ command, sub string }{
		{"dlp", "-g"},
		{"policy", "activat"},
		{"ratelimit", "nonesuch"},
		{"stats", "nonesuch"},
		{"alerts", "nonesuch"},
		{"webhooks", "nonesuch"},
	} {
		t.Run(tc.command+" "+tc.sub, func(t *testing.T) {
			_, e := capture(t, func() {
				if code, _ := unknownSub(tc.command, tc.sub, "USAGE-BLOCK"); code != 1 {
					t.Fatalf("want exit 1, got %d", code)
				}
			})
			if !strings.Contains(e, tc.sub) {
				t.Errorf("the refusal does not name what was typed: %q", e)
			}
			if !strings.Contains(e, tc.command) {
				t.Errorf("the refusal does not name the command: %q", e)
			}
			if !strings.Contains(e, "USAGE-BLOCK") {
				t.Errorf("the usage block is gone: %q", e)
			}
		})
	}
}

// A command invoked with only a flag has no token to name, and a line reading
// `Unknown subcommand: ""` would be worse than none.
func TestUnknownSubcommandWithNothingTypedJustShowsUsage(t *testing.T) {
	_, e := capture(t, func() {
		if code, _ := unknownSub("dlp", "", "USAGE-BLOCK"); code != 1 {
			t.Fatalf("want exit 1, got %d", code)
		}
	})
	if strings.Contains(e, "Unknown") {
		t.Errorf("named a subcommand that was never typed: %q", e)
	}
	if !strings.Contains(e, "USAGE-BLOCK") {
		t.Errorf("the usage block is gone: %q", e)
	}
}

func TestNamesAndHandlersAgree(t *testing.T) {
	h := handlers()
	for _, n := range Names {
		if _, ok := h[n]; !ok {
			t.Fatalf("%q is advertised but not wired", n)
		}
	}
	if len(h) != len(Names) {
		t.Fatalf("%d handlers for %d advertised names", len(h), len(Names))
	}
}

// A permission the guard has no name for would be stored, never match, and
// leave a rule that reads correctly in `policy show` and enforces nothing. So a
// typo is refused rather than dropped.
func TestPolicyPermissionFlagRefusesWhatTheGuardCannotMatch(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
		bad  string
	}{
		{in: "READ", want: []string{"READ"}},
		{in: "read,write", want: []string{"READ", "WRITE"}},
		{in: " Execute , NETWORK ", want: []string{"EXECUTE", "NETWORK"}},
		{in: "READ,READ", want: []string{"READ"}},
		{in: "", want: nil},
		{in: "READ,ADMIN", bad: "ADMIN"},
		{in: "reed", bad: "reed"},
	} {
		got, bad := parsePermissions(tc.in)
		if bad != tc.bad {
			t.Errorf("parsePermissions(%q) bad = %q, want %q", tc.in, bad, tc.bad)
			continue
		}
		if tc.bad != "" {
			if got != nil {
				t.Errorf("parsePermissions(%q) returned %v alongside a refusal", tc.in, got)
			}
			continue
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("parsePermissions(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
