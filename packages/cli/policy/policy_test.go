// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !windows

package policy

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
)

// newHome isolates the local-file client store behind a throwaway $HOME so
// tests never touch the real machine's SolonGate state.
func newHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

// captureOutput redirects the process's real stdout and stderr file
// descriptors for the duration of fn and returns everything written to
// either. cliutil.Out/Errln/Table/PrintJSON write through unexported
// io.Writer values that were bound to os.Stdout/os.Stderr at package init,
// so merely reassigning those variables would not intercept the writes; the
// underlying fds must be swapped instead.
func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	outFd := int(os.Stdout.Fd())
	errFd := int(os.Stderr.Fd())
	origOut, err := syscall.Dup(outFd)
	if err != nil {
		t.Fatal(err)
	}
	origErr, err := syscall.Dup(errFd)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup2(int(w.Fd()), outFd); err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup2(int(w.Fd()), errFd); err != nil {
		t.Fatal(err)
	}

	fn()

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup2(origOut, outFd); err != nil {
		t.Fatal(err)
	}
	if err := unix.Dup2(origErr, errFd); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Close(origOut); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Close(origErr); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func ruleID(t *testing.T, raw string) string {
	t.Helper()
	var m client.RuleMutation
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("decoding RuleMutation JSON %q: %v", raw, err)
	}
	if m.Rule == nil {
		t.Fatalf("RuleMutation has no rule: %s", raw)
	}
	return m.Rule.ID
}

func TestPolicyUsage(t *testing.T) {
	u := policyUsage()
	for _, want := range []string{"solongate policy", "--permission", "policy list", "policy protect"} {
		if !strings.Contains(u, want) {
			t.Errorf("policyUsage() missing %q:\n%s", want, u)
		}
	}
}

func TestParsePermissions(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantPerms []string
		wantBad   string
	}{
		{"empty", "", nil, ""},
		{"single", "read", []string{"READ"}, ""},
		{"several mixed case and whitespace", "Read, WRITE , execute", []string{"READ", "WRITE", "EXECUTE"}, ""},
		{"duplicates deduped", "read,READ, Read", []string{"READ"}, ""},
		{"invalid token", "read,bogus", nil, "bogus"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			perms, bad := parsePermissions(tc.raw)
			if bad != tc.wantBad {
				t.Errorf("bad = %q, want %q", bad, tc.wantBad)
			}
			if len(perms) != len(tc.wantPerms) {
				t.Fatalf("perms = %v, want %v", perms, tc.wantPerms)
			}
			for i := range perms {
				if perms[i] != tc.wantPerms[i] {
					t.Errorf("perms[%d] = %q, want %q", i, perms[i], tc.wantPerms[i])
				}
			}
		})
	}
}

func TestRunEmptyAndHelp(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	out := captureOutput(t, func() {
		code, err := Run(ctx, c, cliutil.Parse(nil))
		if code != 1 || err != nil {
			t.Errorf("Run(empty) = (%d, %v), want (1, nil)", code, err)
		}
	})
	if !strings.Contains(out, "solongate policy") {
		t.Errorf("empty sub did not print usage:\n%s", out)
	}

	out = captureOutput(t, func() {
		code, err := Run(ctx, c, cliutil.Parse([]string{"help"}))
		if code != 0 || err != nil {
			t.Errorf("Run(help) = (%d, %v), want (0, nil)", code, err)
		}
	})
	if !strings.Contains(out, "solongate policy") {
		t.Errorf("help did not print usage:\n%s", out)
	}
}

func TestRunUnknownSub(t *testing.T) {
	newHome(t)
	c := client.New()
	out := captureOutput(t, func() {
		code, err := Run(context.Background(), c, cliutil.Parse([]string{"bogus-sub"}))
		if code != 1 || err != nil {
			t.Errorf("Run(bogus) = (%d, %v), want (1, nil)", code, err)
		}
	})
	if !strings.Contains(out, "Unknown policy subcommand") || !strings.Contains(out, "bogus-sub") {
		t.Errorf("unexpected unknown-sub output:\n%s", out)
	}
}

func TestRunProtectDelegation(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	viaRun := captureOutput(t, func() {
		code, err := Run(ctx, c, cliutil.Parse([]string{"protect", "help"}))
		if code != 0 || err != nil {
			t.Errorf("Run(protect help) = (%d, %v), want (0, nil)", code, err)
		}
	})
	direct := captureOutput(t, func() {
		code, err := runProtect(ctx, c, cliutil.Parse([]string{"help"}))
		if code != 0 || err != nil {
			t.Errorf("runProtect(help) = (%d, %v), want (0, nil)", code, err)
		}
	})
	if viaRun != direct {
		t.Errorf("Run(\"protect\", ...) did not delegate to runProtect:\nviaRun=%q\ndirect=%q", viaRun, direct)
	}
}

// TestRunPolicyLifecycle walks one policy through its whole life against a
// single isolated local store, mirroring how a user would actually drive the
// CLI: this local store holds exactly one policy, so create can only succeed
// once per store and delete removes it for good.
func TestRunPolicyLifecycle(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	run := func(args ...string) (int, error, string) {
		var code int
		var err error
		out := captureOutput(t, func() { code, err = Run(ctx, c, cliutil.Parse(args)) })
		return code, err, out
	}

	t.Run("active before any policy exists", func(t *testing.T) {
		code, err, out := run("active")
		if code != 0 || err != nil {
			t.Fatalf("active = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, "No active policy resolves") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("list when empty", func(t *testing.T) {
		code, err, out := run("list")
		if code != 0 || err != nil {
			t.Fatalf("list = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, "No policies") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("list when empty json", func(t *testing.T) {
		code, err, out := run("list", "--json")
		if code != 0 || err != nil {
			t.Fatalf("list --json = (%d, %v), want (0, nil)", code, err)
		}
		if strings.TrimSpace(out) != "[]" {
			t.Errorf("list --json = %q, want []", out)
		}
	})

	t.Run("show before create", func(t *testing.T) {
		code, err, _ := run("show", "anything")
		if code != 1 || err == nil {
			t.Fatalf("show(before create) = (%d, %v), want (1, non-nil)", code, err)
		}
	})

	t.Run("create with no name", func(t *testing.T) {
		code, err, out := run("create")
		if code != 1 || err != nil {
			t.Fatalf("create() = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: policy create") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	orig := nowMillis
	nowMillis = func() int64 { return 1234567890 }
	t.Cleanup(func() { nowMillis = orig })

	var id string
	t.Run("create a policy", func(t *testing.T) {
		code, err, out := run("create", "My Policy")
		if code != 0 || err != nil {
			t.Fatalf("create = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, "policy-1234567890") {
			t.Errorf("unexpected output:\n%s", out)
		}
		id = "policy-1234567890"
	})

	t.Run("list after create", func(t *testing.T) {
		code, err, out := run("list")
		if code != 0 || err != nil {
			t.Fatalf("list = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, "My Policy") || !strings.Contains(out, id) {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("list after create json", func(t *testing.T) {
		code, err, out := run("list", "--json")
		if code != 0 || err != nil {
			t.Fatalf("list --json = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, id) || !strings.Contains(out, "My Policy") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("show missing id after create", func(t *testing.T) {
		code, err, _ := run("show", "not-the-real-id")
		if code != 1 || err == nil {
			t.Fatalf("show(bogus) = (%d, %v), want (1, non-nil)", code, err)
		}
	})

	t.Run("show real id", func(t *testing.T) {
		code, err, out := run("show", id)
		if code != 0 || err != nil {
			t.Fatalf("show = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, "My Policy") || !strings.Contains(out, "rules: 0") || !strings.Contains(out, "(no rules)") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("show real id json", func(t *testing.T) {
		code, err, out := run("show", id, "--json")
		if code != 0 || err != nil {
			t.Fatalf("show --json = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, id) {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("mode bad args", func(t *testing.T) {
		code, err, out := run("mode", id, "bogus-mode")
		if code != 1 || err != nil {
			t.Fatalf("mode(bogus) = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: policy mode") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("mode whitelist with zero rules warns", func(t *testing.T) {
		code, err, out := run("mode", id, "whitelist")
		if code != 0 || err != nil {
			t.Fatalf("mode(whitelist) = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, "whitelist") {
			t.Errorf("unexpected output:\n%s", out)
		}
		if !strings.Contains(out, "no ALLOW rules") {
			t.Errorf("expected the zero-rules warning:\n%s", out)
		}
	})

	t.Run("mode denylist", func(t *testing.T) {
		code, err, out := run("mode", id, "denylist")
		if code != 0 || err != nil {
			t.Fatalf("mode(denylist) = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, "denylist") {
			t.Errorf("unexpected output:\n%s", out)
		}
		if strings.Contains(out, "no ALLOW rules") {
			t.Errorf("denylist should not warn about missing ALLOW rules:\n%s", out)
		}
	})

	t.Run("rule bad args", func(t *testing.T) {
		code, err, out := run("rule", id, "r1", "bogus-action")
		if code != 1 || err != nil {
			t.Fatalf("rule(bogus) = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: policy rule") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("rule nonexistent with zero rules", func(t *testing.T) {
		code, err, out := run("rule", id, "no-such-rule", "enable")
		if code != 1 || err != nil {
			t.Fatalf("rule(missing) = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, `No rule "no-such-rule"`) {
			t.Errorf("unexpected output:\n%s", out)
		}
		if strings.Contains(out, "Rules in this policy") {
			t.Errorf("should not list rules when there are none:\n%s", out)
		}
	})

	t.Run("allow with no id", func(t *testing.T) {
		code, err, out := run("allow")
		if code != 1 || err != nil {
			t.Fatalf("allow() = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: policy allow") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("deny with no id", func(t *testing.T) {
		code, err, out := run("deny")
		if code != 1 || err != nil {
			t.Fatalf("deny() = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: policy deny") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("allow with invalid permission", func(t *testing.T) {
		code, err, out := run("allow", id, "--permission", "bogus")
		if code != 1 || err != nil {
			t.Fatalf("allow(bad perm) = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, `Unknown permission "bogus"`) {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	var cmdRuleID, pathRuleID, filenameRuleID, urlRuleID, permRuleID string

	t.Run("allow --command", func(t *testing.T) {
		code, err, out := run("allow", id, "--command", "rm -rf /", "--json")
		if code != 0 || err != nil {
			t.Fatalf("allow(--command) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		cmdRuleID = ruleID(t, out)
	})

	t.Run("deny --path", func(t *testing.T) {
		code, err, out := run("deny", id, "--path", "/etc/shadow", "--json")
		if code != 0 || err != nil {
			t.Fatalf("deny(--path) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		pathRuleID = ruleID(t, out)
	})

	t.Run("allow --filename", func(t *testing.T) {
		code, err, out := run("allow", id, "--filename", "secrets.env", "--json")
		if code != 0 || err != nil {
			t.Fatalf("allow(--filename) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		filenameRuleID = ruleID(t, out)
	})

	t.Run("allow --url", func(t *testing.T) {
		code, err, out := run("allow", id, "--url", "https://example.com", "--json")
		if code != 0 || err != nil {
			t.Fatalf("allow(--url) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		urlRuleID = ruleID(t, out)
	})

	t.Run("allow --permission", func(t *testing.T) {
		code, err, out := run("allow", id, "--permission", "Read, WRITE , execute", "--json")
		if code != 0 || err != nil {
			t.Fatalf("allow(--permission) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		permRuleID = ruleID(t, out)
	})

	t.Run("ids are all distinct", func(t *testing.T) {
		seen := map[string]bool{}
		for _, rid := range []string{cmdRuleID, pathRuleID, filenameRuleID, urlRuleID, permRuleID} {
			if rid == "" {
				t.Fatalf("got an empty rule id")
			}
			if seen[rid] {
				t.Fatalf("rule id %q was reused", rid)
			}
			seen[rid] = true
		}
	})

	t.Run("show renders every rule kind", func(t *testing.T) {
		code, err, out := run("show", id)
		if code != 0 || err != nil {
			t.Fatalf("show = (%d, %v), want (0, nil)", code, err)
		}
		for _, want := range []string{"command", "path", "filename", "url", "rm -rf /", "/etc/shadow", "secrets.env", "example.com", "EXECUTE+READ+WRITE"} {
			if !strings.Contains(out, want) {
				t.Errorf("show output missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("rule nonexistent with some rules present lists them", func(t *testing.T) {
		code, err, out := run("rule", id, "no-such-rule", "enable")
		if code != 1 || err != nil {
			t.Fatalf("rule(missing) = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Rules in this policy") || !strings.Contains(out, cmdRuleID) {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("rule enable round trip", func(t *testing.T) {
		code, err, out := run("rule", id, cmdRuleID, "enable")
		if code != 0 || err != nil {
			t.Fatalf("rule enable = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, cmdRuleID) || !strings.Contains(out, "enabled") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("rule disable round trip", func(t *testing.T) {
		code, err, out := run("rule", id, cmdRuleID, "disable")
		if code != 0 || err != nil {
			t.Fatalf("rule disable = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, cmdRuleID) || !strings.Contains(out, "disabled") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("revoke bad args", func(t *testing.T) {
		code, err, out := run("revoke", id)
		if code != 1 || err != nil {
			t.Fatalf("revoke() = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: policy revoke") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("revoke add-then-revoke round trip", func(t *testing.T) {
		_, _, addOut := run("allow", id, "--command", "revoke-me", "--json")
		rid := ruleID(t, addOut)

		code, err, out := run("revoke", id, rid)
		if code != 0 || err != nil {
			t.Fatalf("revoke = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, rid) {
			t.Errorf("unexpected output:\n%s", out)
		}

		_, _, showOut := run("show", id)
		if strings.Contains(showOut, "revoke-me") {
			t.Errorf("revoked rule still shows up:\n%s", showOut)
		}
	})

	t.Run("activate with no id", func(t *testing.T) {
		code, err, out := run("activate")
		if code != 1 || err != nil {
			t.Fatalf("activate() = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: policy activate") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("activate a real id", func(t *testing.T) {
		code, err, out := run("activate", id)
		if code != 0 || err != nil {
			t.Fatalf("activate(%s) = (%d, %v), want (0, nil)", id, code, err)
		}
		if !strings.Contains(out, "Enforcing "+id) {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("activate --off", func(t *testing.T) {
		// This local store has no separate "active" pointer: SetActive
		// treats an empty policy id as nothing to switch off, always.
		code, err, _ := run("activate", "--off")
		if code != 1 || err == nil {
			t.Fatalf("activate(--off) = (%d, %v), want (1, non-nil)", code, err)
		}
		if !strings.Contains(err.Error(), "nothing to switch off") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("active after create resolves without an explicit activate", func(t *testing.T) {
		code, err, out := run("active")
		if code != 0 || err != nil {
			t.Fatalf("active = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, "Active: My Policy") || !strings.Contains(out, id) {
			t.Errorf("unexpected output:\n%s", out)
		}
		if strings.Contains(out, "rate limit:") || strings.Contains(out, "DLP block:") {
			t.Errorf("no security layers were configured, so these detail lines should not print:\n%s", out)
		}
	})

	t.Run("active json", func(t *testing.T) {
		code, err, out := run("active", "--json")
		if code != 0 || err != nil {
			t.Fatalf("active --json = (%d, %v), want (0, nil)", code, err)
		}
		if !strings.Contains(out, id) {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("delete with no id", func(t *testing.T) {
		code, err, out := run("delete")
		if code != 1 || err != nil {
			t.Fatalf("delete() = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: policy delete") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("delete a real id", func(t *testing.T) {
		code, err, out := run("delete", id)
		if code != 0 || err != nil {
			t.Fatalf("delete(%s) = (%d, %v), want (0, nil)", id, code, err)
		}
		if !strings.Contains(out, "Deleted "+id) {
			t.Errorf("unexpected output:\n%s", out)
		}

		_, _, listOut := run("list")
		if !strings.Contains(listOut, "No policies") {
			t.Errorf("policy still listed after delete:\n%s", listOut)
		}
	})

	t.Run("delete a stale id is not idempotent on an empty store", func(t *testing.T) {
		// The local store holds at most one policy; once it is gone there is
		// nothing left to resolve an id against, so a second delete errors
		// rather than quietly succeeding.
		code, err, _ := run("delete", id)
		if code != 1 || err == nil {
			t.Fatalf("delete(stale) = (%d, %v), want (1, non-nil)", code, err)
		}
	})
}

func TestPermScope(t *testing.T) {
	t.Run("no permissions falls back to any", func(t *testing.T) {
		got := permScope(client.PolicyRule{})
		want := cliutil.Dim("any")
		if got != want {
			t.Errorf("permScope() = %q, want %q", got, want)
		}
	})

	t.Run("permissions are sorted and joined", func(t *testing.T) {
		raw, err := json.Marshal([]string{"WRITE", "READ"})
		if err != nil {
			t.Fatal(err)
		}
		got := permScope(client.PolicyRule{Permission: raw})
		want := "READ+WRITE"
		if got != want {
			t.Errorf("permScope() = %q, want %q", got, want)
		}
	})
}

func TestPrintRules(t *testing.T) {
	t.Run("zero rules", func(t *testing.T) {
		out := captureOutput(t, func() { printRules(client.Rules{}) })
		if !strings.Contains(out, "(no rules)") {
			t.Errorf("unexpected output:\n%s", out)
		}
	})

	t.Run("rules and an unreadable footer", func(t *testing.T) {
		rules := client.Rules{
			Items: []client.PolicyRule{
				{ID: "rule-1", Effect: "ALLOW", Priority: 5, ToolPattern: "bash", Description: "let it run"},
				{ID: "rule-2", Effect: "DENY", Priority: 10, ToolPattern: "*"},
			},
			Unreadable: 2,
		}
		out := captureOutput(t, func() { printRules(rules) })
		for _, want := range []string{"EFFECT", "PRIO", "ID", "ON", "PERM", "PATTERN", "DESCRIPTION",
			"rule-1", "rule-2", "ALLOW", "DENY", "let it run", "-",
			"2 rule(s) this version cannot read"} {
			if !strings.Contains(out, want) {
				t.Errorf("missing %q in output:\n%s", want, out)
			}
		}
	})
}

func TestRulesCount(t *testing.T) {
	t.Run("items only", func(t *testing.T) {
		got := rulesCount(client.Rules{Items: []client.PolicyRule{{}, {}}})
		if got != 2 {
			t.Errorf("rulesCount() = %d, want 2", got)
		}
	})

	t.Run("raw takes precedence over items", func(t *testing.T) {
		r := client.Rules{
			Raw:   []json.RawMessage{json.RawMessage(`{}`), json.RawMessage(`{}`), json.RawMessage(`{}`)},
			Items: []client.PolicyRule{{}},
		}
		got := rulesCount(r)
		if got != 3 {
			t.Errorf("rulesCount() = %d, want 3 (len(Raw), not len(Items))", got)
		}
	})
}

func TestSetRuleEnabled(t *testing.T) {
	base := func() client.PolicySet {
		return client.PolicySet{
			Rules: client.Rules{Raw: []json.RawMessage{
				json.RawMessage(`{"id":"rule-1","enabled":true}`),
				json.RawMessage(`not valid json`),
				json.RawMessage(`{"id":"rule-2","enabled":false}`),
			}},
		}
	}

	t.Run("found and disabled", func(t *testing.T) {
		next, found := setRuleEnabled(base(), "rule-1", false)
		if !found {
			t.Fatal("expected found = true")
		}
		if !strings.Contains(string(next.Rules.Raw[0]), `"enabled":false`) {
			t.Errorf("rule-1 was not disabled: %s", next.Rules.Raw[0])
		}
	})

	t.Run("found and enabled", func(t *testing.T) {
		next, found := setRuleEnabled(base(), "rule-2", true)
		if !found {
			t.Fatal("expected found = true")
		}
		if !strings.Contains(string(next.Rules.Raw[2]), `"enabled":true`) {
			t.Errorf("rule-2 was not enabled: %s", next.Rules.Raw[2])
		}
	})

	t.Run("not found leaves pol unchanged", func(t *testing.T) {
		pol := base()
		next, found := setRuleEnabled(pol, "no-such-rule", true)
		if found {
			t.Fatal("expected found = false")
		}
		for i := range pol.Rules.Raw {
			if string(pol.Rules.Raw[i]) != string(next.Rules.Raw[i]) {
				t.Errorf("raw[%d] changed: %s -> %s", i, pol.Rules.Raw[i], next.Rules.Raw[i])
			}
		}
	})

	t.Run("an unreadable entry is skipped, not matched", func(t *testing.T) {
		pol := client.PolicySet{Rules: client.Rules{Raw: []json.RawMessage{json.RawMessage(`not valid json`)}}}
		_, found := setRuleEnabled(pol, "", true)
		if found {
			t.Fatal("an unreadable raw entry must never be treated as a match")
		}
	})
}

func TestMustJSON(t *testing.T) {
	t.Run("normal value", func(t *testing.T) {
		got := mustJSON(map[string]int{"a": 1})
		if string(got) != `{"a":1}` {
			t.Errorf("mustJSON() = %s, want {\"a\":1}", got)
		}
	})

	t.Run("unencodable value falls back to empty object", func(t *testing.T) {
		got := mustJSON(make(chan int))
		if string(got) != "{}" {
			t.Errorf("mustJSON() = %s, want {}", got)
		}
	})
}

func TestRuleMatch(t *testing.T) {
	tests := []struct {
		name        string
		rule        client.PolicyRule
		wantKind    string
		wantPattern string
	}{
		{
			name:        "command denied",
			rule:        client.PolicyRule{CommandConstraints: &client.Constraint{Denied: []string{"rm -rf /"}}},
			wantKind:    "command",
			wantPattern: "rm -rf /",
		},
		{
			name:        "filename allowed",
			rule:        client.PolicyRule{FilenameConstraints: &client.Constraint{Allowed: []string{"ok.txt"}}},
			wantKind:    "filename",
			wantPattern: "ok.txt",
		},
		{
			name:        "url constraints",
			rule:        client.PolicyRule{URLConstraints: &client.Constraint{Denied: []string{"http://evil.example"}}},
			wantKind:    "url",
			wantPattern: "http://evil.example",
		},
		{
			name:        "path constraints only",
			rule:        client.PolicyRule{PathConstraints: &client.PathConstraint{Allowed: []string{"/tmp"}}},
			wantKind:    "path",
			wantPattern: "/tmp",
		},
		{
			name:        "non-wildcard tool pattern",
			rule:        client.PolicyRule{ToolPattern: "bash"},
			wantKind:    "tool",
			wantPattern: "bash",
		},
		{
			name:        "bare wildcard tool fallback",
			rule:        client.PolicyRule{ToolPattern: "*"},
			wantKind:    "tool",
			wantPattern: "*",
		},
		{
			name:        "no pattern at all falls back to wildcard tool",
			rule:        client.PolicyRule{},
			wantKind:    "tool",
			wantPattern: "*",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, pattern := ruleMatch(tc.rule)
			if kind != tc.wantKind || pattern != tc.wantPattern {
				t.Errorf("ruleMatch() = (%q, %q), want (%q, %q)", kind, pattern, tc.wantKind, tc.wantPattern)
			}
		})
	}
}
