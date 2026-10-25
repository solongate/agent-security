// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package health

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/core/install"
)

func newClient(t *testing.T) (*client.Client, context.Context, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	return client.New(), context.Background(), home
}

func writeEvalRecord(t *testing.T, home, project, jsonLine string) {
	t.Helper()
	dir := filepath.Join(home, ".solongate", "projects", project)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".eval-ring.jsonl"), []byte(jsonLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func boolPtr(b bool) *bool { return &b }

func intPtr(n int) *int { return &n }

func TestCheckStateMarshalJSON(t *testing.T) {
	cases := []struct {
		name string
		s    CheckState
		want string
	}{
		{"ok marshals to the boolean true", StateOK, "true"},
		{"warn marshals to the string warn", StateWarn, `"warn"`},
		{"fail marshals to the boolean false", StateFail, "false"},
		{"an unrecognized value also marshals to false", CheckState(42), "false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.s.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON() error = %v", err)
			}
			if string(b) != tc.want {
				t.Errorf("MarshalJSON() = %s, want %s", b, tc.want)
			}
		})
	}
}

func TestPlural(t *testing.T) {
	cases := []struct {
		n    int
		one  string
		many string
		want string
	}{
		{0, "path", "paths", "0 paths"},
		{1, "path", "paths", "1 path"},
		{2, "path", "paths", "2 paths"},
	}
	for _, tc := range cases {
		if got := plural(tc.n, tc.one, tc.many); got != tc.want {
			t.Errorf("plural(%d, %q, %q) = %q, want %q", tc.n, tc.one, tc.many, got, tc.want)
		}
	}
}

func TestRoundHalfUp(t *testing.T) {
	cases := []struct {
		v    float64
		want int64
	}{
		{0, 0},
		{2.4, 2},
		{2.5, 3},
		{2.9, 3},
		{-2.5, -2},
	}
	for _, tc := range cases {
		if got := roundHalfUp(tc.v); got != tc.want {
			t.Errorf("roundHalfUp(%v) = %d, want %d", tc.v, got, tc.want)
		}
	}
}

func TestFixed0(t *testing.T) {
	cases := []struct {
		v    float64
		want string
	}{
		{0, "0"},
		{1.4, "1"},
		{1.5, "2"},
		{2.5, "3"},
		{-1.5, "-2"},
	}
	for _, tc := range cases {
		if got := fixed0(tc.v); got != tc.want {
			t.Errorf("fixed0(%v) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

func TestRlWindows(t *testing.T) {
	cases := []struct {
		name string
		l    *client.RateLimitSettings
		want string
	}{
		{"nothing set", &client.RateLimitSettings{}, "no window set"},
		{"minute only", &client.RateLimitSettings{PerMinute: 10}, "10/min"},
		{"minute and hour", &client.RateLimitSettings{PerMinute: 10, PerHour: 100}, "10/min · 100/hr"},
		{"day only", &client.RateLimitSettings{PerDay: 50}, "50/day"},
		{"all three", &client.RateLimitSettings{PerMinute: 1, PerHour: 2, PerDay: 3}, "1/min · 2/hr · 3/day"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rlWindows(tc.l); got != tc.want {
				t.Errorf("rlWindows(%+v) = %q, want %q", tc.l, got, tc.want)
			}
		})
	}
}

func TestLocalLogCheckNoFileYet(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	checks := localLogCheck()
	if len(checks) != 1 {
		t.Fatalf("localLogCheck() = %+v, want exactly one check", checks)
	}
	if checks[0].OK != StateWarn || !strings.Contains(checks[0].Detail, "nothing recorded yet") {
		t.Errorf("localLogCheck() = %+v", checks[0])
	}
}

func TestLocalLogCheckWithRecentFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	file := config.LocalLogFile()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, make([]byte, 2048), 0o644); err != nil {
		t.Fatal(err)
	}

	checks := localLogCheck()
	if len(checks) != 1 {
		t.Fatalf("localLogCheck() = %+v, want exactly one check", checks)
	}
	got := checks[0]
	if got.OK != StateOK {
		t.Errorf("OK = %v, want StateOK", got.OK)
	}
	if !strings.Contains(got.Detail, "2KB") {
		t.Errorf("Detail = %q, want it to report 2KB", got.Detail)
	}
	if !strings.Contains(got.Detail, "just now") {
		t.Errorf("Detail = %q, want a just-now timestamp for a freshly written file", got.Detail)
	}
}

func TestLocalLogCheckWithOlderFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	file := config.LocalLogFile()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-5 * time.Minute)
	if err := os.Chtimes(file, old, old); err != nil {
		t.Fatal(err)
	}

	checks := localLogCheck()
	if len(checks) != 1 {
		t.Fatalf("localLogCheck() = %+v, want exactly one check", checks)
	}
	if !strings.Contains(checks[0].Detail, "5m ago") {
		t.Errorf("Detail = %q, want it to report 5m ago", checks[0].Detail)
	}
}

func TestPolicyChecksNoPolicy(t *testing.T) {
	c, ctx, _ := newClient(t)
	checks := policyChecks(ctx, c)
	want := []Check{
		{Name: "active policy", OK: StateWarn, Detail: "none · every call is allowed, and recorded"},
		{Name: "rate limit", OK: StateWarn, Detail: "off"},
		{Name: "dlp", OK: StateWarn, Detail: "off"},
		{Name: "self-protection", OK: StateOK, Detail: "on"},
	}
	if !reflect.DeepEqual(checks, want) {
		t.Errorf("policyChecks() = %+v, want %+v", checks, want)
	}
}

func TestPolicyChecksActivePolicy(t *testing.T) {
	cases := []struct {
		name     string
		mode     client.PolicyMode
		wantMode string
	}{
		{"empty mode defaults to denylist", "", "denylist"},
		{"explicit denylist", client.ModeDenylist, "denylist"},
		{"whitelist", client.ModeWhitelist, "whitelist"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ctx, _ := newClient(t)
			if _, err := c.Policies.Create(ctx, client.PolicySet{Name: "test-policy", Mode: tc.mode}); err != nil {
				t.Fatalf("Create: %v", err)
			}
			checks := policyChecks(ctx, c)
			if len(checks) == 0 {
				t.Fatal("policyChecks() returned no checks")
			}
			got := checks[0]
			if got.Name != "active policy" || got.OK != StateOK {
				t.Fatalf("active policy check = %+v", got)
			}
			if !strings.Contains(got.Detail, "test-policy v1") {
				t.Errorf("Detail = %q, want it to name the policy and version", got.Detail)
			}
			if !strings.Contains(got.Detail, tc.wantMode) {
				t.Errorf("Detail = %q, want it to report mode %q", got.Detail, tc.wantMode)
			}
			if !strings.Contains(got.Detail, "matched by pinned") {
				t.Errorf("Detail = %q, want it to report how it matched", got.Detail)
			}
		})
	}
}

func TestPolicyChecksRateLimit(t *testing.T) {
	cases := []struct {
		name       string
		configure  func(t *testing.T, c *client.Client, ctx context.Context)
		wantDetail string
	}{
		{
			name:       "off by default",
			configure:  func(t *testing.T, c *client.Client, ctx context.Context) {},
			wantDetail: "off",
		},
		{
			name: "block mode reports the windows",
			configure: func(t *testing.T, c *client.Client, ctx context.Context) {
				var l client.SecurityLayers
				l.RateLimit.Mode = client.LayerBlock
				l.RateLimit.PerMinute = 10
				l.RateLimit.PerHour = 100
				if _, err := c.Settings.SetSecurityLayers(ctx, l); err != nil {
					t.Fatalf("SetSecurityLayers: %v", err)
				}
			},
			wantDetail: "block · 10/min · 100/hr",
		},
		{
			name: "detect mode flags bursts without blocking",
			configure: func(t *testing.T, c *client.Client, ctx context.Context) {
				var l client.SecurityLayers
				l.RateLimit.Mode = client.LayerDetect
				l.RateLimit.PerDay = 500
				if _, err := c.Settings.SetSecurityLayers(ctx, l); err != nil {
					t.Fatalf("SetSecurityLayers: %v", err)
				}
			},
			wantDetail: "detect · 500/day · flags bursts, never blocks",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ctx, _ := newClient(t)
			tc.configure(t, c, ctx)
			checks := policyChecks(ctx, c)
			var rl *Check
			for i := range checks {
				if checks[i].Name == "rate limit" {
					rl = &checks[i]
				}
			}
			if rl == nil {
				t.Fatal("no rate limit check found")
			}
			if rl.Detail != tc.wantDetail {
				t.Errorf("rate limit detail = %q, want %q", rl.Detail, tc.wantDetail)
			}
		})
	}
}

func TestPolicyChecksDLP(t *testing.T) {
	cases := []struct {
		name       string
		mode       client.LayerMode
		patterns   []string
		wantDetail string
	}{
		{"off by default", "", nil, "off"},
		{"block mode refuses matching calls", client.LayerBlock, []string{"a", "b"}, "block · 2 patterns · refuses a call carrying one"},
		{"redact mode masks secrets", client.LayerRedact, []string{"a"}, "redact · 1 patterns · masks secrets, never blocks"},
		{"detect mode records hits", client.LayerDetect, []string{"a", "b", "c"}, "detect · 3 patterns · records hits, changes nothing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ctx, _ := newClient(t)
			if tc.mode != "" {
				var l client.SecurityLayers
				l.DLP.Mode = tc.mode
				l.DLP.Patterns = tc.patterns
				if _, err := c.Settings.SetSecurityLayers(ctx, l); err != nil {
					t.Fatalf("SetSecurityLayers: %v", err)
				}
			}
			checks := policyChecks(ctx, c)
			var dlp *Check
			for i := range checks {
				if checks[i].Name == "dlp" {
					dlp = &checks[i]
				}
			}
			if dlp == nil {
				t.Fatal("no dlp check found")
			}
			if dlp.Detail != tc.wantDetail {
				t.Errorf("dlp detail = %q, want %q", dlp.Detail, tc.wantDetail)
			}
		})
	}
}

func TestPolicyChecksSelfProtection(t *testing.T) {
	cases := []struct {
		name       string
		set        *bool
		wantOK     CheckState
		wantDetail string
	}{
		{"default is on", nil, StateOK, "on"},
		{"explicitly on", boolPtr(true), StateOK, "on"},
		{"explicitly off", boolPtr(false), StateWarn, "off"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ctx, _ := newClient(t)
			if tc.set != nil {
				if _, err := c.Settings.SetSelfProtection(ctx, *tc.set); err != nil {
					t.Fatalf("SetSelfProtection: %v", err)
				}
			}
			checks := policyChecks(ctx, c)
			got := checks[len(checks)-1]
			if got.Name != "self-protection" || got.OK != tc.wantOK || got.Detail != tc.wantDetail {
				t.Errorf("self-protection check = %+v, want OK=%v Detail=%q", got, tc.wantOK, tc.wantDetail)
			}
		})
	}
}

func TestPolicyChecksCorruptPolicyFile(t *testing.T) {
	c, ctx, _ := newClient(t)
	if err := os.MkdirAll(filepath.Dir(client.PolicyPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(client.PolicyPath(), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	checks := policyChecks(ctx, c)
	if len(checks) != 1 || checks[0].Name != "policy" || checks[0].OK != StateFail {
		t.Errorf("policyChecks() with a corrupt policy file = %+v", checks)
	}
}

func TestProtectedCheckNoProtectedPaths(t *testing.T) {
	c, ctx, _ := newClient(t)
	if got := protectedCheck(ctx, c); got != nil {
		t.Errorf("protectedCheck() = %+v, want nil when nothing is protected", got)
	}
}

func TestProtectedCheckLockStates(t *testing.T) {
	c, ctx, _ := newClient(t)
	dir := t.TempDir()
	writable := filepath.Join(dir, "writable.txt")
	locked := filepath.Join(dir, "locked.txt")
	if err := os.WriteFile(writable, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(locked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := c.Settings.SetProtectedPaths(ctx, []string{writable, locked}); err != nil {
		t.Fatalf("SetProtectedPaths: %v", err)
	}

	checks := protectedCheck(ctx, c)
	if len(checks) == 0 {
		t.Fatal("protectedCheck() returned no checks")
	}
	got := checks[0]
	if got.Name != "protected paths" || got.OK != StateWarn {
		t.Fatalf("protected paths check = %+v", got)
	}
	if !strings.Contains(got.Detail, "0 of 2 fully locked") {
		t.Errorf("Detail = %q, want it to report the lock count", got.Detail)
	}
	if !strings.Contains(got.Detail, writable) {
		t.Errorf("Detail = %q, want it to name the first unlocked path", got.Detail)
	}
	if !strings.Contains(got.Detail, "not locked") {
		t.Errorf("Detail = %q, want it to describe the writable file as unlocked", got.Detail)
	}
}

func TestProtectedCheckChmodOnlyLock(t *testing.T) {
	c, ctx, _ := newClient(t)
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked.txt")
	if err := os.WriteFile(locked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := c.Settings.SetProtectedPaths(ctx, []string{locked}); err != nil {
		t.Fatalf("SetProtectedPaths: %v", err)
	}

	checks := protectedCheck(ctx, c)
	if len(checks) == 0 {
		t.Fatal("protectedCheck() returned no checks")
	}
	got := checks[0]
	if !strings.Contains(got.Detail, "chmod 0400") || !strings.Contains(got.Detail, "CAN still be deleted") {
		t.Errorf("Detail = %q, want it to describe a chmod-only lock", got.Detail)
	}
}

func TestProtectedCheckStaleCredential(t *testing.T) {
	c, ctx, home := newClient(t)

	protected := filepath.Join(home, "protected.txt")
	if err := os.WriteFile(protected, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Settings.SetProtectedPaths(ctx, []string{protected}); err != nil {
		t.Fatalf("SetProtectedPaths: %v", err)
	}

	sgDir := filepath.Join(home, ".solongate")
	if err := os.MkdirAll(sgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(sgDir, "accounts.json")
	if err := os.WriteFile(stale, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	checks := protectedCheck(ctx, c)
	var found *Check
	for i := range checks {
		if checks[i].Name == "stale credential" {
			found = &checks[i]
		}
	}
	if found == nil {
		t.Fatal("expected a stale credential check for a leftover accounts.json")
	}
	if found.OK != StateWarn || !strings.Contains(found.Detail, stale) {
		t.Errorf("stale credential check = %+v", found)
	}
}

func TestProtectedCheckConfinement(t *testing.T) {
	cases := []struct {
		name               string
		setup              func(t *testing.T, c *client.Client, ctx context.Context, home string)
		wantOK             CheckState
		wantDetailContains string
	}{
		{
			name: "required confinement is always enforced",
			setup: func(t *testing.T, c *client.Client, ctx context.Context, home string) {
				if err := c.Settings.SetRequireSandbox(ctx, true); err != nil {
					t.Fatal(err)
				}
			},
			wantOK:             StateOK,
			wantDetailContains: "required",
		},
		{
			name:               "nothing recorded yet",
			setup:              func(t *testing.T, c *client.Client, ctx context.Context, home string) {},
			wantOK:             StateWarn,
			wantDetailContains: "no tool call recorded yet",
		},
		{
			name: "last call came from inside run",
			setup: func(t *testing.T, c *client.Client, ctx context.Context, home string) {
				writeEvalRecord(t, home, "proj1", `{"ts":1,"sandbox":"linux"}`)
			},
			wantOK:             StateOK,
			wantDetailContains: "came from inside",
		},
		{
			name: "last call came from outside run",
			setup: func(t *testing.T, c *client.Client, ctx context.Context, home string) {
				writeEvalRecord(t, home, "proj1", `{"ts":1}`)
			},
			wantOK:             StateWarn,
			wantDetailContains: "kernel was not enforcing",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ctx, home := newClient(t)

			protected := filepath.Join(home, "protected.txt")
			if err := os.WriteFile(protected, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := c.Settings.SetProtectedPaths(ctx, []string{protected}); err != nil {
				t.Fatal(err)
			}

			tc.setup(t, c, ctx, home)

			checks := protectedCheck(ctx, c)
			var conf *Check
			for i := range checks {
				if checks[i].Name == "confinement" {
					conf = &checks[i]
				}
			}
			if conf == nil {
				t.Fatal("expected a confinement check")
			}
			if conf.OK != tc.wantOK {
				t.Errorf("OK = %v, want %v", conf.OK, tc.wantOK)
			}
			if !strings.Contains(conf.Detail, tc.wantDetailContains) {
				t.Errorf("Detail = %q, want containing %q", conf.Detail, tc.wantDetailContains)
			}
		})
	}
}

func TestGuardHookCheck(t *testing.T) {
	cases := []struct {
		name                string
		latest              int
		installed           *int
		wantOK              CheckState
		wantDetailContains  string
	}{
		{"nothing known, nothing to update to", 0, nil, StateWarn, "v? → v0 available"},
		{"a newer version is published", 5, nil, StateWarn, "v? → v5 available"},
		{"installed and current", 3, intPtr(3), StateOK, "v3 (latest)"},
		{"installed but behind", 3, intPtr(1), StateWarn, "v1 → v3 available"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			old := client.GuardVersions
			client.GuardVersions = func() (int, *int) { return tc.latest, tc.installed }
			defer func() { client.GuardVersions = old }()

			c, ctx := client.New(), context.Background()
			checks := guardHookCheck(ctx, c)
			if len(checks) != 1 {
				t.Fatalf("guardHookCheck() = %+v, want exactly one check", checks)
			}
			got := checks[0]
			if got.OK != tc.wantOK {
				t.Errorf("OK = %v, want %v", got.OK, tc.wantOK)
			}
			if !strings.Contains(got.Detail, tc.wantDetailContains) {
				t.Errorf("Detail = %q, want containing %q", got.Detail, tc.wantDetailContains)
			}
		})
	}
}

func TestClientChecksNothingInstalled(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	checks := clientChecks()
	if len(checks) != 1 {
		t.Fatalf("clientChecks() = %+v, want exactly the Claude hooks check", checks)
	}
	got := checks[0]
	if got.Name != "Claude hooks" || got.OK != StateFail {
		t.Errorf("Claude hooks check = %+v", got)
	}
}

func TestClientChecksGuardRegisteredAndHealthy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settings := `{"hooks":{"PreToolUse":[{"matcher":"","hooks":[{"type":"command","command":"sh ` +
		home + `/.solongate/hooks/sg-run.sh guard"}]}]}}`
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}

	hooksDir := filepath.Join(home, ".solongate", "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(hooksDir, install.LauncherName)
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\necho /fake/solongate-guard\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	beatDir := filepath.Join(home, ".solongate", install.BeatDirName)
	if err := os.MkdirAll(beatDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(beatDir, "guard"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}

	checks := clientChecks()
	byName := map[string]Check{}
	for _, c := range checks {
		byName[c.Name] = c
	}

	if c := byName["Claude hooks"]; c.OK != StateOK {
		t.Errorf("Claude hooks = %+v, want StateOK", c)
	}
	if c := byName["guard binary"]; c.OK != StateOK || c.Detail != "/fake/solongate-guard" {
		t.Errorf("guard binary = %+v", c)
	}
	if c := byName["guard fired"]; c.OK != StateOK {
		t.Errorf("guard fired = %+v, want StateOK", c)
	}
}

func TestClientChecksGuardRegisteredNoBinary(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settings := `{"hooks":{"PreToolUse":[{"hooks":[{"command":".solongate guard"}]}]}}`
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}

	checks := clientChecks()
	byName := map[string]Check{}
	for _, c := range checks {
		byName[c.Name] = c
	}

	if c := byName["guard binary"]; c.OK != StateFail || !strings.Contains(c.Detail, "nothing is being enforced") {
		t.Errorf("guard binary = %+v", c)
	}
	if c := byName["guard fired"]; c.OK != StateWarn || !strings.Contains(c.Detail, "never") {
		t.Errorf("guard fired = %+v", c)
	}
}

func TestClientChecksCodexStates(t *testing.T) {
	cases := []struct {
		name                string
		hooksJSON           string
		configToml          string
		wantOK              CheckState
		wantDetailContains  string
	}{
		{
			name:               "not registered",
			wantOK:             StateFail,
			wantDetailContains: "NOT registered",
		},
		{
			name:               "registered but not trusted",
			hooksJSON:          `{"PreToolUse":[{"hooks":[{"type":"command","command":"/x/.solongate/hooks/sg-run.sh"}]}]}`,
			wantOK:             StateWarn,
			wantDetailContains: "trust them",
		},
		{
			name:               "registered and trusted",
			hooksJSON:          `{"PreToolUse":[{"hooks":[{"type":"command","command":"/x/.solongate/hooks/sg-run.sh"}]}]}`,
			configToml:         "trusted_hash = \"abc\"\n",
			wantOK:             StateOK,
			wantDetailContains: "registered + trusted",
		},
		{
			name:               "hooks disabled",
			hooksJSON:          `{"PreToolUse":[{"hooks":[{"type":"command","command":"/x/.solongate/hooks/sg-run.sh"}]}]}`,
			configToml:         "[features]\nhooks = false\n",
			wantOK:             StateFail,
			wantDetailContains: "hooks disabled",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("CODEX_HOME", "")
			t.Setenv("XDG_CONFIG_HOME", "")

			codexDir := filepath.Join(home, ".codex")
			if err := os.MkdirAll(codexDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.hooksJSON != "" {
				if err := os.WriteFile(filepath.Join(codexDir, "hooks.json"), []byte(tc.hooksJSON), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.configToml != "" {
				if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(tc.configToml), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			checks := clientChecks()
			var got *Check
			for i := range checks {
				if checks[i].Name == "Codex hooks" {
					got = &checks[i]
				}
			}
			if got == nil {
				t.Fatal("expected a Codex hooks check")
			}
			if got.OK != tc.wantOK {
				t.Errorf("OK = %v, want %v", got.OK, tc.wantOK)
			}
			if !strings.Contains(got.Detail, tc.wantDetailContains) {
				t.Errorf("Detail = %q, want containing %q", got.Detail, tc.wantDetailContains)
			}
		})
	}
}

func TestClientChecksOpencodeStates(t *testing.T) {
	cases := []struct {
		name                string
		installPlugin       bool
		wantOK              CheckState
		wantDetailContains  string
	}{
		{"not installed", false, StateFail, "NOT registered"},
		{"installed", true, StateOK, "not active under"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("CODEX_HOME", "")
			t.Setenv("XDG_CONFIG_HOME", "")

			opencodeDir := filepath.Join(home, ".config", "opencode")
			if err := os.MkdirAll(opencodeDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.installPlugin {
				pluginDir := filepath.Join(opencodeDir, "plugins")
				if err := os.MkdirAll(pluginDir, 0o755); err != nil {
					t.Fatal(err)
				}
				plugin := []byte("tool.execute.before(() => {})")
				if err := os.WriteFile(filepath.Join(pluginDir, "solongate.js"), plugin, 0o644); err != nil {
					t.Fatal(err)
				}
			}

			checks := clientChecks()
			var got *Check
			for i := range checks {
				if checks[i].Name == "OpenCode hooks" {
					got = &checks[i]
				}
			}
			if got == nil {
				t.Fatal("expected an OpenCode hooks check")
			}
			if got.OK != tc.wantOK {
				t.Errorf("OK = %v, want %v", got.OK, tc.wantOK)
			}
			if !strings.Contains(got.Detail, tc.wantDetailContains) {
				t.Errorf("Detail = %q, want containing %q", got.Detail, tc.wantDetailContains)
			}
		})
	}
}

func TestClientChecksAntigravityStates(t *testing.T) {
	cases := []struct {
		name            string
		createHooksFile bool
		wantOK          CheckState
	}{
		{"detected but hooks missing", false, StateFail},
		{"detected and hooks registered", true, StateOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("CODEX_HOME", "")
			t.Setenv("XDG_CONFIG_HOME", "")

			antigravityDir := filepath.Join(home, ".gemini", "config")
			if err := os.MkdirAll(antigravityDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.createHooksFile {
				if err := os.WriteFile(filepath.Join(antigravityDir, "hooks.json"), []byte("{}"), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			checks := clientChecks()
			var got *Check
			for i := range checks {
				if checks[i].Name == "Antigravity hooks" {
					got = &checks[i]
				}
			}
			if got == nil {
				t.Fatal("expected an Antigravity hooks check")
			}
			if got.OK != tc.wantOK {
				t.Errorf("OK = %v, want %v", got.OK, tc.wantOK)
			}
		})
	}
}

func TestCollectChecksPolicyFilePresence(t *testing.T) {
	c, ctx, _ := newClient(t)

	checks := CollectChecks(ctx, c)
	if len(checks) == 0 || checks[0].Name != "policy file" || checks[0].OK != StateWarn {
		t.Fatalf("first check = %+v, want a warning that no policy file exists yet", checks[0])
	}

	if _, err := c.Policies.Create(ctx, client.PolicySet{Name: "p"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	checks = CollectChecks(ctx, c)
	if checks[0].OK != StateOK || checks[0].Detail != client.PolicyPath() {
		t.Errorf("policy file check after creating a policy = %+v", checks[0])
	}
}