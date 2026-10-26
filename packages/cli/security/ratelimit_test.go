// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !windows

package security

import (
	"context"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
)

func TestRateLimitUsage(t *testing.T) {
	u := ratelimitUsage()
	for _, want := range []string{"solongate ratelimit", "ratelimit show", "ratelimit set", "ratelimit history", "--minute", "--mode"} {
		if !strings.Contains(u, want) {
			t.Errorf("ratelimitUsage() missing %q:\n%s", want, u)
		}
	}
}

func TestModeColor(t *testing.T) {
	tests := []struct {
		name string
		mode client.LayerMode
		want string
	}{
		{"block is green", client.LayerBlock, cliutil.Green(string(client.LayerBlock))},
		{"detect is yellow", client.LayerDetect, cliutil.Yellow(string(client.LayerDetect))},
		{"off falls back to dim", client.LayerOff, cliutil.Dim(string(client.LayerOff))},
		{"redact falls back to dim", client.LayerRedact, cliutil.Dim(string(client.LayerRedact))},
		{"an unrecognized mode falls back to dim", client.LayerMode("bogus"), cliutil.Dim("bogus")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := modeColor(tc.mode); got != tc.want {
				t.Errorf("modeColor(%q) = %q, want %q", tc.mode, got, tc.want)
			}
		})
	}
}

func TestParseRateLimitMode(t *testing.T) {
	tests := []struct {
		raw  string
		want client.LayerMode
		ok   bool
	}{
		{"off", client.LayerOff, true},
		{"detect", client.LayerDetect, true},
		{"block", client.LayerBlock, true},
		{"redact", "", false},
		{"nonsense", "", false},
		{"BLOCK", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			got, ok := parseRateLimitMode(tc.raw)
			if ok != tc.ok || got != tc.want {
				t.Errorf("parseRateLimitMode(%q) = (%q, %v), want (%q, %v)", tc.raw, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestRunRateLimitSetRejectsUnknownMode(t *testing.T) {
	ctx := context.Background()
	c := client.New()
	before, err := c.Settings.GetSecurityLayers(ctx)
	if err != nil {
		t.Fatalf("GetSecurityLayers() before: %v", err)
	}

	var code int
	var runErr error
	out := captureOutput(t, func() {
		code, runErr = RunRateLimit(ctx, c, cliutil.Parse([]string{"set", "--mode", "nonsense"}))
	})
	if runErr != nil || code != 1 {
		t.Fatalf("RunRateLimit(set --mode nonsense) = (%d, %v), want (1, nil): %s", code, runErr, out)
	}
	if !strings.Contains(out, "off|detect|block") {
		t.Errorf("usage error does not list the valid modes: %s", out)
	}

	after, err := c.Settings.GetSecurityLayers(ctx)
	if err != nil {
		t.Fatalf("GetSecurityLayers() after: %v", err)
	}
	if after.Layers.RateLimit.Mode != before.Layers.RateLimit.Mode {
		t.Errorf("mode was stored as %q, want it left at %q", after.Layers.RateLimit.Mode, before.Layers.RateLimit.Mode)
	}
}

func TestRunRateLimitSetRejectsNonPositiveLimits(t *testing.T) {
	for _, flag := range []string{"minute", "hour", "day"} {
		for _, value := range []string{"0", "-1"} {
			t.Run(flag+"="+value, func(t *testing.T) {
				ctx := context.Background()
				c := client.New()

				var code int
				var runErr error
				out := captureOutput(t, func() {
					code, runErr = RunRateLimit(ctx, c, cliutil.Parse([]string{"set", "--" + flag, value}))
				})
				if runErr != nil || code != 1 {
					t.Fatalf("RunRateLimit(set --%s %s) = (%d, %v), want (1, nil): %s", flag, value, code, runErr, out)
				}
				if !strings.Contains(out, "positive") {
					t.Errorf("usage error does not say the limit must be positive: %s", out)
				}
			})
		}
	}
}

func TestRunRateLimitSetAppliesValidValues(t *testing.T) {
	ctx := context.Background()
	c := client.New()

	var code int
	var runErr error
	out := captureOutput(t, func() {
		code, runErr = RunRateLimit(ctx, c, cliutil.Parse([]string{"set", "--mode", "block", "--minute", "30"}))
	})
	if runErr != nil || code != 0 {
		t.Fatalf("RunRateLimit(set --mode block --minute 30) = (%d, %v), want (0, nil): %s", code, runErr, out)
	}

	after, err := c.Settings.GetSecurityLayers(ctx)
	if err != nil {
		t.Fatalf("GetSecurityLayers() after: %v", err)
	}
	if after.Layers.RateLimit.Mode != client.LayerBlock {
		t.Errorf("mode = %q, want %q", after.Layers.RateLimit.Mode, client.LayerBlock)
	}
	if after.Layers.RateLimit.PerMinute != 30 {
		t.Errorf("per-minute limit = %d, want 30", after.Layers.RateLimit.PerMinute)
	}
}

func TestIsoMillis(t *testing.T) {
	tests := []struct {
		ms   int64
		want string
	}{
		{1700000000000, "2023-11-14T22:13:20.000Z"},
		{1700000000123, "2023-11-14T22:13:20.123Z"},
		{0, "1970-01-01T00:00:00.000Z"},
	}
	for _, tc := range tests {
		if got := isoMillis(tc.ms); got != tc.want {
			t.Errorf("isoMillis(%d) = %q, want %q", tc.ms, got, tc.want)
		}
	}
}

func TestRunRateLimitHelp(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	var code int
	var err error
	out := captureOutput(t, func() { code, err = RunRateLimit(ctx, c, cliutil.Parse([]string{"help"})) })
	if code != 0 || err != nil {
		t.Errorf("RunRateLimit(help) = (%d, %v), want (0, nil)", code, err)
	}
	if !strings.Contains(out, "solongate ratelimit") {
		t.Errorf("help did not print usage:\n%s", out)
	}
}

func TestRunRateLimitUnknownSub(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	var code int
	var err error
	out := captureOutput(t, func() { code, err = RunRateLimit(ctx, c, cliutil.Parse([]string{"bogus-sub"})) })
	if code != 1 || err != nil {
		t.Errorf("RunRateLimit(bogus-sub) = (%d, %v), want (1, nil)", code, err)
	}
	if !strings.Contains(out, "Unknown ratelimit subcommand") || !strings.Contains(out, "bogus-sub") {
		t.Errorf("unexpected unknown-sub output:\n%s", out)
	}
}

func TestRunRateLimitShow(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	run := func(args ...string) (int, error, string) {
		var code int
		var err error
		out := captureOutput(t, func() { code, err = RunRateLimit(ctx, c, cliutil.Parse(args)) })
		return code, err, out
	}

	t.Run("empty sub defaults to show, zero history prints no history line", func(t *testing.T) {
		code, err, out := run()
		if code != 0 || err != nil {
			t.Fatalf("RunRateLimit() = (%d, %v), want (0, nil): %s", code, err, out)
		}
		if !strings.Contains(out, "Rate limit") || !strings.Contains(out, "/min") {
			t.Errorf("show output=%q, want it to render the rate-limit summary", out)
		}
		if strings.Contains(out, "history") {
			t.Errorf("show output=%q, want no history line when history is empty", out)
		}
	})

	t.Run("show json reports rateLimit and history keys", func(t *testing.T) {
		code, err, out := run("show", "--json")
		if code != 0 || err != nil {
			t.Fatalf("RunRateLimit(show --json) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		if !strings.Contains(out, `"rateLimit"`) || !strings.Contains(out, `"history"`) {
			t.Errorf("show --json output=%q, want rateLimit and history keys", out)
		}
	})

	t.Run("after a set, show renders a history sparkline", func(t *testing.T) {
		code, err, out := run("set", "--minute", "42")
		if code != 0 || err != nil {
			t.Fatalf("RunRateLimit(set --minute 42) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		_, _, out = run("show")
		if !strings.Contains(out, "history") {
			t.Errorf("show output after a set=%q, want a history line", out)
		}
		if !strings.Contains(out, "1 changes") {
			t.Errorf("show output after one set=%q, want it to report 1 change", out)
		}
	})
}

func TestRunRateLimitHistory(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	run := func(args ...string) (int, error, string) {
		var code int
		var err error
		out := captureOutput(t, func() { code, err = RunRateLimit(ctx, c, cliutil.Parse(args)) })
		return code, err, out
	}

	t.Run("zero entries prints a no-history message", func(t *testing.T) {
		code, err, out := run("history")
		if code != 0 || err != nil {
			t.Fatalf("RunRateLimit(history) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		if !strings.Contains(out, "No rate-limit changes recorded") {
			t.Errorf("history output=%q, want the no-history message", out)
		}
	})

	t.Run("zero entries json is an empty array", func(t *testing.T) {
		code, err, out := run("history", "--json")
		if code != 0 || err != nil {
			t.Fatalf("RunRateLimit(history --json) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		if strings.TrimSpace(out) != "[]" {
			t.Errorf("history --json output=%q, want an empty array", out)
		}
	})

	t.Run("entries after a set render as a table", func(t *testing.T) {
		code, err, out := run("set", "--minute", "10", "--hour", "100", "--day", "1000", "--mode", "block")
		if code != 0 || err != nil {
			t.Fatalf("RunRateLimit(set) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		_, _, out = run("history")
		if !strings.Contains(out, "WHEN") || !strings.Contains(out, "MINUTE") || !strings.Contains(out, "HOUR") || !strings.Contains(out, "DAY") {
			t.Errorf("history output=%q, want a table header", out)
		}
		if !strings.Contains(out, "10") || !strings.Contains(out, "100") || !strings.Contains(out, "1000") {
			t.Errorf("history output=%q, want the recorded minute/hour/day values", out)
		}

		_, _, outJSON := run("history", "--json")
		if !strings.Contains(outJSON, `"minute": 10`) || !strings.Contains(outJSON, `"hour": 100`) || !strings.Contains(outJSON, `"day": 1000`) {
			t.Errorf("history --json output=%q, want the recorded values", outJSON)
		}
	})
}

func TestRunRateLimitSet(t *testing.T) {
	newHome(t)
	c := client.New()
	ctx := context.Background()

	run := func(args ...string) (int, error, string) {
		var code int
		var err error
		out := captureOutput(t, func() { code, err = RunRateLimit(ctx, c, cliutil.Parse(args)) })
		return code, err, out
	}

	t.Run("no flags at all is a usage error", func(t *testing.T) {
		code, err, out := run("set")
		if code != 1 || err != nil {
			t.Errorf("RunRateLimit(set) = (%d, %v), want (1, nil)", code, err)
		}
		if !strings.Contains(out, "Usage: ratelimit set") {
			t.Errorf("set output=%q, want usage text", out)
		}
	})

	t.Run("setting only the mode is enough to pass validation", func(t *testing.T) {
		code, err, out := run("set", "--mode", "detect")
		if code != 0 || err != nil {
			t.Fatalf("RunRateLimit(set --mode detect) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		if !strings.Contains(out, "Rate limit updated") || !strings.Contains(out, "detect") {
			t.Errorf("set --mode output=%q, want a confirmation naming the mode", out)
		}
	})

	t.Run("setting minute/hour/day round trips through show --json", func(t *testing.T) {
		code, err, out := run("set", "--minute", "5", "--hour", "50", "--day", "500", "--mode", "block")
		if code != 0 || err != nil {
			t.Fatalf("RunRateLimit(set) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		_, _, show := run("show", "--json")
		for _, want := range []string{`"perMinute": 5`, `"perHour": 50`, `"perDay": 500`, `"mode": "block"`} {
			if !strings.Contains(show, want) {
				t.Errorf("show --json after set = %q, want %q", show, want)
			}
		}
	})

	t.Run("a partial set only touches the flags given", func(t *testing.T) {
		if code, err, out := run("set", "--minute", "7", "--hour", "70", "--day", "700", "--mode", "block"); code != 0 || err != nil {
			t.Fatalf("RunRateLimit(set full) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		code, err, out := run("set", "--minute", "9")
		if code != 0 || err != nil {
			t.Fatalf("RunRateLimit(set --minute 9) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		_, _, show := run("show", "--json")
		for _, want := range []string{`"perMinute": 9`, `"perHour": 70`, `"perDay": 700`, `"mode": "block"`} {
			if !strings.Contains(show, want) {
				t.Errorf("show --json after a partial set = %q, want %q preserved/updated", show, want)
			}
		}
	})

	t.Run("set --json prints the saved rate limit", func(t *testing.T) {
		code, err, out := run("set", "--minute", "3", "--json")
		if code != 0 || err != nil {
			t.Fatalf("RunRateLimit(set --json) = (%d, %v), want (0, nil): %s", code, err, out)
		}
		if !strings.Contains(out, `"perMinute": 3`) {
			t.Errorf("set --json output=%q, want perMinute reflected", out)
		}
	})
}
