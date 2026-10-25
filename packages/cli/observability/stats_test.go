// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !windows

package observability

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
)

func TestStatsUsage(t *testing.T) {
	u := statsUsage()
	for _, want := range []string{"solongate stats", "overview", "timeseries", "drift"} {
		if !strings.Contains(u, want) {
			t.Errorf("statsUsage() missing %q, got: %s", want, u)
		}
	}
}

func TestRunStatsHelp(t *testing.T) {
	newHome(t)
	c := client.New()
	code, err := RunStats(context.Background(), c, cliutil.Parse([]string{"help"}))
	if err != nil {
		t.Fatalf("RunStats(help): %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
}

func TestRunStatsOverviewEmpty(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"default subcommand", nil},
		{"explicit overview", []string{"overview"}},
	}
	for _, c := range cases {
		t.Run(c.name+"/json", func(t *testing.T) {
			newHome(t)
			cl := client.New()
			var code int
			var err error
			out := captureFD(t, 1, func() {
				code, err = RunStats(context.Background(), cl, cliutil.Parse(append(append([]string{}, c.args...), "--json")))
			})
			if err != nil {
				t.Fatalf("RunStats: %v", err)
			}
			if code != 0 {
				t.Errorf("code = %d, want 0", code)
			}
			var s client.Stats
			if jerr := json.Unmarshal([]byte(out), &s); jerr != nil {
				t.Fatalf("output is not valid JSON: %v\noutput: %s", jerr, out)
			}
			if s.TotalCalls != 0 || s.Allowed != 0 || s.Denied != 0 || s.ActivePolicies != 0 {
				t.Errorf("got %+v, want all zero on a fresh store", s)
			}
		})
		t.Run(c.name+"/text", func(t *testing.T) {
			newHome(t)
			cl := client.New()
			var code int
			var err error
			out := captureFD(t, 2, func() {
				code, err = RunStats(context.Background(), cl, cliutil.Parse(c.args))
			})
			if err != nil {
				t.Fatalf("RunStats: %v", err)
			}
			if code != 0 {
				t.Errorf("code = %d, want 0", code)
			}
			for _, want := range []string{"0 calls", "0 allowed", "0 denied"} {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q:\n%s", want, out)
				}
			}
		})
	}
}

func TestRunStatsOverviewWithActivity(t *testing.T) {
	newHome(t)
	seedAuditLog(t,
		`{"ts":"2026-01-01T00:00:00Z","tool":"Bash","decision":"ALLOW"}`,
		`{"ts":"2026-01-01T00:01:00Z","tool":"Write","decision":"DENY"}`,
	)
	c := client.New()

	var code int
	var err error
	out := captureFD(t, 2, func() {
		code, err = RunStats(context.Background(), c, cliutil.Parse(nil))
	})
	if err != nil {
		t.Fatalf("RunStats: %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	for _, want := range []string{"2 calls", "1 allowed", "1 denied", "Recent:", "Write", "Bash"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRunStatsTimeseries(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"default period", nil},
		{"explicit period", []string{"--period", "7d"}},
	}
	for _, c := range cases {
		t.Run(c.name+"/json", func(t *testing.T) {
			newHome(t)
			cl := client.New()
			args := append(append([]string{"timeseries"}, c.args...), "--json")
			var code int
			var err error
			out := captureFD(t, 1, func() {
				code, err = RunStats(context.Background(), cl, cliutil.Parse(args))
			})
			if err != nil {
				t.Fatalf("RunStats(timeseries): %v", err)
			}
			if code != 0 {
				t.Errorf("code = %d, want 0", code)
			}
			var ts client.Timeseries
			if jerr := json.Unmarshal([]byte(out), &ts); jerr != nil {
				t.Fatalf("output is not valid JSON: %v\noutput: %s", jerr, out)
			}
		})
		t.Run(c.name+"/text", func(t *testing.T) {
			newHome(t)
			cl := client.New()
			args := append([]string{"timeseries"}, c.args...)
			var code int
			var err error
			out := captureFD(t, 2, func() {
				code, err = RunStats(context.Background(), cl, cliutil.Parse(args))
			})
			if err != nil {
				t.Fatalf("RunStats(timeseries): %v", err)
			}
			if code != 0 {
				t.Errorf("code = %d, want 0", code)
			}
			if !strings.Contains(out, "Timeseries") {
				t.Errorf("output missing %q:\n%s", "Timeseries", out)
			}
		})
	}
}

func TestRunStatsDrift(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"default days", nil},
		{"explicit days", []string{"--days", "3"}},
	}
	for _, c := range cases {
		t.Run(c.name+"/json", func(t *testing.T) {
			newHome(t)
			cl := client.New()
			args := append(append([]string{"drift"}, c.args...), "--json")
			var code int
			var err error
			out := captureFD(t, 1, func() {
				code, err = RunStats(context.Background(), cl, cliutil.Parse(args))
			})
			if err != nil {
				t.Fatalf("RunStats(drift): %v", err)
			}
			if code != 0 {
				t.Errorf("code = %d, want 0", code)
			}
			var d client.Drift
			if jerr := json.Unmarshal([]byte(out), &d); jerr != nil {
				t.Fatalf("output is not valid JSON: %v\noutput: %s", jerr, out)
			}
		})
		t.Run(c.name+"/text", func(t *testing.T) {
			newHome(t)
			cl := client.New()
			args := append([]string{"drift"}, c.args...)
			var code int
			var err error
			out := captureFD(t, 2, func() {
				code, err = RunStats(context.Background(), cl, cliutil.Parse(args))
			})
			if err != nil {
				t.Fatalf("RunStats(drift): %v", err)
			}
			if code != 0 {
				t.Errorf("code = %d, want 0", code)
			}
			if !strings.Contains(out, "Denial drift") {
				t.Errorf("output missing %q:\n%s", "Denial drift", out)
			}
			if !strings.Contains(out, "No denials in window.") {
				t.Errorf("expected the no-denials message on an empty store:\n%s", out)
			}
		})
	}
}

func TestRunStatsUnknownSub(t *testing.T) {
	newHome(t)
	c := client.New()
	var code int
	var err error
	out := captureFD(t, 2, func() {
		code, err = RunStats(context.Background(), c, cliutil.Parse([]string{"bogus"}))
	})
	if err != nil {
		t.Fatalf("RunStats(bogus): %v", err)
	}
	if code != 1 {
		t.Errorf("code = %d, want 1 (cliutil.UnknownSub)", code)
	}
	if !strings.Contains(out, "Unknown stats subcommand") {
		t.Errorf("output missing unknown-subcommand message:\n%s", out)
	}
}