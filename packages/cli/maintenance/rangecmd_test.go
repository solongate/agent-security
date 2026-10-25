// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package maintenance

import (
	"context"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/config"
)

func TestRangeUsageMentionsSolongateRange(t *testing.T) {
	u := rangeUsage()
	if !strings.Contains(u, "solongate range") {
		t.Errorf("rangeUsage() should mention solongate range, got: %s", u)
	}
}

func TestRunRangeHelp(t *testing.T) {
	var code int
	var err error
	out := captureStderrFD(t, func() {
		code, err = RunRange(context.Background(), nil, cliutil.Parse([]string{"help"}))
	})
	if err != nil {
		t.Fatalf("RunRange(help) returned error: %v", err)
	}
	if code != 0 {
		t.Errorf("RunRange(help) = %d, want 0", code)
	}
	if !strings.Contains(out, "solongate range") {
		t.Errorf("RunRange(help) output should show usage, got: %s", out)
	}
}

func TestRunRangeEmptyDelegatesToRangeShow(t *testing.T) {
	newHome(t)
	var code int
	var err error
	out := captureStderrFD(t, func() {
		code, err = RunRange(context.Background(), nil, cliutil.Parse(nil))
	})
	if err != nil {
		t.Fatalf("RunRange() returned error: %v", err)
	}
	if code != 0 {
		t.Errorf("RunRange() = %d, want 0", code)
	}
	if !strings.Contains(out, config.UpdateRangeLong) {
		t.Errorf("RunRange() with no config set should show the default (%s) range, got: %s", config.UpdateRangeLong, out)
	}
}

func TestRunRangeSetValidValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		arg  string
	}{
		{"short", config.UpdateRangeShort},
		{"long", config.UpdateRangeLong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			newHome(t)
			var code int
			var err error
			out := captureStderrFD(t, func() {
				code, err = RunRange(context.Background(), nil, cliutil.Parse([]string{tc.arg}))
			})
			if err != nil {
				t.Fatalf("RunRange(%s) returned error: %v", tc.arg, err)
			}
			if code != 0 {
				t.Errorf("RunRange(%s) = %d, want 0", tc.arg, code)
			}
			if got := config.UpdateRangeOf(config.LoadTUIConfig()); got != tc.arg {
				t.Errorf("after RunRange(%s), the stored range = %q, want %q", tc.arg, got, tc.arg)
			}
			if !strings.Contains(out, tc.arg) {
				t.Errorf("RunRange(%s) output should mention %q, got: %s", tc.arg, tc.arg, out)
			}
		})
	}
}

func TestRunRangeUnrecognizedValue(t *testing.T) {
	var code int
	var err error
	out := captureStderrFD(t, func() {
		code, err = RunRange(context.Background(), nil, cliutil.Parse([]string{"bogus"}))
	})
	if err != nil {
		t.Fatalf("RunRange(bogus) returned error: %v", err)
	}
	if code != 1 {
		t.Errorf("RunRange(bogus) = %d, want 1", code)
	}
	if !strings.Contains(out, "solongate range") {
		t.Errorf("RunRange(bogus) output should show usage, got: %s", out)
	}
}

func TestRangeShowLongIsTheDefault(t *testing.T) {
	newHome(t)
	var code int
	var err error
	out := captureStderrFD(t, func() {
		code, err = rangeShow()
	})
	if err != nil {
		t.Fatalf("rangeShow() returned error: %v", err)
	}
	if code != 0 {
		t.Errorf("rangeShow() = %d, want 0", code)
	}
	if !strings.Contains(out, config.UpdateRangeLong) {
		t.Errorf("rangeShow() should show %q as the current range, got: %s", config.UpdateRangeLong, out)
	}
	if !strings.Contains(out, "tagged releases only") {
		t.Errorf("rangeShow() long-range label is missing, got: %s", out)
	}
	if !strings.Contains(out, "solongate range "+config.UpdateRangeShort) {
		t.Errorf("rangeShow() should suggest switching to %q, got: %s", config.UpdateRangeShort, out)
	}
}

func TestRangeShowShort(t *testing.T) {
	newHome(t)
	if err := config.SetUpdateRange(config.UpdateRangeShort); err != nil {
		t.Fatalf("config.SetUpdateRange: %v", err)
	}

	var code int
	var err error
	out := captureStderrFD(t, func() {
		code, err = rangeShow()
	})
	if err != nil {
		t.Fatalf("rangeShow() returned error: %v", err)
	}
	if code != 0 {
		t.Errorf("rangeShow() = %d, want 0", code)
	}
	if !strings.Contains(out, config.UpdateRangeShort) {
		t.Errorf("rangeShow() should show %q as the current range, got: %s", config.UpdateRangeShort, out)
	}
	if !strings.Contains(out, "every commit on the branch") {
		t.Errorf("rangeShow() short-range label is missing, got: %s", out)
	}
	if !strings.Contains(out, "solongate range "+config.UpdateRangeLong) {
		t.Errorf("rangeShow() should suggest switching to %q, got: %s", config.UpdateRangeLong, out)
	}
}