// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package maintenance

import (
	"context"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/health"
)

// wantFailCount runs the same health checks RunDoctor runs internally, so
// tests assert against what a fresh, isolated home actually reports instead
// of a guessed check count.
func wantFailCount(ctx context.Context, c *client.Client) int {
	n := 0
	for _, ch := range health.CollectChecks(ctx, c) {
		if ch.OK == health.StateFail {
			n++
		}
	}
	return n
}

func TestRunDoctorPlainTextRunsHealthChecks(t *testing.T) {
	newHome(t)
	ctx := context.Background()
	c := client.New()
	wantFail := wantFailCount(ctx, c)

	var code int
	var err error
	out := captureStderrFD(t, func() {
		code, err = RunDoctor(ctx, c, cliutil.Parse(nil))
	})
	if err != nil {
		t.Fatalf("RunDoctor() returned error: %v", err)
	}

	wantCode := 0
	if wantFail > 0 {
		wantCode = 1
	}
	if code != wantCode {
		t.Errorf("RunDoctor() = %d, want %d (health reported %d failing check(s))", code, wantCode, wantFail)
	}
	if !strings.Contains(out, "SolonGate doctor") {
		t.Errorf("RunDoctor() output missing the banner, got: %s", out)
	}
	switch {
	case wantFail > 0 && !strings.Contains(out, "problem"):
		t.Errorf("RunDoctor() output should mention problems when a check fails, got: %s", out)
	case wantFail == 0 && strings.Contains(out, "problem"):
		t.Errorf("RunDoctor() output mentions problems when nothing failed, got: %s", out)
	}
}

func TestRunDoctorJSONMatchesPlainTextReturnCode(t *testing.T) {
	newHome(t)
	ctx := context.Background()
	c := client.New()
	wantFail := wantFailCount(ctx, c)

	code, err := RunDoctor(ctx, c, cliutil.Parse([]string{"--json"}))
	if err != nil {
		t.Fatalf("RunDoctor(--json) returned error: %v", err)
	}

	wantCode := 0
	if wantFail > 0 {
		wantCode = 1
	}
	if code != wantCode {
		t.Errorf("RunDoctor(--json) = %d, want %d (health reported %d failing check(s))", code, wantCode, wantFail)
	}
}