// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package maintenance

import (
	"context"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/cli/cliutil"
)

func TestDoctorUsage(t *testing.T) {
	u := doctorUsage()
	if !strings.Contains(u, "solongate doctor") {
		t.Errorf("doctorUsage() should mention solongate doctor, got: %s", u)
	}
	if !strings.Contains(u, "--json") {
		t.Errorf("doctorUsage() should mention --json, got: %s", u)
	}
}

func TestRunDoctorHelp(t *testing.T) {
	for _, arg := range []string{"help", "-h"} {
		code, err := RunDoctor(context.Background(), nil, cliutil.Parse([]string{arg}))
		if err != nil {
			t.Fatalf("RunDoctor(%q) returned error: %v", arg, err)
		}
		if code != 0 {
			t.Errorf("RunDoctor(%q) returned code %d, want 0", arg, code)
		}
	}
}

func TestRunDoctorUnknownSub(t *testing.T) {
	code, err := RunDoctor(context.Background(), nil, cliutil.Parse([]string{"foobar"}))
	if err != nil {
		t.Fatalf("RunDoctor(foobar) returned error: %v", err)
	}
	if code != 1 {
		t.Errorf("RunDoctor(foobar) returned code %d, want 1", code)
	}
}
