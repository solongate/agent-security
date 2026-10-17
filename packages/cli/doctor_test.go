// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"context"
	"strings"
	"testing"
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
		code, err := runDoctor(context.Background(), nil, parse([]string{arg}))
		if err != nil {
			t.Fatalf("runDoctor(%q) returned error: %v", arg, err)
		}
		if code != 0 {
			t.Errorf("runDoctor(%q) returned code %d, want 0", arg, code)
		}
	}
}

func TestRunDoctorUnknownSub(t *testing.T) {
	code, err := runDoctor(context.Background(), nil, parse([]string{"foobar"}))
	if err != nil {
		t.Fatalf("runDoctor(foobar) returned error: %v", err)
	}
	if code != 1 {
		t.Errorf("runDoctor(foobar) returned code %d, want 1", code)
	}
}
