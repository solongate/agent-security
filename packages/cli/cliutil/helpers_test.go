// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cliutil

import (
	"bytes"
	"strings"
	"testing"
)

func TestUsageErr(t *testing.T) {
	orig := stderr
	var buf bytes.Buffer
	stderr = &buf
	defer func() { stderr = orig }()

	code, err := UsageErr("something went wrong")
	if code != 1 || err != nil {
		t.Errorf("UsageErr = %d, %v, want 1, nil", code, err)
	}
	if !strings.Contains(buf.String(), "something went wrong") {
		t.Errorf("UsageErr output = %q, want it to contain the message", buf.String())
	}
}

func TestOkf(t *testing.T) {
	orig := stderr
	var buf bytes.Buffer
	stderr = &buf
	defer func() { stderr = orig }()

	Okf("saved %d items", 3)
	got := buf.String()
	if !strings.Contains(got, "saved 3 items") {
		t.Errorf("Okf output = %q, want it to contain the formatted message", got)
	}
	if !strings.Contains(got, "✓") {
		t.Errorf("Okf output = %q, want it to contain a check mark", got)
	}
}