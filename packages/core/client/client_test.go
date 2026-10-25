// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

import "testing"

func TestErrorError(t *testing.T) {
	err := &Error{Code: "denied", Message: "nope", Status: 403}
	if got := err.Error(); got != "nope" {
		t.Errorf("Error()=%q, want %q", got, "nope")
	}
}

func TestNewWiresEveryResourceBackToTheClient(t *testing.T) {
	c := New()
	if c.Policies.c != c {
		t.Error("Policies does not point back to the client that made it")
	}
	if c.Settings.c != c {
		t.Error("Settings does not point back to the client that made it")
	}
	if c.Stats.c != c {
		t.Error("Stats does not point back to the client that made it")
	}
	if c.Audit.c != c {
		t.Error("Audit does not point back to the client that made it")
	}
}