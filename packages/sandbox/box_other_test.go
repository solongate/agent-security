// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !linux

package sandbox

import "testing"

func TestBoxAvailableUnsupportedOffLinux(t *testing.T) {
	if err := BoxAvailable(); err == nil {
		t.Error("expected BoxAvailable to refuse off Linux")
	}
}

func TestBoxLaunchUnsupportedOffLinux(t *testing.T) {
	rep, err := BoxLaunch(BoxPlan{}, nil)
	if err == nil {
		t.Error("expected BoxLaunch to refuse off Linux")
	}
	if rep.Err == nil {
		t.Error("expected the report to carry the same error")
	}
}

func TestBoxAgentUnsupportedOffLinux(t *testing.T) {
	if _, _, err := BoxAgent("ls", nil); err == nil {
		t.Error("expected BoxAgent to refuse off Linux")
	}
}

func TestDefaultBoxRuntimeOffLinux(t *testing.T) {
	if got := DefaultBoxRuntime(); got != nil {
		t.Errorf("DefaultBoxRuntime() off Linux = %v, want nil", got)
	}
}
