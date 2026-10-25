// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !linux && !darwin && !windows

package sandbox

import "testing"

func TestOtherPlatformLaunchIsUnsupported(t *testing.T) {
	_, err := Launch(Plan{}, []string{"true"}, nil)
	if err != ErrUnsupported {
		t.Errorf("Launch() err = %v, want ErrUnsupported", err)
	}
}

func TestOtherPlatformPreviewAndDescribe(t *testing.T) {
	if got := Preview(Plan{}); got != nil {
		t.Errorf("Preview() = %v, want nil", got)
	}
	mech, notes := Describe()
	if mech != "" {
		t.Errorf("Describe() mechanism = %q, want empty", mech)
	}
	if len(notes) == 0 {
		t.Error("expected a note explaining there is no confinement here")
	}
}
