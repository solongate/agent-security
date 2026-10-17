// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !linux && !darwin && !windows

package sandbox

func Launch(p Plan, argv []string, env []string) (Report, error) {
	return Report{Err: ErrUnsupported}, ErrUnsupported
}

func Preview(p Plan) []string { return nil }

func Describe() (string, []string) {
	return "", []string{"no OS-level confinement is implemented for this platform"}
}