// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !linux

package sandbox

import "errors"

var errNoBox = errors.New("the closed box needs a Linux mount namespace, which this platform does not have. " +
	"`solongate run` applies the strongest confinement available here instead")

func BoxAvailable() error { return errNoBox }

func BoxLaunch(p BoxPlan, env []string) (Report, error) {
	return Report{Err: errNoBox}, errNoBox
}

func BoxAgent(name string, argv []string) (string, []string, error) {
	return "", nil, errNoBox
}

func DefaultBoxRuntime() []string { return nil }