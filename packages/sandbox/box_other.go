// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sandbox

import "errors"

// The closed box is a Linux mount namespace, and there is no equivalent to fall
// back to.
//
// macOS has no namespaces; its sandbox is Seatbelt, which is a permission layer
// like Landlock, it can refuse a path and cannot remove it. Windows has no
// equivalent either outside a container runtime. Both get `solongate run`,
// which is honest about being the weaker thing.
//
// IT REFUSES RATHER THAN DEGRADING. A closed box that quietly became a
// permission layer would claim more than it does, and the claim is the whole
// product here.

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