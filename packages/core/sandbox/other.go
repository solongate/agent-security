// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !windows

package sandbox

// Everything SolonGate does not ship a binary for.
//
// IT REFUSES RATHER THAN RUNNING UNCONFINED. Every other fallback in this
// product fails open, because a hardening step that cannot run should not stop
// the thing it was hardening. This one is the opposite: the entire promise of
// `solongate run` is that the agent is confined, and a command that silently
// ran it loose would be the most expensive kind of wrong, which is the kind
// that looks like it worked.

func Launch(p Plan, argv []string, env []string) (Report, error) {
	return Report{Err: ErrUnsupported}, ErrUnsupported
}

func Preview(p Plan) []string { return nil }

func Describe() (string, []string) {
	return "", []string{"no OS-level confinement is implemented for this platform"}
}
