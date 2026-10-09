// SPDX-License-Identifier: Apache-2.0

// Confinement the agent cannot talk its way out of.
//
// WHY THIS EXISTS AT ALL. Everything else in SolonGate decides by reading the
// strings in a tool call. That catches `rm game.c` and does not catch
// `find . -name 'game*' -delete`, a base64 pipeline, a script written a moment
// earlier and then run, or a program the agent compiles that calls unlink
// itself. Measured against this build, four of six attempts went straight
// through. The set of ways to name a file without typing its name has no end,
// so no amount of pattern-adding closes it.
//
// What closes it is the kernel, and reaching the kernel means being the
// agent's PARENT. SolonGate has never been that: the guard is a hook the agent
// spawns, judged and then obeyed by the agent's own process. `solongate run`
// inverts it. The confinement is installed before the agent's first
// instruction, every descendant inherits it, and nothing the agent runs can
// take it off.
//
// THE THREE PLATFORMS DO NOT WORK THE SAME WAY and this package does not
// pretend they do. Each file says what it actually gets and what it does not;
// Describe reports it back so the CLI can print the true version rather than
// the flattering one.
package sandbox

import "errors"

// Plan is what the confinement has to achieve.
type Plan struct {
	// Deny are absolute, cleaned paths the child must not be able to read,
	// write or delete. A directory covers everything inside it.
	Deny []string
}

// Report is what a platform actually managed, in enough detail to print.
type Report struct {
	// Mechanism names the kernel feature, so somebody can go and read about it:
	// "Landlock", "Seatbelt", "restricted token", or "" when there is none.
	Mechanism string

	// Enforced is whether the Deny list is actually being enforced by the OS.
	// False means the process ran unconfined and the caller must say so.
	Enforced bool

	// Notes are the true costs and limits of what was applied, one per line.
	// They are printed, not logged: a limit nobody is told about is a limit
	// that gets discovered as a bug.
	Notes []string

	// Err is why nothing was applied.
	Err error
}

// ErrUnsupported is returned by platforms with no implementation.
var ErrUnsupported = errors.New("no OS-level confinement is implemented for this platform")
