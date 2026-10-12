// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"os"
	"path/filepath"
	"strings"
)

// SandboxEnv is set by `solongate run` and `solongate sandbox` on the process
// they launch, and inherited by everything that process starts.
//
// IT IS A REPORT, NOT A MECHANISM. An agent can obviously set an environment
// variable, and the variable confines nothing: the confinement is the Landlock
// domain, the Seatbelt profile, the restricted token or the mount namespace,
// applied before the agent's first instruction and impossible for it to drop.
//
// THE ARGUMENT THAT USED TO BE HERE WAS NOT ENOUGH, and it is worth writing
// down why. It said a lying agent gains nothing, because the only way to be
// outside the box is to have been started outside it. That is true of the
// confinement and false of the CHECK: `requireSandbox` refused a call on the
// strength of this variable's absence, so an agent that exported it was not
// confined and was not refused either. One line in a shell profile, inherited
// by every agent the machine ever starts, and the fail-closed switch fails
// open. See VerifiedInSandbox.
const SandboxEnv = "SOLONGATE_SANDBOX"

// The value carries WHICH confinement applied it, because the two are verified
// differently and a check that cannot tell them apart can only verify the
// weaker one. Everything after the colon is the SolonGate version, so a machine
// running two builds can still tell which one a call came through.
const (
	SandboxModeRun = "run"
	SandboxModeBox = "box"
)

// SandboxMarker is the value to set, for the mode that applied the confinement.
func SandboxMarker(mode, version string) string { return mode + ":" + version }

// InSandbox reports whether the marker is present at all.
//
// THE UNVERIFIED ANSWER, kept because two callers want exactly that: the eval
// record stamps what the call claimed, and `doctor` reports the claim beside
// whether it held. Nothing that REFUSES a call may use this — see
// VerifiedInSandbox.
func InSandbox() bool { return os.Getenv(SandboxEnv) != "" }

// SandboxMode is the mode from the marker, or "" when there is none.
func SandboxMode() string {
	v := os.Getenv(SandboxEnv)
	if v == "" {
		return ""
	}
	if i := strings.IndexByte(v, ':'); i >= 0 {
		return v[:i]
	}
	// A marker from a build that wrote only the version. Treated as `run`,
	// which is the weaker of the two and therefore the safe reading.
	return SandboxModeRun
}

// VerifiedInSandbox asks the KERNEL, not the environment, and is what a
// refusal may rest on.
//
// It returns whether the process is confined and whether the answer is worth
// anything. An inconclusive answer is not a yes: the caller fails closed on it,
// because "I could not tell" and "it is confined" are different sentences and
// only one of them should let a call through on a machine whose owner asked for
// confinement to be mandatory.
//
// THE TWO PROBES, and each is a fact about this process that an agent cannot
// produce by writing to its own environment:
//
//	box  /proc/1/comm is the box's own init. A mount namespace gives the
//	     process its own /proc, in which PID 1 is bwrap rather than the host's
//	     systemd. Faking it means being PID 1 in a namespace, which means being
//	     in one — and a namespace an agent built for itself grants it nothing it
//	     did not already have.
//
//	run  a protected path cannot be opened for reading. Outside the Landlock
//	     domain it can: `solongate protect` locks against writing and deleting,
//	     and both chattr +i and chmod 0444 leave a file readable. Inside, the
//	     path has no rule and open() returns EACCES. So a successful read is
//	     proof the confinement is not on, which is the direction that matters.
//
// WHAT IS INCONCLUSIVE, stated rather than discovered: `run` with no protected
// paths has nothing to probe against, and a protected path that does not exist
// on disk is skipped. A machine in that state gets "could not tell", and
// require-sandbox refuses — which is the switch doing what its name says.
func VerifiedInSandbox(protectedPaths []string) (confined, conclusive bool) {
	switch SandboxMode() {
	case "":
		// No marker. Not confined by us, and that is conclusive: both launchers
		// set it, so its absence means neither ran.
		return false, true

	case SandboxModeBox:
		b, err := os.ReadFile("/proc/1/comm")
		if err != nil {
			// No /proc to ask. On Linux that is itself odd; anywhere else the
			// box cannot have applied, so the marker is already wrong.
			return false, false
		}
		init := strings.TrimSpace(string(b))
		switch init {
		case "systemd", "init", "launchd":
			// The host's init is PID 1, so this process shares the host's pid
			// namespace and no box was built.
			return false, true
		case "":
			return false, false
		default:
			return true, true
		}

	default:
		for _, p := range protectedPaths {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			f, err := os.Open(filepath.Clean(p))
			if err == nil {
				// Readable, so nothing is standing between this process and the
				// path somebody protected. The marker is a lie.
				_ = f.Close()
				return false, true
			}
			if os.IsNotExist(err) {
				continue // nothing to learn from a path that is not there
			}
			// Unreadable. Inside the domain that is what it should be; the
			// path's own permissions could also produce it, so this is taken as
			// a yes only because the launcher set the marker as well.
			return true, true
		}
		return false, false
	}
}
