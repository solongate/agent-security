// SPDX-License-Identifier: Apache-2.0

package shared

import "os"

// SandboxEnv is set by `solongate run` on the process it launches, and
// inherited by everything that process starts.
//
// IT IS A REPORT, NOT A MECHANISM, and the distinction matters because an
// agent can obviously set an environment variable. Setting it gains nothing:
// the variable does not confine anything. The confinement is the Landlock
// domain, the Seatbelt profile or the restricted token, applied before the
// agent's first instruction and impossible for it to drop. A lying agent is
// one that claims to be inside a box it is in fact inside, because the only
// way to be outside the box is to have been started outside it, and then
// `requireSandbox` refuses the call on the strength of the variable's absence.
//
// The value is the SolonGate version that applied the confinement, so a
// machine running two builds can tell which one a call came through.
const SandboxEnv = "SOLONGATE_SANDBOX"

// InSandbox reports whether this process was started inside a SolonGate
// confinement.
func InSandbox() bool { return os.Getenv(SandboxEnv) != "" }
