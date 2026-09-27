//go:build !windows

package install

import (
	"os/exec"
	"syscall"
)

// Put the policy-warm child in its own session so it outlives this process.
// Without it, the CLI exiting can take the refresh down with it, and the point
// of warming the cache was that the client's first tool call finds a policy
// already there.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
