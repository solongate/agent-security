//go:build !windows

package selfupdate

import (
	"os/exec"
	"syscall"
)

// Put the install in its own session so it outlives this process. The whole
// point of the background updater is that the command the user actually ran
// returns at once and the install finishes on its own; without this the CLI's
// exit takes the install down with it, part-way through replacing a package.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
