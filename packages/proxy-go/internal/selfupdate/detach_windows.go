//go:build windows

package selfupdate

import (
	"os/exec"
	"syscall"
)

// Windows has no sessions; the equivalent is a detached process in its own
// group, with no console, so the install neither dies with the CLI nor flashes a
// window over whatever the user is doing.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000008 | 0x00000200, // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
		HideWindow:    true,
	}
}
