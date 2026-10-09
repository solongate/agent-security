// SPDX-License-Identifier: Apache-2.0

//go:build windows

package install

import (
	"os/exec"
	"syscall"
)

// Windows has no sessions; the equivalent is a new process group with no
// console, so the policy-warm child neither dies with this process nor flashes a
// window at someone watching an install.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000008 | 0x00000200, // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
		HideWindow:    true,
	}
}
