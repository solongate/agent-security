//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// Windows has no sessions; the equivalent is a new process group with no
// console, so the child neither dies with the parent nor flashes a window.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000008 | 0x00000200, // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
		HideWindow:    true,
	}
}
