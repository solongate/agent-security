// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// Put the child in its own session so it outlives this process. Without it the
// parent's exit can take the audit POST down with it, and the whole point of
// detaching was to keep the record while giving the agent its verdict at once.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
