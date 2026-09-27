//go:build windows

package logsserver

import (
	"os"
	"os/exec"
	"syscall"
)

// Windows has no sessions; the equivalent is a detached process in its own
// group with no console, so the service neither dies with the terminal that
// started it nor flashes a window on every CLI run that resurrects it.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000008 | 0x00000200, // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
		HideWindow:    true,
	}
}

// There is no SIGTERM to send here: os.Process.Signal refuses it on Windows,
// and Node's process.kill() ends up in TerminateProcess on this platform too,
// so this is the same stop the other implementation performs.
func terminate(p *os.Process) { _ = p.Kill() }
