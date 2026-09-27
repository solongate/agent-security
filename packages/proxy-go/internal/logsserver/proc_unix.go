//go:build !windows

package logsserver

import (
	"os"
	"os/exec"
	"syscall"
)

// The daemon has to outlive the terminal that started it, so it gets its own
// session instead of staying in the CLI's process group. Without this a Ctrl+C
// or a closed terminal takes the service down with the shell — and surviving
// both is the entire reason it is a service rather than a foreground command.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// SIGTERM, which is what Node's process.kill(pid) sends, so a server started by
// one implementation is stopped the same way by the other. The service holds
// nothing that needs flushing, and a polite signal leaves a wedged process
// visible rather than papering over it.
func terminate(p *os.Process) { _ = p.Signal(syscall.SIGTERM) }
