package logsserver

// Lifecycle of the local audit-log service as a BACKGROUND service, ported from
// packages/proxy/src/logs-server-daemon.ts.
//
// The desired state lives in ~/.solongate/.logs-server.json and it is the source
// of truth, deliberately separate from whether a process happens to be alive.
// Once enabled — from the dataroom's Settings row, or by running the command —
// the service must keep existing until the user DISABLES it. Closing the
// dataroom, closing the terminal, Ctrl+C and rebooting all kill the process
// without touching the decision, and the next human CLI run brings it back
// (Ensure). Only an explicit stop writes desired "off".
//
// That state file is shared with the npm package, which manages the same
// service through the same fields. Either implementation's CLI can start, stop
// and report a server the other one spawned, and neither may add a field the
// other would drop on its next write.

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// Status is what the service is set to and what it is actually doing. Two
// separate answers, both reported: "enabled, not running" is the state a reboot
// leaves behind and it is the one worth seeing.
type Status struct {
	Desired string // "on" or "off"
	Running bool
	Pid     int
	Port    int
}

// CurrentStatus reads the state file and probes the recorded pid. It touches
// nothing, so it is safe to poll — the dataroom does, every three seconds.
func CurrentStatus() Status {
	s := config.LoadLogsServerState()
	st := Status{Desired: "off", Running: pidAlive(s.Pid), Port: s.Port}
	if s.Desired == "on" {
		st.Desired = "on"
	}
	if st.Running {
		st.Pid = s.Pid
	}
	if st.Port == 0 {
		st.Port = DefaultPort
	}
	return st
}

// recordStarted is called by the server itself once it holds the port.
//
// It rewrites the whole file rather than merging, and it writes desired "on":
// ANY start is an enable. A user who runs the command in the foreground has
// asked for the service, so closing that terminal must not be the same as
// turning it off.
func recordStarted(port int) {
	_ = config.SaveLogsServerState(config.LogsServerState{
		Desired:   "on",
		Pid:       os.Getpid(),
		Port:      port,
		StartedAt: time.Now().UnixMilli(),
	})
}

// Start brings the service up in the background and marks it desired.
//
// Idempotent by design: an already-running service is left alone and only the
// desired flag is refreshed, because restarting it would mean fighting itself
// for the port and reporting the loser as a failed start.
func Start() Status {
	cur := CurrentStatus()
	if cur.Running {
		s := config.LoadLogsServerState()
		s.Desired = "on"
		_ = config.SaveLogsServerState(s)
		cur.Desired = "on"
		return cur
	}

	// Every failure below returns desired "on" with running false, and leaves
	// whatever state was already on disk alone. A start that could not spawn
	// must not look like a stop: the service stays wanted, and the next CLI run
	// tries again.
	failed := Status{Desired: "on", Port: cur.Port}

	exe, err := os.Executable()
	if err != nil {
		return failed
	}
	if err := config.EnsureDir(); err != nil {
		return failed
	}
	// Appended, never truncated. This file is the only record of why a daemon
	// that will not stay up is failing, and a start that wiped it would erase
	// the previous attempt's reason at exactly the moment someone went looking.
	logFile, err := os.OpenFile(config.LogsServerLogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return failed
	}
	defer logFile.Close()

	cmd := exec.Command(exe, "logs-server")
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// Spawned by US, not by an agent. The CLI refuses to run without an
	// interactive terminal, and a detached daemon has none by definition, so
	// without this exemption the service could never start itself.
	cmd.Env = append(os.Environ(), "SOLONGATE_INTERNAL=1")
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return failed
	}
	// Read before Release: releasing the handle clears Pid, and a state file
	// recording -1 would report the service as permanently down.
	pid := cmd.Process.Pid
	// Nothing waits on this child and nothing should — the CLI exits in a
	// moment and the daemon is reparented. Release says that explicitly rather
	// than leaving a handle for a process this one no longer manages.
	_ = cmd.Process.Release()

	_ = config.SaveLogsServerState(config.LogsServerState{
		Desired:   "on",
		Pid:       pid,
		Port:      DefaultPort,
		StartedAt: time.Now().UnixMilli(),
	})
	return Status{Desired: "on", Running: true, Pid: pid, Port: DefaultPort}
}

// Stop kills the process AND disables the service, and the second half is the
// point.
//
// Ensure resurrects anything still marked desired on every human CLI run, so a
// stop that only killed the process would be undone by the next command the
// user typed — the service would look like it refused to stay down. This is the
// only thing in the port that writes desired "off".
func Stop() Status {
	s := config.LoadLogsServerState()
	if pidAlive(s.Pid) {
		if p, err := os.FindProcess(s.Pid); err == nil {
			terminate(p)
		}
	}
	// The port survives so the next start reports the one this device was
	// using. The pid and the start time do not: for a process that is gone they
	// are two more ways for a later reader to be wrong.
	_ = config.SaveLogsServerState(config.LogsServerState{Desired: "off", Port: s.Port})

	port := s.Port
	if port == 0 {
		port = DefaultPort
	}
	return Status{Desired: "off", Port: port}
}

// Ensure resurrects a service that SHOULD be running and is not — after a
// reboot, a Ctrl+C on a foreground run, or a crash.
//
// Called from every human CLI startup. This is the half of the design that
// makes "enabled" outlive the process that was serving, and it is why Stop has
// to disable rather than only kill.
func Ensure() {
	s := CurrentStatus()
	if s.Desired == "on" && !s.Running {
		Start()
	}
}

// pidAlive probes a recorded pid without touching it.
//
// A pid can be recycled, so a very stale entry can read as alive. That is
// accepted here for the same reason the Node implementation accepts it: the
// alternative failure — treating a live server as dead — starts a second one
// that cannot bind, and reports the working service as broken.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Windows FindProcess opens a handle and fails when the process is gone,
	// which is the whole answer; everywhere else it always succeeds and signal 0
	// is what actually tests for existence.
	if runtime.GOOS == "windows" {
		return true
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	// EPERM means the pid exists and belongs to someone else. It still holds
	// the port, so reporting it dead would have the next run try to start a
	// server that cannot bind.
	return errors.Is(err, os.ErrPermission)
}
