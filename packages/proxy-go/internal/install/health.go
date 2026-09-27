package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Does the guard actually RUN? Not "is it registered" — that question was
// already answered, and it answered yes for the whole time nothing was enforced.
//
// Every check this CLI had reads a config file. A config file can name a node
// binary that a `brew upgrade` deleted, or a hook that somebody removed, and it
// still reads as "guard registered". The client spawns the command, the spawn
// fails, and the client says nothing: Claude Code does not report a hook that
// could not start. From the outside that is indistinguishable from a machine
// with no guard on it, which is exactly what it is.
//
// So this file produces the two facts no amount of reading a config can:
//
//	HookRuntime  the command in the config, run for real, reaches a node that
//	             executes. Established by running it.
//	Beat         when the client last invoked the hook. Recorded by the launcher
//	             before it does anything else, so it is true even when everything
//	             after it fails.
//
// Together they separate three states that used to look identical: never
// invoked (the client is not calling us), invoked but unable to start (the node
// path is dead), and starting fine but enforcing nothing (a credential problem,
// which the existing checks already cover).

// HookRuntime is what a hook command would actually run with.
type HookRuntime struct {
	OK bool
	// Node is the binary the launcher resolved, when it resolved one.
	Node   string
	Detail string
}

// CheckHookRuntime runs the INSTALLED launcher's own resolution.
//
// It runs the launcher rather than reimplementing its search here. A second copy
// of the candidate list would drift from the first, and the drift would be
// invisible: this check would pass while the thing it stands for failed.
func CheckHookRuntime() HookRuntime {
	p := GlobalPaths()

	if runtime.GOOS == "windows" {
		// Windows names node directly in the command, so the question there is
		// whether that path is still on disk.
		node := nodeFromRegistration(p)
		if node == "" {
			return HookRuntime{Detail: "no node recorded in any registration - run `solongate repair`"}
		}
		return HookRuntime{OK: true, Node: node, Detail: node}
	}

	launcher := filepath.Join(p.HooksDir, LauncherName)
	if !Exists(launcher) {
		return HookRuntime{Detail: "hook launcher missing - run `solongate repair`"}
	}

	cmd := exec.Command("/bin/sh", launcher, "--sg-doctor")
	out, err := cmd.Output()
	if err != nil {
		return HookRuntime{Detail: "launcher found no node runtime - install node, or set SOLONGATE_NODE"}
	}
	node := strings.TrimSpace(string(out))
	if node == "" {
		return HookRuntime{Detail: "launcher found no node runtime - install node, or set SOLONGATE_NODE"}
	}
	return HookRuntime{OK: true, Node: node, Detail: node}
}

// Beat is one hook's record of having been invoked.
type Beat struct {
	Hook string
	At   time.Time
	// Node is what the launcher resolved that time, or "no-node" when it
	// resolved nothing at all.
	Node string
}

// Beats is every hook that has ever run on this machine, most recent first.
func Beats() []Beat {
	dir := filepath.Join(GlobalPaths().SGDir, BeatDirName)
	out := []Beat{}
	for _, hook := range []string{GuardHookName, auditHookName, conversationHookName, stopHookName} {
		f := filepath.Join(dir, hook)
		info, err := os.Stat(f)
		if err != nil {
			continue // never fired, or the beat was removed
		}
		body, _ := os.ReadFile(f)
		out = append(out, Beat{Hook: hook, At: info.ModTime(), Node: strings.TrimSpace(string(body))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out
}

// GuardBeat is the guard's own, which is the one that means a tool call was
// actually judged. Nil when the guard has never run here.
func GuardBeat() *Beat {
	for _, b := range Beats() {
		if b.Hook == GuardHookName {
			return &b
		}
	}
	return nil
}

// Ago is a duration a person reads rather than parses.
func Ago(t time.Time) string {
	s := int(time.Since(t).Seconds())
	if s < 0 {
		s = 0
	}
	switch {
	case s <= 3:
		return "just now"
	case s < 60:
		return strconv.Itoa(s) + "s ago"
	case s < 3600:
		return strconv.Itoa((s+30)/60) + "m ago"
	case s < 86400:
		return strconv.Itoa((s+1800)/3600) + "h ago"
	default:
		return strconv.Itoa((s+43200)/86400) + "d ago"
	}
}
