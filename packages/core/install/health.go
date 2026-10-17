// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

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

type HookRuntime struct {
	OK bool

	Node   string
	Detail string
}

func CheckHookRuntime() HookRuntime {
	p := GlobalPaths()

	if runtime.GOOS == "windows" {

		node := nodeFromRegistration(p)
		if node == "" {
			return HookRuntime{Detail: "no node recorded in any registration, run `solongate repair`"}
		}
		return HookRuntime{OK: true, Node: node, Detail: node}
	}

	launcher := filepath.Join(p.HooksDir, LauncherName)
	if !Exists(launcher) {
		return HookRuntime{Detail: "hook launcher missing, run `solongate repair`"}
	}

	cmd := exec.Command("/bin/sh", launcher, "--sg-doctor")
	out, err := cmd.Output()
	if err != nil {
		return HookRuntime{Detail: "launcher found no node runtime, install node, or set SOLONGATE_NODE"}
	}
	node := strings.TrimSpace(string(out))
	if node == "" {
		return HookRuntime{Detail: "launcher found no node runtime, install node, or set SOLONGATE_NODE"}
	}
	return HookRuntime{OK: true, Node: node, Detail: node}
}

type Beat struct {
	Hook string
	At   time.Time

	Node string
}

func Beats() []Beat {
	dir := filepath.Join(GlobalPaths().SGDir, BeatDirName)
	out := []Beat{}
	for _, hook := range []string{GuardHookName, auditHookName, tokensHookName, stopHookName} {
		f := filepath.Join(dir, hook)
		info, err := os.Stat(f)
		if err != nil {
			continue
		}
		body, _ := os.ReadFile(f)
		out = append(out, Beat{Hook: hook, At: info.ModTime(), Node: strings.TrimSpace(string(body))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out
}

func GuardBeat() *Beat {
	for _, b := range Beats() {
		if b.Hook == GuardHookName {
			return &b
		}
	}
	return nil
}

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