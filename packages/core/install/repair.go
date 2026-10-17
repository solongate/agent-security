// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/solongate/agent-security/packages/core/config"
)

type ReportLine struct {
	Label  string
	OK     bool
	Detail string
}

type Report struct {
	OK      bool
	Message string
	Before  []ReportLine
	After   []ReportLine
	Notes   []string
}

func reportLine(label string, ok bool, yes, no string) ReportLine {
	detail := no
	if ok {
		detail = yes
	}
	return ReportLine{Label: label, OK: ok, Detail: detail}
}

func Repair() Report {
	p := GlobalPaths()

	runtime := func() ReportLine {
		rt := CheckHookRuntime()
		detail := rt.Detail
		if rt.OK {
			detail = "node " + detail
		}
		return ReportLine{Label: "hook runtime", OK: rt.OK, Detail: detail}
	}

	before := []ReportLine{
		reportLine("guard hook file", Exists(p.GuardPath()), "present", "MISSING"),

		runtime(),
		reportLine("Claude hooks", ClaudeGuardInstalled(), "guard registered", "guard NOT registered"),
		reportLine("Antigravity hooks", Exists(p.AntigravityHooksPath), "guard registered", "guard NOT registered"),
		reportLine("Codex hooks", CodexGuardInstalled(), "guard registered", "guard NOT registered"),
		reportLine("OpenCode hooks", OpencodeGuardInstalled(), "guard registered", "guard NOT registered"),
	}

	r := Install()
	if !r.OK {
		return Report{Message: r.Message, Before: before}
	}

	version := "?"
	if v := InstalledGuardVersion(); v != nil {
		version = strconv.Itoa(*v)
	}
	after := []ReportLine{
		{Label: "guard hook file", OK: true, Detail: "present (v" + version + ")"},
		runtime(),
		reportLine("Claude hooks", ClaudeGuardInstalled(), "guard registered", "NOT registered"),
		reportLine("Antigravity hooks", Exists(p.AntigravityHooksPath), "guard registered", "NOT registered"),
		reportLine("Codex hooks", CodexGuardInstalled(), "guard registered", "NOT registered"),
		reportLine("OpenCode hooks", OpencodeGuardInstalled(), "guard registered", "NOT registered"),
	}

	notes := append([]string{}, r.Notes...)

	if swept := SweepStrayScratchDirs(p.Home); swept > 0 {
		notes = append(notes, "Removed "+strconv.Itoa(swept)+
			" leftover .solongate scratch folder(s) from earlier versions; per-call flags now live under ~/.solongate/projects.")
	}

	for _, name := range []string{"accounts.json", "cloud-guard.json"} {
		stale := filepath.Join(p.SGDir, name)
		if !Exists(stale) {
			continue
		}
		err := os.Remove(stale)
		if err != nil {

			config.UnlockFile(stale)
			err = os.Remove(stale)
		}
		if err == nil {
			notes = append(notes, "Removed "+stale+", left over from when this product had accounts. "+
				"It held an API key: revoke that key at whatever issued it, because deleting the file does not.")
		} else {
			notes = append(notes, "Could not remove "+stale+" ("+err.Error()+"). "+
				"It is left over from when this product had accounts and holds an API key; "+
				"delete it and revoke the key.")
		}
	}

	cx := CodexHooksStatus()
	if cx.Registered && !cx.Trusted {
		notes = append(notes, "Codex only: run `/hooks` inside Codex once and trust the SolonGate hooks (Codex skips any hook it has not been told to trust).")
	}
	if cx.Disabled {
		notes = append(notes, "Codex only: hooks are turned OFF in ~/.codex/config.toml ([features] hooks = false). The guard cannot run there until that line is removed.")
	}

	return Report{
		OK:      true,
		Message: "guard repaired.",
		Before:  before,
		After:   after,
		Notes:   notes,
	}
}

var scratchFiles = map[string]bool{
	".eval-ring.jsonl": true,
	".last-eval":       true,
	".last-deny":       true,
	".last-tool-call":  true,
	".debug-guard-log": true,
}

const (
	scratchMaxDepth = 6

	scratchBudget = 40000
)

func SweepStrayScratchDirs(root string) int {
	return sweepScratch(root, scratchMaxDepth, scratchBudget)
}

func sweepScratch(root string, maxDepth, budget int) int {
	removed := 0
	visited := 0
	skip := map[string]bool{"node_modules": true, ".git": true, "dist": true, ".next": true, "build": true}

	store := GlobalPaths().SGDir

	protected := map[string]bool{}
	if runtime.GOOS == "darwin" {
		for _, n := range []string{"Desktop", "Documents", "Downloads", "Movies", "Music", "Pictures", "Public", "Library", "Applications"} {
			protected[filepath.Join(root, n)] = true
		}
	}

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxDepth {
			return
		}

		seen := visited
		visited++
		if seen > budget {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			name := e.Name()
			if skip[name] {
				continue
			}
			full := filepath.Join(dir, name)
			if full == store || protected[full] {
				continue
			}

			info, err := os.Stat(full)
			if err != nil || !info.IsDir() {
				continue
			}
			if name == ".solongate" {
				if sweepOne(full) {
					removed++
				}
				continue
			}
			walk(full, depth+1)
		}
	}
	walk(root, 0)
	return removed
}

func sweepOne(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	left := 0
	for _, e := range entries {
		if !scratchFiles[e.Name()] {
			left++
			continue
		}
		if os.Remove(filepath.Join(dir, e.Name())) != nil {
			left++
		}
	}
	if left != 0 {
		return false
	}
	return os.Remove(dir) == nil
}