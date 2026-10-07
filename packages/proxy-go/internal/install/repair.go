// SPDX-License-Identifier: Apache-2.0

package install

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// `solongate repair` — put the guard back after tampering or deletion.
//
// It reports what was missing, rewrites every protection file, re-registers the
// hooks in all four clients and re-locks. The logged-in account is reused, so
// nothing has to be paired again.

// ReportLine is one row of the before/after listing.
type ReportLine struct {
	Label  string
	OK     bool
	Detail string
}

// Report is the whole repair, with no printing in it — the same restore backs
// `solongate repair` and the dataroom's Settings panel, and the dataroom owns
// the terminal while it is up.
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

// Repair runs the restore and returns what it found and what it fixed.
func Repair() Report {
	p := GlobalPaths()

	// The runtime line is the one that matters on a Mac. Every other line in
	// this report reads a config file, and a config file said the guard was
	// registered for the whole time it could not start.
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
		// There was a `cloud credential` row here. It reported MISSING on every
		// machine — nothing writes one — which is a red line on a healthy install,
		// and a report with a permanent red line in it stops being read.
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
	// Older versions kept per-call scratch next to the user's code. The guard
	// clears the one in its own working directory, but a folder no agent visits
	// again would keep it forever — so repair goes and looks.
	if swept := SweepStrayScratchDirs(p.Home); swept > 0 {
		notes = append(notes, "Removed "+strconv.Itoa(swept)+
			" leftover .solongate scratch folder(s) from earlier versions; per-call flags now live under ~/.solongate/projects.")
	}
	cx := CodexHooksStatus()
	if cx.Registered && !cx.Trusted {
		notes = append(notes, "Codex only: run `/hooks` inside Codex once and trust the SolonGate hooks (Codex skips any hook it has not been told to trust).")
	}
	if cx.Disabled {
		notes = append(notes, "Codex only: hooks are turned OFF in ~/.codex/config.toml ([features] hooks = false) - the guard cannot run there until that line is removed.")
	}

	return Report{
		OK:      true,
		Message: "guard repaired. Open a new AI session for it to take effect.",
		Before:  before,
		After:   after,
		Notes:   notes,
	}
}

// ── the stray scratch sweep ──────────────────────────────────────────────────

// Files older versions wrote next to the user's code. Nothing else in a folder
// of that name is ours, and that distinction is the whole safety of the sweep.
var scratchFiles = map[string]bool{
	".eval-ring.jsonl": true,
	".last-eval":       true,
	".last-deny":       true,
	".last-tool-call":  true,
	".debug-guard-log": true,
}

const (
	// Depth 6 because a monorepo puts real working directories four or five
	// levels down (…/repo/apps/web/src).
	scratchMaxDepth = 6
	// High enough that one big repo early in the walk cannot use the whole budget
	// before the rest of home is reached — which is exactly what a smaller one
	// did. Only ever runs on an explicit repair.
	scratchBudget = 40000
)

// SweepStrayScratchDirs clears the ./.solongate/ folders older versions
// scattered around.
//
// The guard used to keep its per-call flags next to the user's code, so one of
// these was left in every directory an agent had ever run in — config folders
// and dotfile repos included. The guard now sweeps the folder in its own working
// directory, which heals anywhere an agent goes again; somewhere like
// ~/.config/ags may never be visited twice, so repair goes looking.
//
// Deliberately narrow: only our own filenames are removed, only a directory that
// empties as a result is taken, and the walk is bounded in depth and in how many
// directories it will visit. Anything unexpected inside is left alone and the
// folder stays.
func SweepStrayScratchDirs(root string) int {
	return sweepScratch(root, scratchMaxDepth, scratchBudget)
}

func sweepScratch(root string, maxDepth, budget int) int {
	removed := 0
	visited := 0
	skip := map[string]bool{"node_modules": true, ".git": true, "dist": true, ".next": true, "build": true}
	// The real store, which must never be a candidate. Excluded by PATH, not by
	// name — excluding the name would skip every folder the sweep came for.
	store := GlobalPaths().SGDir

	// macOS TCC-protected personal folders, skipped by full path so the sweep
	// never descends into them. Walking in makes the OS raise a permission
	// prompt - Desktop, Documents, Downloads, the media library under Music, the
	// Photos library under Pictures, iCloud Drive and third-party cloud mounts
	// under Library - and each one BLOCKS THE SWEEP until somebody answers it:
	// a dozen dialogs asking for access to a person's photos, raised by a
	// security tool, in the middle of tidying up legacy scratch files.
	//
	// Stray scratch never lived in these anyway - it was left beside a user's
	// code. By full path, not by name, so a project directory deeper down that
	// merely shares one of these names is still swept. Only on darwin, which is
	// where the prompts are.
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
		// The budget counts directories ENTERED, and it is spent before the check,
		// so a walk that reaches it stops rather than finishing the level it is on.
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
			// Stat rather than Lstat, matching Node's statSync: a symlinked repo is
			// walked, and the depth and budget are what keep that bounded.
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

// sweepOne empties one stray folder and reports whether it could be removed.
// A file that is not ours, or one that will not delete, means the folder stays.
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
