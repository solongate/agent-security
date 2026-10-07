// SPDX-License-Identifier: Apache-2.0

// solongate-audit reads the AI transcripts already on this machine and grades
// what they show against the OWASP Agentic Top 10.
//
// It is the Go build of the `solongate-audit` bin from @solongate/proxy. The
// npm package keeps that name and keeps working; this is a second
// implementation beside it, writing the same report files with the same names
// and the same columns.
//
// Two things worth knowing before changing this file:
//
//   - This is NOT the PostToolUse hook. That hook is
//     packages/proxy/hooks/audit.mjs, a self-contained file that shares no code
//     with src/audit and runs on every single tool call. This binary is a
//     report a person runs; it reads a lot of disk and takes as long as it
//     takes.
//   - Unlike `solongate`, this command is not gated to humans, and that matches
//     the npm bin. The gate exists because the main CLI edits security policy;
//     this one only reads transcripts and writes a report, so gating it would
//     block a CI job from producing an audit without protecting anything.
package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/auditscan"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	// The flags are matched by presence anywhere in the argument list rather
	// than parsed positionally, which is what the npm tool does and what any
	// existing invocation of it relies on.
	if idx := indexOf(args, "--add-dir"); idx >= 0 {
		dir := argAt(args, idx+1)
		if dir == "" {
			fmt.Println("  Usage: solongate-audit --add-dir <path>")
			return 1
		}
		auditscan.AddDir(dir)
		return 0
	}

	if idx := indexOf(args, "--remove-dir"); idx >= 0 {
		dir := argAt(args, idx+1)
		if dir == "" {
			fmt.Println("  Usage: solongate-audit --remove-dir <path>")
			return 1
		}
		auditscan.RemoveDir(dir)
		return 0
	}

	if has(args, "--list-dirs") {
		auditscan.ListDirs()
		return 0
	}
	if has(args, "--search") {
		auditscan.SearchLogs()
		return 0
	}
	if has(args, "--help") || has(args, "-h") {
		printHelp()
		return 0
	}

	showDetailed := has(args, "--detailed") || has(args, "-d")
	showJSON := has(args, "--json")
	showWatch := has(args, "--watch") || has(args, "-w")
	showLogs := has(args, "--logs") || has(args, "-l")
	showExport := has(args, "--export") || has(args, "-e")

	if showExport {
		idx := indexOf(args, "--export")
		if idx < 0 {
			idx = indexOf(args, "-e")
		}
		format := argAt(args, idx+1)
		if format == "" || strings.HasPrefix(format, "-") {
			fmt.Println("  Usage: solongate-audit --export <json|csv|html|pdf|all>")
			return 1
		}
		data, results, _ := runAudit(false)
		printReport(data, results, showDetailed)
		return auditscan.RunExport(format, auditscan.ExportPayload{Data: data, Results: results})
	}

	if showWatch {
		return runWatch(showDetailed)
	}

	if showLogs {
		data, _, _ := runAudit(false)
		auditscan.PrintHeader()
		auditscan.PrintLogSummary(data)
		auditscan.PrintLogs(data, logLimit(args), true)
		return 0
	}

	data, results, intScore := runAudit(showJSON)

	if showJSON {
		out, err := auditscan.MachineReport(data, results, intScore)
		if err != nil {
			fmt.Fprintln(os.Stderr, "  Could not encode the report:", err)
			return 1
		}
		fmt.Println(out)
	} else {
		printReport(data, results, showDetailed)
	}

	// A score of 7 is the pass mark, and a non-zero exit is what makes this
	// usable as a CI gate.
	if intScore >= 7 {
		return 0
	}
	return 1
}

// runAudit does the scan. The spinner is suppressed for --json so nothing but
// JSON reaches stdout.
func runAudit(silent bool) (*auditscan.AuditData, []auditscan.CheckResult, int) {
	var spinner *auditscan.Spinner
	if !silent {
		spinner = auditscan.NewSpinner("Scanning AI tool logs...").Start()
	}

	data := auditscan.CollectLogs()
	if spinner != nil {
		spinner.Update("Running OWASP Agentic Top 10 checks...")
	}

	results := auditscan.RunAllChecks(data)
	intScore, _ := auditscan.CalcScore(results)

	if spinner != nil {
		spinner.Stop(fmt.Sprintf("Scanned %d tool calls across %d sessions",
			data.TotalToolCalls, len(data.Sessions)))
	}
	return data, results, intScore
}

func printReport(data *auditscan.AuditData, results []auditscan.CheckResult, detailed bool) {
	auditscan.PrintHeader()
	auditscan.PrintLogSummary(data)
	auditscan.PrintCompactReport(results)
	auditscan.PrintScore(results)
	if detailed {
		auditscan.PrintDetailedReport(results)
		auditscan.PrintFooter(results)
	}
}

// ── watch ──────────────────────────────────────────────────────────────────

// runWatch prints the report once and then polls for new calls.
//
// Polling, not a filesystem watcher: four clients write to four directory trees
// on three operating systems, and a missed inotify registration would show a
// live feed that silently stopped. Re-reading every two seconds cannot go
// stale.
func runWatch(detailed bool) int {
	seen := map[string]bool{}

	data, results, _ := runAudit(false)
	lastToolCount := data.TotalToolCalls
	lastSessionCount := len(data.Sessions)
	for _, tc := range data.AllCalls() {
		seen[tc.ID+tc.Timestamp] = true
	}

	fmt.Print("\x1b[2J\x1b[H")
	printReport(data, results, detailed)

	allCalls := sortedByTimestamp(data)
	last10 := allCalls
	if len(last10) > 10 {
		last10 = last10[len(last10)-10:]
	}

	fmt.Println("")
	fmt.Println(auditscan.Bold("  Live Log Feed"))
	fmt.Println(auditscan.Dim("  " + strings.Repeat("─", 80)))
	fmt.Println(auditscan.Dim("  Time     Source Tool              Arguments"))
	fmt.Println(auditscan.Dim("  " + strings.Repeat("─", 80)))

	for _, tc := range last10 {
		auditscan.PrintToolCall(tc, true, "")
	}

	fmt.Println("")
	fmt.Println(auditscan.Dim("  Waiting for new tool calls..."))

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		data, _, intScore := runAudit(true)
		if data.TotalToolCalls == lastToolCount && len(data.Sessions) == lastSessionCount {
			continue
		}

		var newCalls []*auditscan.ToolCall
		for _, tc := range sortedByTimestamp(data) {
			if !seen[tc.ID+tc.Timestamp] {
				newCalls = append(newCalls, tc)
			}
		}

		if len(newCalls) > 0 {
			// Erase the line above before appending. On the first update that
			// is the "Waiting for new tool calls..." line; afterwards it is the
			// previous batch's summary. The npm tool behaves the same way and
			// the feed reads correctly either way.
			fmt.Print("\x1b[1A\x1b[2K")

			for _, tc := range newCalls {
				seen[tc.ID+tc.Timestamp] = true
				auditscan.PrintToolCall(tc, true, "")
			}

			errorCount := 0
			for _, tc := range data.AllCalls() {
				if tc.Errored() {
					errorCount++
				}
			}
			fmt.Println("")
			fmt.Println(auditscan.Dim(fmt.Sprintf("  %d calls | %d sessions | %d errors | Score: %d/10 | LIVE",
				data.TotalToolCalls, len(data.Sessions), errorCount, intScore)))
		}

		lastToolCount = data.TotalToolCalls
		lastSessionCount = len(data.Sessions)
	}
	return 0
}

// sortedByTimestamp orders every call across every session, oldest first.
//
// Stable, so two calls sharing a timestamp keep the order their sessions were
// collected in — the feed must not reshuffle itself between polls when nothing
// has happened.
func sortedByTimestamp(data *auditscan.AuditData) []*auditscan.ToolCall {
	calls := data.AllCalls()
	sort.SliceStable(calls, func(i, j int) bool {
		return calls[i].Timestamp < calls[j].Timestamp
	})
	return calls
}

// ── argument helpers ───────────────────────────────────────────────────────

func has(args []string, want string) bool { return indexOf(args, want) >= 0 }

func indexOf(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}

func argAt(args []string, i int) string {
	if i < 0 || i >= len(args) {
		return ""
	}
	return args[i]
}

// logLimit is `--logs 100`, defaulting to 50. A value that is not a number at
// all falls back to the default rather than showing nothing.
func logLimit(args []string) int {
	idx := indexOf(args, "--logs")
	if idx < 0 {
		idx = indexOf(args, "-l")
	}
	next := argAt(args, idx+1)
	if idx < 0 || next == "" || strings.HasPrefix(next, "-") {
		return 50
	}
	n := leadingInt(next)
	if n == 0 {
		return 50
	}
	return n
}

// leadingInt is JavaScript's parseInt: as many leading digits as there are.
func leadingInt(s string) int {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0
	}
	return n
}

func printHelp() {
	fmt.Print(`
  solongate-audit — AI agent audit log tool

  Usage:
    npx solongate-audit                 Scan logs and show report
    npx solongate-audit --detailed      Show detailed analysis per category
    npx solongate-audit --logs          Show recent tool calls (last 50)
    npx solongate-audit --logs 100      Show last N tool calls
    npx solongate-audit --watch         Live monitoring with log feed
    npx solongate-audit --json          Machine-readable JSON output

  Export:
    npx solongate-audit --export json   Export full report as JSON
    npx solongate-audit --export csv    Export tool calls as CSV
    npx solongate-audit --export html   Export visual HTML report
    npx solongate-audit --export pdf    Export PDF-ready HTML (print to PDF)
    npx solongate-audit --export all    Export all formats at once

  Log directories:
    npx solongate-audit --search        Search system for AI tool logs
    npx solongate-audit --list-dirs     Show all log directories
    npx solongate-audit --add-dir <path>    Add a custom log directory
    npx solongate-audit --remove-dir <path> Remove a custom log directory

  Config: ~/.solongate-audit/config.json
`)
}
