package auditscan

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mattn/go-isatty"

	"github.com/codeyevsky/solongate/proxy/internal/term"
)

// The report's colours are the 4-bit ANSI set rather than the CLI's truecolor
// palette in internal/term. That is deliberate and it is what the npm tool
// does: a terminal remaps the sixteen basic colours to the user's own theme, so
// "green" stays readable on a light background, where a fixed RGB green does
// not. The reset, bold and dim codes are shared with term because those are the
// same everywhere.
const (
	ansiGreen     = "\x1b[32m"
	ansiYellow    = "\x1b[33m"
	ansiRed       = "\x1b[31m"
	ansiCyan      = "\x1b[36m"
	ansiMagenta   = "\x1b[35m"
	ansiBlue      = "\x1b[34m"
	ansiWhite     = "\x1b[37m"
	ansiUnderline = "\x1b[4m"
)

// colorEnabled follows the same rules chalk does, because the TypeScript this
// replaces goes through chalk and a report redirected into a file has to arrive
// without escape codes in it.
var colorEnabled = detectColor()

func detectColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if v := os.Getenv("FORCE_COLOR"); v != "" && v != "0" {
		return true
	}
	return isatty.IsTerminal(os.Stdout.Fd())
}

// paint wraps text in codes, or does not.
func paint(text string, codes ...string) string {
	if !colorEnabled || len(codes) == 0 {
		return text
	}
	return strings.Join(codes, "") + text + term.Reset
}

func dim(s string) string  { return paint(s, term.Dim) }
func bold(s string) string { return paint(s, term.Bold) }

// Dim and Bold are exported for the live feed, which draws its own headings
// between calls into the printers below and has to match their styling.
func Dim(s string) string  { return dim(s) }
func Bold(s string) string { return bold(s) }

func statusIcon(s CheckStatus) string {
	switch s {
	case StatusProtected:
		return paint("✅", ansiGreen)
	case StatusPartial:
		return paint("⚠️", ansiYellow)
	default:
		return paint("❌", ansiRed)
	}
}

func statusLabel(s CheckStatus) string {
	switch s {
	case StatusProtected:
		return paint("PROTECTED", ansiGreen, term.Bold)
	case StatusPartial:
		return paint("PARTIAL", ansiYellow, term.Bold)
	default:
		return paint("NOT PROTECTED", ansiRed, term.Bold)
	}
}

func evidenceIcon(i EvidenceIcon) string {
	switch i {
	case IconFound:
		return paint("•", ansiGreen)
	case IconMissing:
		return paint("•", ansiRed)
	case IconWarn:
		return paint("•", ansiYellow)
	default:
		return paint("•", term.Dim)
	}
}

func PrintHeader() {
	fmt.Println("")
	title := "  SolonGate Security Audit — OWASP Agentic Top 10  "
	border := strings.Repeat("─", jsLen(title))
	fmt.Println(paint("┌"+border+"┐", term.Bold, ansiWhite))
	fmt.Println(paint("│", term.Bold, ansiWhite) + title + paint("│", term.Bold, ansiWhite))
	fmt.Println(paint("└"+border+"┘", term.Bold, ansiWhite))
	fmt.Println("")
}

func PrintLogSummary(data *AuditData) {
	if len(data.Sources) > 0 {
		fmt.Println(dim("  AI Tools: ") + strings.Join(data.Sources, ", "))
	} else {
		fmt.Println(dim("  AI Tools: ") + paint("No AI tool logs found", ansiRed))
	}

	fmt.Printf("%s%d total, %d tool calls\n", dim("  Sessions: "), len(data.Sessions), data.TotalToolCalls)

	if data.TimeRange != nil {
		from := formatDateNumeric(data.TimeRange.From)
		to := formatDateNumeric(data.TimeRange.To)
		fmt.Println(dim("  Period: ") + from + " — " + to)
	}
	fmt.Println("")
}

// CalcScore is the whole grade: one point per PROTECTED category, a half for
// PARTIAL, floored. fixCount is the number of categories that are outright
// unprotected, which is what the report asks the user to act on.
func CalcScore(results []CheckResult) (intScore, fixCount int) {
	score := 0.0
	for _, r := range results {
		switch r.Status {
		case StatusProtected:
			score += 1
		case StatusPartial:
			score += 0.5
		case StatusNotProtected:
			fixCount++
		}
	}
	return int(score), fixCount
}

// sortedByStatus puts the good news first and the gaps last, so the bottom of
// the list is the part worth reading.
func sortedByStatus(results []CheckResult) []CheckResult {
	order := map[CheckStatus]int{StatusProtected: 0, StatusPartial: 1, StatusNotProtected: 2}
	out := append([]CheckResult(nil), results...)
	sort.SliceStable(out, func(i, j int) bool {
		return order[out[i].Status] < order[out[j].Status]
	})
	return out
}

func PrintCompactReport(results []CheckResult) {
	for _, r := range sortedByStatus(results) {
		head := r.Code + " " + r.Title
		fmt.Printf("%s %s %s\n", statusIcon(r.Status), padEnd(head, 24), statusLabel(r.Status))
		fmt.Println(dim("   " + r.Summary))
	}
	fmt.Println("")
}

func PrintScore(results []CheckResult) {
	intScore, fixCount := CalcScore(results)

	color := ansiRed
	if intScore >= 7 {
		color = ansiGreen
	} else if intScore >= 4 {
		color = ansiYellow
	}
	fmt.Printf("  Security Score: %s\n", paint(fmt.Sprintf("%d/10", intScore), color, term.Bold))
	fmt.Println("")

	switch {
	case fixCount > 0:
		// The findings are in this report. Pointing at a website for the fix was
		// pointing at a hosted product; the report is the product here.
		fmt.Printf("  %d critical %s to fix — see the findings below.\n",
			fixCount, plural(fixCount, "issue", "issues"))
	case intScore < 10:
		fmt.Println(paint("  No critical gaps, but improvements possible.", ansiYellow, term.Dim))
	default:
		fmt.Println(paint("  Maximum protection achieved!", ansiGreen, term.Bold))
	}
	fmt.Println("")
}

func PrintDetailedReport(results []CheckResult) {
	fmt.Println(bold(strings.Repeat("─", 56)))
	fmt.Println(bold("  DETAILED ANALYSIS"))
	fmt.Println(bold(strings.Repeat("─", 56)))
	fmt.Println("")

	for _, r := range sortedByStatus(results) {
		fmt.Printf("  %s %s  %s\n", statusIcon(r.Status), bold(r.Code+" "+r.Title), statusLabel(r.Status))
		fmt.Printf("     %s\n", r.Summary)
		fmt.Println("")

		for _, e := range r.Evidence {
			lines := strings.Split(e.Text, "\n")
			fmt.Printf("     %s %s\n", evidenceIcon(e.Icon), lines[0])
			for _, extra := range lines[1:] {
				fmt.Printf("       %s\n", extra)
			}
		}
		fmt.Println("")

		fmt.Printf("     %s\n", dim(r.Details))

		if r.Recommendation != "" {
			fmt.Println("")
			fmt.Printf("     %s %s\n", paint("➜", ansiCyan), paint(r.Recommendation, ansiCyan))
		}

		fmt.Println("")
		fmt.Println(dim("     " + strings.Repeat("─", 46)))
		fmt.Println("")
	}
}

func PrintFooter(results []CheckResult) {
	intScore, fixCount := CalcScore(results)

	line := fmt.Sprintf("  Security Score: %d/10", intScore)
	if fixCount > 0 {
		line += " — Critical risks detected."
	}
	fmt.Println(line)
	if fixCount > 0 {
		fmt.Printf("  Run %s to write a policy for these.\n", paint("solongate", ansiCyan))
	}
	fmt.Println("")
}

// ── Log viewer ─────────────────────────────────────────────────────────────

func sourceColor(src string) string {
	switch Source(src) {
	case SourceClaude:
		return ansiMagenta
	case SourceCodex:
		return ansiCyan
	case SourceAntigravity:
		return ansiBlue
	case SourceOpenClaw:
		return ansiGreen
	}
	return ansiWhite
}

func sourceLabel(src string) string {
	switch Source(src) {
	case SourceClaude:
		return "Claude"
	case SourceCodex:
		return "Codex"
	case SourceAntigravity:
		return "Antigravity"
	case SourceOpenClaw:
		return "OClaw"
	}
	return src
}

// padEnd is String.prototype.padEnd, measured the way JavaScript measures it.
func padEnd(s string, width int) string {
	n := jsLen(s)
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}

func truncateDisplay(s string, max int) string {
	if jsLen(s) <= max {
		return s
	}
	return jsSliceHead(s, max-1) + "…"
}

var newlineReplacer = strings.NewReplacer("\n", " ", "\r", " ")

// extractArgSummary picks the one field that says what a call was about. The
// order is the order a reader wants: what was run, then what was touched, then
// what was searched for. A diff gets its before and after; a large body gets
// its size rather than its content.
func extractArgSummary(args *Args) string {
	for _, key := range []string{"command", "file_path", "path", "pattern", "url", "query"} {
		if v, ok := args.Get(key); ok && truthy(v) {
			return jsString(v)
		}
	}
	if v, ok := args.Get("old_string"); ok && truthy(v) {
		newVal := ""
		if nv, ok := args.Get("new_string"); ok && truthy(nv) {
			newVal = jsString(nv)
		}
		return `"` + jsSliceHead(jsString(v), 30) + `" → "` + jsSliceHead(newVal, 30) + `"`
	}
	if v, ok := args.Get("content"); ok && truthy(v) {
		return fmt.Sprintf("[%d chars]", jsLen(jsString(v)))
	}
	if args.Len() > 0 {
		return args.String()
	}
	return ""
}

// PrintToolCall renders one call. The compact form is one line and is what the
// live feed uses; the detailed form is what `--logs` prints.
func PrintToolCall(tc *ToolCall, detailed bool, model string) {
	color := sourceColor(string(tc.Source))
	label := sourceLabel(string(tc.Source))
	clock := formatClock(tc.Timestamp)
	tool := truncateDisplay(tc.ToolName, 16)
	errorMark := ""
	if tc.Errored() {
		errorMark = paint(" ERR", ansiRed)
	}

	if !detailed {
		argSummary := truncateDisplay(newlineReplacer.Replace(extractArgSummary(tc.Arguments)), 70)
		fmt.Printf("  %s %s %s %s%s\n",
			dim(clock), paint(padEnd(label, 6), color),
			paint(padEnd(tool, 17), ansiWhite), dim(argSummary), errorMark)
		return
	}

	fmt.Printf("  %s %s %s%s\n", dim(clock), paint(padEnd(label, 6), color),
		paint(tool, ansiWhite, term.Bold), errorMark)

	indent := strings.Repeat(" ", 9)
	modelPart := ""
	if model != "" {
		modelPart = "  " + dim("Model:") + " " + dim(model)
	}
	fmt.Printf("  %s%s %s  %s %s%s\n", indent,
		dim("ID:"), dim(jsSliceHead(tc.ID, 12)),
		dim("Session:"), dim(jsSliceHead(tc.SessionID, 12)), modelPart)

	argStr := newlineReplacer.Replace(extractArgSummary(tc.Arguments))
	if jsLen(argStr) > 0 {
		if jsLen(argStr) <= 120 {
			fmt.Printf("  %s%s %s\n", indent, paint("▸", ansiCyan), argStr)
		} else {
			// Long arguments wrap to at most four lines and then say how many
			// were dropped. A wall of text scrolls the rest of the log away.
			lines := chunk(argStr, 120)
			fmt.Printf("  %s%s %s\n", indent, paint("▸", ansiCyan), lines[0])
			shown := len(lines)
			if shown > 4 {
				shown = 4
			}
			for i := 1; i < shown; i++ {
				fmt.Printf("  %s%s\n", strings.Repeat(" ", 11), lines[i])
			}
			if len(lines) > 4 {
				fmt.Printf("  %s%s\n", strings.Repeat(" ", 11),
					dim(fmt.Sprintf("... +%d more lines", len(lines)-4)))
			}
		}
	}

	if tc.Result != nil {
		resultStr := strings.TrimSpace(collapseWhitespace(*tc.Result))
		if len(resultStr) > 0 {
			icon := paint("✔", ansiGreen)
			if tc.Errored() {
				icon = paint("✘", ansiRed)
			}
			fmt.Printf("  %s%s %s\n", indent, icon, dim(truncateDisplay(resultStr, 120)))
		}
	}
	fmt.Println("")
}

// collapseWhitespace is `.replace(/[\n\r]+/g, ' ')`.
func collapseWhitespace(s string) string {
	var b strings.Builder
	prevBreak := false
	for _, r := range s {
		if r == '\n' || r == '\r' {
			if !prevBreak {
				b.WriteByte(' ')
			}
			prevBreak = true
			continue
		}
		prevBreak = false
		b.WriteRune(r)
	}
	return b.String()
}

// chunk is `s.match(/.{1,n}/g)`.
func chunk(s string, n int) []string {
	total := jsLen(s)
	if total == 0 {
		return []string{s}
	}
	var out []string
	for i := 0; i < total; i += n {
		out = append(out, jsSliceRange(s, i, i+n))
	}
	return out
}

// PrintLogs prints the most recent calls, grouped by day.
func PrintLogs(data *AuditData, limit int, detailed bool) {
	fmt.Println("")
	fmt.Println(bold("  Recent Tool Calls"))
	fmt.Println(dim("  " + strings.Repeat("─", 90)))
	if !detailed {
		fmt.Println(dim("  Time     Source Tool              Arguments"))
		fmt.Println(dim("  " + strings.Repeat("─", 90)))
	}

	models := map[string]string{}
	for _, s := range data.Sessions {
		if _, seen := models[s.ID]; !seen {
			models[s.ID] = s.Model
		}
	}

	allCalls := data.AllCalls()
	sort.SliceStable(allCalls, func(i, j int) bool {
		return allCalls[i].Timestamp < allCalls[j].Timestamp
	})

	recent := allCalls
	if limit < len(recent) {
		recent = recent[len(recent)-limit:]
	}

	lastDate := ""
	for _, tc := range recent {
		date := formatDayMonth(tc.Timestamp)
		if date != lastDate {
			lastDate = date
			fmt.Println(dim("\n  ── " + date + " ──"))
		}
		PrintToolCall(tc, detailed, models[tc.SessionID])
	}

	errorCount := 0
	var sources []string
	seen := map[string]bool{}
	for _, tc := range recent {
		if tc.Errored() {
			errorCount++
		}
		if !seen[string(tc.Source)] {
			seen[string(tc.Source)] = true
			sources = append(sources, string(tc.Source))
		}
	}

	fmt.Println("")
	fmt.Println(dim(fmt.Sprintf("  Showing last %d of %d total tool calls", len(recent), len(allCalls))))
	if errorCount > 0 {
		fmt.Println(dim(fmt.Sprintf("  %d error(s) in view | Sources: %s", errorCount, strings.Join(sources, ", "))))
	}
	fmt.Println("")
}
