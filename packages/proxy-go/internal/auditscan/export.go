// SPDX-License-Identifier: Apache-2.0

package auditscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Exports are written into the CURRENT DIRECTORY under a fixed name, which is
// how the npm tool has always behaved and what any script wrapping it expects
// to find. The CSV column names in particular are part of that contract and are
// not changed here for any reason.

// ExportPayload is one scan's result, ready to be written out.
type ExportPayload struct {
	Data    *AuditData
	Results []CheckResult
}

func exportPath(ext string) string {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	return filepath.Join(cwd, "solongate-audit-report."+ext)
}

// ── JSON ───────────────────────────────────────────────────────────────────

type jsonSummary struct {
	Sources        []string   `json:"sources"`
	Sessions       int        `json:"sessions"`
	TotalToolCalls int        `json:"totalToolCalls"`
	TimeRange      *TimeRange `json:"timeRange"`
}

type jsonAuditResult struct {
	Code string `json:"code"`
	// Title is the human name of the category.
	Title  string      `json:"title"`
	Status CheckStatus `json:"status"`
	// Summary and Details are the one-liner and the paragraph.
	Summary string `json:"summary"`
	Details string `json:"details"`
	// Recommendation is explicitly null rather than absent when a category
	// needs nothing done: a consumer testing for the key finds it either way.
	Recommendation *string    `json:"recommendation"`
	Evidence       []Evidence `json:"evidence"`
}

type jsonSession struct {
	ID            string  `json:"id"`
	Source        Source  `json:"source"`
	Model         *string `json:"model"`
	StartTime     string  `json:"startTime"`
	EndTime       *string `json:"endTime"`
	FilePath      string  `json:"filePath"`
	ToolCallCount int     `json:"toolCallCount"`
}

type jsonToolCall struct {
	ID        string  `json:"id"`
	ToolName  string  `json:"toolName"`
	Arguments *Args   `json:"arguments"`
	Timestamp string  `json:"timestamp"`
	Source    Source  `json:"source"`
	SessionID string  `json:"sessionId"`
	Result    *string `json:"result,omitempty"`
	IsError   *bool   `json:"isError,omitempty"`
	Model     *string `json:"model"`
}

type jsonReport struct {
	GeneratedAt  string            `json:"generatedAt"`
	Score        int               `json:"score"`
	MaxScore     int               `json:"maxScore"`
	Summary      jsonSummary       `json:"summary"`
	AuditResults []jsonAuditResult `json:"auditResults"`
	Sessions     []jsonSession     `json:"sessions"`
	ToolCalls    []jsonToolCall    `json:"toolCalls"`
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	v := s
	return &v
}

// ExportJSON writes the whole scan: the grade, every category, every session
// and every tool call. It is the format anything downstream should read.
func ExportJSON(p ExportPayload) (string, error) {
	intScore, _ := CalcScore(p.Results)

	report := jsonReport{
		GeneratedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Score:       intScore,
		MaxScore:    10,
		Summary: jsonSummary{
			Sources:        emptyIfNil(p.Data.Sources),
			Sessions:       len(p.Data.Sessions),
			TotalToolCalls: p.Data.TotalToolCalls,
			TimeRange:      p.Data.TimeRange,
		},
		AuditResults: make([]jsonAuditResult, 0, len(p.Results)),
		Sessions:     make([]jsonSession, 0, len(p.Data.Sessions)),
		ToolCalls:    make([]jsonToolCall, 0, p.Data.TotalToolCalls),
	}

	for _, r := range p.Results {
		ev := r.Evidence
		if ev == nil {
			ev = []Evidence{}
		}
		report.AuditResults = append(report.AuditResults, jsonAuditResult{
			Code: r.Code, Title: r.Title, Status: r.Status,
			Summary: r.Summary, Details: r.Details,
			Recommendation: nullable(r.Recommendation), Evidence: ev,
		})
	}

	for _, s := range p.Data.Sessions {
		report.Sessions = append(report.Sessions, jsonSession{
			ID: s.ID, Source: s.Source, Model: nullable(s.Model),
			StartTime: s.StartTime, EndTime: nullable(s.EndTime),
			FilePath: s.FilePath, ToolCallCount: len(s.ToolCalls),
		})
		model := nullable(s.Model)
		for _, tc := range s.ToolCalls {
			report.ToolCalls = append(report.ToolCalls, jsonToolCall{
				ID: tc.ID, ToolName: tc.ToolName, Arguments: tc.Arguments,
				Timestamp: tc.Timestamp, Source: tc.Source, SessionID: tc.SessionID,
				Result: tc.Result, IsError: tc.IsError, Model: model,
			})
		}
	}

	sort.SliceStable(report.ToolCalls, func(i, j int) bool {
		return report.ToolCalls[i].Timestamp < report.ToolCalls[j].Timestamp
	})

	compact, err := encodeJSON(report)
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", "  "); err != nil {
		out.Reset()
		out.Write(compact)
	}

	path := exportPath("json")
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// machineReport is what `--json` prints. It is deliberately a SMALLER document
// than the JSON export: the grade, the ten categories with their evidence, and
// the counts. The tool calls themselves are not in it, because this is what a
// CI job parses on every run and it should not have to stream a year of
// transcripts to read one number.
type machineReport struct {
	Score    int           `json:"score"`
	MaxScore int           `json:"maxScore"`
	Results  []CheckResult `json:"results"`
	Summary  jsonSummary   `json:"summary"`
}

// MachineReport renders the --json output.
func MachineReport(data *AuditData, results []CheckResult, intScore int) (string, error) {
	if results == nil {
		results = []CheckResult{}
	}
	compact, err := encodeJSON(machineReport{
		Score: intScore, MaxScore: 10, Results: results,
		Summary: jsonSummary{
			Sources:        emptyIfNil(data.Sources),
			Sessions:       len(data.Sessions),
			TotalToolCalls: data.TotalToolCalls,
			TimeRange:      data.TimeRange,
		},
	})
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", "  "); err != nil {
		return string(compact), nil
	}
	return out.String(), nil
}

// ── CSV ────────────────────────────────────────────────────────────────────

// csvHeaders are load-bearing. People point scripts at these names.
var csvHeaders = []string{
	"timestamp", "source", "sessionId", "model", "toolCallId", "toolName",
	"arguments", "result", "isError",
}

func escapeCSV(value string) string {
	if strings.ContainsAny(value, ",\"\n\r") {
		return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
	}
	return value
}

// ExportCSV writes one row per tool call, oldest first.
func ExportCSV(p ExportPayload) (string, error) {
	rows := []string{strings.Join(csvHeaders, ",")}

	models := map[string]string{}
	for _, s := range p.Data.Sessions {
		if _, seen := models[s.ID]; !seen {
			models[s.ID] = s.Model
		}
	}

	allCalls := p.Data.AllCalls()
	sort.SliceStable(allCalls, func(i, j int) bool {
		return allCalls[i].Timestamp < allCalls[j].Timestamp
	})

	for _, tc := range allCalls {
		isError := "false"
		if tc.Errored() {
			isError = "true"
		}
		rows = append(rows, strings.Join([]string{
			escapeCSV(tc.Timestamp),
			escapeCSV(string(tc.Source)),
			escapeCSV(tc.SessionID),
			escapeCSV(models[tc.SessionID]),
			escapeCSV(tc.ID),
			escapeCSV(tc.ToolName),
			escapeCSV(tc.ArgsJSON()),
			escapeCSV(tc.ResultText()),
			escapeCSV(isError),
		}, ","))
	}

	path := exportPath("csv")
	if err := os.WriteFile(path, []byte(strings.Join(rows, "\n")), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// ── HTML ───────────────────────────────────────────────────────────────────

var htmlEscaper = strings.NewReplacer(
	"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;",
)

func escapeHTML(s string) string { return htmlEscaper.Replace(s) }

func htmlStatusIcon(s CheckStatus) string {
	switch s {
	case StatusProtected:
		return "&#x2705;"
	case StatusPartial:
		return "&#x26A0;&#xFE0F;"
	default:
		return "&#x274C;"
	}
}

func htmlPillClass(s CheckStatus) string {
	switch s {
	case StatusProtected:
		return "pill pill-green"
	case StatusPartial:
		return "pill pill-yellow"
	default:
		return "pill pill-red"
	}
}

func htmlSourceLabel(src Source) string {
	switch src {
	case SourceClaude:
		return "Claude"
	case SourceCodex:
		return "Codex"
	case SourceAntigravity:
		return "Antigravity"
	case SourceOpenClaw:
		return "OpenClaw"
	}
	return string(src)
}

// ExportHTML writes the standalone report: a dark single-file page with the
// grade, the ten categories and a filterable, paginated table of every call.
func ExportHTML(p ExportPayload) (string, error) {
	intScore, fixCount := CalcScore(p.Results)

	allCalls := p.Data.AllCalls()
	// Newest first: the table is something a person scans from the top for what
	// just happened.
	sort.SliceStable(allCalls, func(i, j int) bool {
		return allCalls[i].Timestamp > allCalls[j].Timestamp
	})

	models := map[string]string{}
	for _, s := range p.Data.Sessions {
		if _, seen := models[s.ID]; !seen {
			models[s.ID] = s.Model
		}
	}

	errorCount := 0
	for _, tc := range allCalls {
		if tc.Errored() {
			errorCount++
		}
	}

	sortedResults := sortedByStatus(p.Results)
	var auditRows strings.Builder
	for _, r := range sortedResults {
		rec := ""
		if r.Recommendation != "" {
			rec = escapeHTML(r.Recommendation)
		}
		auditRows.WriteString("\n      <tr>\n        <td style=\"text-align:center;font-size:14px\">" +
			htmlStatusIcon(r.Status) + "</td>\n        <td><span class=\"code-tag\">" +
			escapeHTML(r.Code) + "</span></td>\n        <td class=\"cat\">" +
			escapeHTML(r.Title) + "</td>\n        <td><span class=\"" + htmlPillClass(r.Status) + "\">" +
			strings.ReplaceAll(string(r.Status), "_", " ") + "</span></td>\n        <td class=\"det\">" +
			escapeHTML(r.Summary) + "</td>\n        <td class=\"det\">" + rec + "</td>\n      </tr>")
	}

	var toolRows strings.Builder
	for _, tc := range allCalls {
		argFull := escapeHTML(tc.Arguments.Indent())
		hasArgs := argFull != "{}"
		resStr := escapeHTML(jsSliceHead(tc.ResultText(), 500))
		src := string(tc.Source)

		clock, dateShort, dateFull := "", "", ""
		if tc.Timestamp != "" {
			clock = formatClock(tc.Timestamp)
			dateShort = formatDayMonth(tc.Timestamp)
			dateFull = formatDateLong(tc.Timestamp)
		}

		// The trailing space after "log-row" is not a typo: the original
		// interpolates the error class into `class="log-row ${…}"`, so a
		// non-error row carries it too. Dropping it would make every one of
		// these rows differ from the npm exporter's for no reason at all.
		errRow, errTag := "", ""
		if tc.Errored() {
			errRow = "err-row"
			errTag = `<span class="err-tag">ERR</span>`
		}

		argCell := `<span style="color:#2a2a2e">&mdash;</span>`
		if hasArgs {
			argCell = `<div class="acc"><span class="acc-toggle">args</span><div class="acc-body"><div><pre>` +
				argFull + `</pre></div></div></div>`
		}

		resCell := `<span style="color:#2a2a2e">&mdash;</span>`
		if resStr != "" {
			label := "result"
			if tc.Errored() {
				label = `<span style="color:#f87171">error</span>`
			}
			resCell = `<div class="acc"><span class="acc-toggle">` + label +
				`</span><div class="acc-body"><div><pre>` + resStr + `</pre></div></div></div>`
		}

		model := models[tc.SessionID]
		if model == "" {
			model = "-"
		}

		toolRows.WriteString("\n      <tr class=\"log-row " + errRow + "\" data-source=\"" + src +
			"\" data-date=\"" + dateFull + "\">\n        <td class=\"ts\"><span class=\"d\">" +
			dateShort + "</span> " + clock + "</td>\n        <td><span class=\"src-tag src-" + src + "\">" +
			htmlSourceLabel(tc.Source) + "</span></td>\n        <td class=\"tool\">" +
			escapeHTML(tc.ToolName) + errTag + "</td>\n        <td class=\"args\">" + argCell +
			"</td>\n        <td>" + resCell + "</td>\n        <td class=\"meta\">" +
			escapeHTML(jsSliceHead(tc.ID, 8)) + "<br>" + escapeHTML(model) + "</td>\n      </tr>")
	}

	skeletonRow := `<tr class="skel-row"><td><div class="skel-bar skel-w1"></div></td><td><div class="skel-bar skel-w2"></div></td><td><div class="skel-bar skel-w3"></div></td><td><div class="skel-bar skel-w4"></div></td><td><div class="skel-bar skel-w5"></div></td><td><div class="skel-bar skel-w6"></div></td></tr>`
	skeleton := strings.Repeat(skeletonRow, 12)

	scoreColor := "#ef4444"
	if intScore >= 7 {
		scoreColor = "#22c55e"
	} else if intScore >= 4 {
		scoreColor = "#eab308"
	}

	scoreText := "Critical gaps across multiple categories."
	if intScore >= 7 {
		scoreText = "Good protection."
	} else if intScore >= 4 {
		scoreText = "Several categories need attention."
	}

	fixColor := "#4ade80"
	fixSub := "none"
	fixLink := ""
	if fixCount > 0 {
		fixColor = "#f87171"
		fixSub = "need attention"
		fixLink = fmt.Sprintf(
			`<p style="margin-top:6px">Fix %d issue%s with <code>solongate policy</code></p>`,
			fixCount, plural(fixCount, "", "s"))
	}

	sourcesList := strings.Join(p.Data.Sources, ", ")
	if sourcesList == "" {
		sourcesList = "None"
	}

	rangeText := "-"
	if p.Data.TimeRange != nil {
		rangeText = formatDateShort(p.Data.TimeRange.From) + " &ndash; " + formatDateShortYear(p.Data.TimeRange.To)
	}

	errorsText := "No errors"
	if errorCount > 0 {
		errorsText = fmt.Sprintf("%d error%s", errorCount, plural(errorCount, "", "s"))
	}

	ringDash := int(math.Round(float64(intScore) / 10 * 251))

	html := strings.NewReplacer(
		"__SG_SCORE_COLOR__", scoreColor,
		"__SG_LOGO__", sgLogoSVG,
		"__SG_DATE__", nowDateShortYear(),
		"__SG_SOURCES_COUNT__", fmt.Sprint(len(p.Data.Sources)),
		"__SG_SOURCES_LIST__", sourcesList,
		"__SG_SESSIONS_COUNT__", fmt.Sprint(len(p.Data.Sessions)),
		"__SG_RANGE__", rangeText,
		"__SG_CALLS_TOTAL__", toLocaleString(p.Data.TotalToolCalls),
		"__SG_ERRORS__", errorsText,
		"__SG_FIX_COLOR__", fixColor,
		"__SG_FIX_COUNT__", fmt.Sprint(fixCount),
		"__SG_FIX_SUB__", fixSub,
		"__SG_SCORE__", fmt.Sprint(intScore),
		"__SG_SCORE_TEXT__", scoreText,
		"__SG_FIX_LINK__", fixLink,
		"__SG_RESULTS_COUNT__", fmt.Sprint(len(p.Results)),
		"__SG_AUDIT_ROWS__", auditRows.String(),
		"__SG_CALLS_COUNT__", toLocaleString(len(allCalls)),
		"__SG_SKELETON__", skeleton,
		"__SG_TOOL_ROWS__", toolRows.String(),
		"__SG_RING_DASH__", fmt.Sprint(ringDash),
	).Replace(htmlTemplate)

	path := exportPath("html")
	if err := os.WriteFile(path, []byte(html), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// ── PDF ────────────────────────────────────────────────────────────────────

// ExportPDF writes a small page that redirects to the HTML report so the
// browser's own print-to-PDF can do the work. Bundling a PDF engine into the
// CLI to produce a document the browser already renders correctly is not a
// trade worth making.
func ExportPDF(p ExportPayload) (string, error) {
	htmlPath, err := ExportHTML(p)
	if err != nil {
		return "", err
	}
	href := strings.ReplaceAll(htmlPath, `\`, "/")

	pdfHTML := `<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="0;url=` + href + `">
</head>
<body>
<p>Opening report... If not redirected, <a href="` + href + `">click here</a> and press Ctrl+P to save as PDF.</p>
</body></html>`

	path := exportPath("pdf.html")
	if err := os.WriteFile(path, []byte(pdfHTML), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// ── Dispatcher ─────────────────────────────────────────────────────────────

// ExportAll writes every format.
func ExportAll(p ExportPayload) ([]string, error) {
	var files []string
	for _, fn := range []func(ExportPayload) (string, error){ExportJSON, ExportCSV, ExportHTML, ExportPDF} {
		path, err := fn(p)
		if err != nil {
			return files, err
		}
		files = append(files, path)
	}
	return files, nil
}

// RunExport is the --export command. It returns the process exit code so the
// caller decides how to leave, rather than this function ending the process
// from inside a library.
func RunExport(format string, p ExportPayload) int {
	fmt.Println("")

	report := func(path string, err error) int {
		if err != nil {
			fmt.Printf("  %s %v\n", paint("✘", ansiRed), err)
			fmt.Println("")
			return 1
		}
		fmt.Printf("  %s Exported: %s\n", paint("✔", ansiGreen), path)
		fmt.Println("")
		return 0
	}

	switch format {
	case "all":
		files, err := ExportAll(p)
		for _, f := range files {
			fmt.Printf("  %s %s\n", paint("✔", ansiGreen), f)
		}
		if err != nil {
			fmt.Printf("  %s %v\n", paint("✘", ansiRed), err)
			fmt.Println("")
			return 1
		}
		fmt.Println("")
		return 0
	case "json":
		return report(ExportJSON(p))
	case "csv":
		return report(ExportCSV(p))
	case "html":
		return report(ExportHTML(p))
	case "pdf":
		return report(ExportPDF(p))
	}

	fmt.Println(paint("  Unknown format: "+format, ansiRed))
	fmt.Println(dim("  Supported: json, csv, html, pdf, all"))
	return 1
}

// sgLogoSVG is the mark, inline.
//
// It was an <img> pointing at a CDN. This report is a file somebody opens from
// their own disk, often to read what an agent did on a machine that is not on a
// network — so a remote image is a broken box offline, and a request to somebody
// else's server announcing that the report was opened when it is not.
const sgLogoSVG = `<svg width="36" height="36" viewBox="0 0 36 36" role="img" aria-label="SolonGate">` +
	`<rect width="36" height="36" rx="8" fill="#1432A0"/>` +
	`<path d="M11 13.5a4 4 0 0 1 4-4h6a4 4 0 0 1 4 4v1h-3v-1a1 1 0 0 0-1-1h-6a1 1 0 0 0-1 1v1.5a1 1 0 0 0 1 1h6a4 4 0 0 1 4 4v1.5a4 4 0 0 1-4 4h-6a4 4 0 0 1-4-4v-1h3v1a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V20a1 1 0 0 0-1-1h-6a4 4 0 0 1-4-4z" fill="#fff"/>` +
	`</svg>`
