// SPDX-License-Identifier: Apache-2.0

package auditscan

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Baseline analysis compares a session against how sessions on this machine
// usually go. It is the only part of the audit with no fixed threshold: what
// counts as a lot of tool calls depends entirely on how the person works, so
// the tool learns it rather than asserting it.

// getPrivilegeLevel ranks what a call can do, 1 (read) to 4 (send data out).
// The ranking is what makes "drift" measurable: a session whose second half
// averages a higher level than its first half is escalating.
func getPrivilegeLevel(toolName string, args *Args) int {
	t := strings.ToLower(toolName)
	argStr := strings.ToLower(argsJSONOf(args))

	if strings.Contains(t, "web") || strings.Contains(t, "fetch") || strings.Contains(t, "navigate") {
		return 4
	}
	isExec := strings.Contains(t, "bash") || strings.Contains(t, "shell") || strings.Contains(t, "exec")
	if isExec && (strings.Contains(argStr, "curl") || strings.Contains(argStr, "wget") || strings.Contains(argStr, "nc ")) {
		return 4
	}
	if isExec || strings.Contains(t, "terminal") {
		return 3
	}
	if strings.Contains(t, "write") || strings.Contains(t, "edit") ||
		strings.Contains(t, "delete") || strings.Contains(t, "notebook") {
		return 2
	}
	return 1
}

func argsJSONOf(a *Args) string {
	if a == nil {
		return "{}"
	}
	return a.String()
}

func getToolCategory(toolName string) string {
	t := strings.ToLower(toolName)
	switch {
	case strings.Contains(t, "read") || strings.Contains(t, "cat") || strings.Contains(t, "grep") ||
		strings.Contains(t, "glob") || strings.Contains(t, "search"):
		return "read"
	case strings.Contains(t, "write") || strings.Contains(t, "edit"):
		return "write"
	case strings.Contains(t, "bash") || strings.Contains(t, "shell") ||
		strings.Contains(t, "exec") || strings.Contains(t, "terminal"):
		return "exec"
	case strings.Contains(t, "web") || strings.Contains(t, "fetch") ||
		strings.Contains(t, "navigate") || strings.Contains(t, "browser"):
		return "network"
	case strings.Contains(t, "task") || strings.Contains(t, "todo") || strings.Contains(t, "agent"):
		return "orchestration"
	}
	return "other"
}

// computeBaseline summarises a group of sessions. The standard deviations use
// the sample formula (n-1), so a single session produces 0 rather than a
// deviation of nothing, and the anomaly detector skips it.
func computeBaseline(sessions []*SessionInfo, source string) SessionBaseline {
	filtered := sessions
	if source != "all" {
		filtered = nil
		for _, s := range sessions {
			if string(s.Source) == source {
				filtered = append(filtered, s)
			}
		}
	}

	var callCounts []float64
	for _, s := range filtered {
		callCounts = append(callCounts, float64(len(s.ToolCalls)))
	}
	avgToolCalls := mean(callCounts)
	stddevToolCalls := sampleStddev(callCounts, avgToolCalls)

	var durations []float64
	for _, s := range filtered {
		if s.StartTime == "" || s.EndTime == "" {
			continue
		}
		start, okS := parseMillis(s.StartTime)
		end, okE := parseMillis(s.EndTime)
		if !okS || !okE {
			continue
		}
		d := end - start
		if d > 0 {
			durations = append(durations, d)
		}
	}
	avgDurationMs := mean(durations)
	stddevDurationMs := sampleStddev(durations, avgDurationMs)

	totalCalls := 0
	counts := map[string]float64{}
	var order []string
	for _, s := range filtered {
		totalCalls += len(s.ToolCalls)
		for _, tc := range s.ToolCalls {
			cat := getToolCategory(tc.ToolName)
			if _, seen := counts[cat]; !seen {
				order = append(order, cat)
			}
			counts[cat]++
		}
	}
	dist := map[string]float64{}
	for cat, n := range counts {
		if totalCalls > 0 {
			dist[cat] = n / float64(totalCalls) * 100
		} else {
			dist[cat] = 0
		}
	}

	return SessionBaseline{
		Source: source, AvgToolCalls: avgToolCalls, StddevToolCalls: stddevToolCalls,
		ToolTypeDistribution: dist, AvgDurationMs: avgDurationMs, StddevDurationMs: stddevDurationMs,
		distOrder: order,
	}
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}

func sampleStddev(v []float64, avg float64) float64 {
	if len(v) <= 1 {
		return 0
	}
	sum := 0.0
	for _, x := range v {
		sum += (x - avg) * (x - avg)
	}
	return math.Sqrt(sum / float64(len(v)-1))
}

// detectAnomalies needs at least three sessions before it says anything. With
// two, every session is either the maximum or the minimum and everything looks
// abnormal.
func detectAnomalies(sessions []*SessionInfo, baselines []SessionBaseline) []SessionAnomaly {
	var anomalies []SessionAnomaly
	allBaseline := findBaseline(baselines, "all")
	if allBaseline == nil || len(sessions) < 3 {
		return anomalies
	}

	for _, session := range sessions {
		baseline := findBaseline(baselines, string(session.Source))
		if baseline == nil {
			baseline = allBaseline
		}
		var deviations []string

		if baseline.StddevToolCalls > 0 {
			z := (float64(len(session.ToolCalls)) - baseline.AvgToolCalls) / baseline.StddevToolCalls
			if z > 2 {
				deviations = append(deviations, fmt.Sprintf(
					"tool calls %sx stddev above mean (%d vs avg %d)",
					toFixed(z, 1), len(session.ToolCalls), int(math.Round(baseline.AvgToolCalls))))
			}
		}

		if session.StartTime != "" && session.EndTime != "" && baseline.StddevDurationMs > 0 {
			start, okS := parseMillis(session.StartTime)
			end, okE := parseMillis(session.EndTime)
			if okS && okE {
				duration := end - start
				if duration > 0 {
					z := (duration - baseline.AvgDurationMs) / baseline.StddevDurationMs
					if z > 2 {
						deviations = append(deviations,
							"duration "+toFixed(z, 1)+"x stddev above mean")
					}
				}
			}
		}

		sessionCategories := map[string]float64{}
		var catOrder []string
		for _, tc := range session.ToolCalls {
			cat := getToolCategory(tc.ToolName)
			if _, seen := sessionCategories[cat]; !seen {
				catOrder = append(catOrder, cat)
			}
			sessionCategories[cat]++
		}
		sessionTotal := float64(len(session.ToolCalls))
		if sessionTotal == 0 {
			sessionTotal = 1
		}
		for _, cat := range catOrder {
			sessionPct := sessionCategories[cat] / sessionTotal * 100
			baselinePct := baseline.ToolTypeDistribution[cat]
			if sessionPct > baselinePct*3 && sessionPct > 10 && baselinePct > 0 {
				deviations = append(deviations, fmt.Sprintf("%s: %s%% vs baseline %s%%",
					cat, toFixed(sessionPct, 0), toFixed(baselinePct, 0)))
			}
		}

		if len(deviations) > 0 {
			severity := SeverityLow
			if len(deviations) >= 3 {
				severity = SeverityHigh
			} else if len(deviations) >= 2 {
				severity = SeverityMedium
			}
			anomalies = append(anomalies, SessionAnomaly{
				SessionID: session.ID, Source: string(session.Source),
				Deviations: deviations, Severity: severity,
			})
		}
	}

	return anomalies
}

func findBaseline(baselines []SessionBaseline, source string) *SessionBaseline {
	for i := range baselines {
		if baselines[i].Source == source {
			return &baselines[i]
		}
	}
	return nil
}

// detectPermissionDrift compares the first half of a session against the
// second. Under eight calls there is no meaningful half, so short sessions are
// skipped rather than measured badly.
func detectPermissionDrift(sessions []*SessionInfo) []PermissionDrift {
	var drifts []PermissionDrift

	for _, session := range sessions {
		calls := session.ToolCalls
		if len(calls) < 8 {
			continue
		}
		mid := len(calls) / 2
		firstHalf, secondHalf := calls[:mid], calls[mid:]

		var early, late []float64
		for _, tc := range firstHalf {
			early = append(early, float64(getPrivilegeLevel(tc.ToolName, tc.Arguments)))
		}
		for _, tc := range secondHalf {
			late = append(late, float64(getPrivilegeLevel(tc.ToolName, tc.Arguments)))
		}
		earlyAvg, lateAvg := mean(early), mean(late)
		driftRatio := lateAvg
		if earlyAvg > 0 {
			driftRatio = lateAvg / earlyAvg
		}

		earlyTools := map[string]bool{}
		for _, tc := range firstHalf {
			earlyTools[getToolCategory(tc.ToolName)] = true
		}
		var newToolTypes []string
		seen := map[string]bool{}
		for _, tc := range secondHalf {
			cat := getToolCategory(tc.ToolName)
			if seen[cat] {
				continue
			}
			seen[cat] = true
			if !earlyTools[cat] {
				newToolTypes = append(newToolTypes, cat)
			}
		}

		if driftRatio > 1.5 || containsStr(newToolTypes, "exec") || containsStr(newToolTypes, "network") {
			drifts = append(drifts, PermissionDrift{
				SessionID: session.ID, EarlyPrivilegeLevel: earlyAvg,
				LatePrivilegeLevel: lateAvg, DriftRatio: driftRatio, NewToolTypes: newToolTypes,
			})
		}
	}

	return drifts
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// ── Unsolicited actions ────────────────────────────────────────────────────

type criticalAction struct {
	re     *regexp.Regexp
	action string
}

var criticalActions = []criticalAction{
	{regexp.MustCompile(`(?i)\b(git\s+push|npm\s+publish|docker\s+push|kubectl\s+apply|terraform\s+apply)\b`), "deploy"},
	{regexp.MustCompile(`(?i)rm\s+-rf\s+[/~$.*]|del\s+/[sf]|drop\s+(table|database)`), "delete"},
	{regexp.MustCompile(`(?i)chmod\s+[0-7]{3,4}|chown\b|sudo\b`), "privilege"},
}

// The request vocabularies include Turkish because this tool's users write to
// their agents in it, and an action asked for in Turkish would otherwise be
// reported as one the agent took on its own.
var (
	rxAskDeploy    = regexp.MustCompile(`\b(deploy|push|publish|release|ship|yayınla|gönder)\b`)
	rxAskDelete    = regexp.MustCompile(`\b(delete|remove|clean|drop|purge|sil|kaldır|temizle)\b`)
	rxAskPrivilege = regexp.MustCompile(`\b(chmod|chown|sudo|permission|root|admin|yetki)\b`)
)

func actionMatchesUserRequest(action, userText string) bool {
	lower := strings.ToLower(userText)
	switch action {
	case "deploy":
		return rxAskDeploy.MatchString(lower)
	case "delete":
		return rxAskDelete.MatchString(lower)
	case "privilege":
		return rxAskPrivilege.MatchString(lower)
	}
	return false
}

// FindUnsolicitedActions reports a critical shell action with no user request
// behind it. A session with no user messages at all is skipped: without them
// there is nothing to compare against, and reporting every action as
// unsolicited would be an artefact of the transcript format rather than a
// finding.
func FindUnsolicitedActions(sessions []*SessionInfo) []UnsolicitedAction {
	var unsolicited []UnsolicitedAction

	for _, session := range sessions {
		userMsgs := session.UserMessages
		if len(userMsgs) == 0 {
			continue
		}

		for i, tc := range session.ToolCalls {
			t := lowerName(tc)
			if !(strings.Contains(t, "bash") || strings.Contains(t, "shell") || strings.Contains(t, "exec")) {
				continue
			}
			argStr := tc.ArgsJSON()

			for _, ca := range criticalActions {
				if !ca.re.MatchString(argStr) {
					continue
				}
				tcTime, okT := parseMillis(tc.Timestamp)
				var lastMsg *UserMessage
				if okT {
					for k := range userMsgs {
						umTime, ok := parseMillis(userMsgs[k].Timestamp)
						if ok && umTime < tcTime {
							lastMsg = &userMsgs[k]
						}
					}
				}
				requested := lastMsg != nil && actionMatchesUserRequest(ca.action, lastMsg.Text)

				if !requested {
					entry := UnsolicitedAction{
						SessionID: session.ID, ToolCallIndex: i,
						ToolName: tc.ToolName, Action: ca.action,
					}
					if lastMsg != nil {
						entry.LastUserMessageBefore = jsSliceHead(lastMsg.Text, 100)
						if umTime, ok := parseMillis(lastMsg.Timestamp); ok && okT {
							entry.TimeSinceLastUserMessage = tcTime - umTime
							entry.HasLastUserMessage = true
						}
					}
					unsolicited = append(unsolicited, entry)
				}
				break
			}
		}
	}

	return unsolicited
}

// AnalyzeBaseline computes the "all" baseline plus one per client that appears,
// then the anomalies and drifts that come off them.
func AnalyzeBaseline(sessions []*SessionInfo) (baselines []SessionBaseline, anomalies []SessionAnomaly, drifts []PermissionDrift) {
	var sources []string
	seen := map[string]bool{}
	for _, s := range sessions {
		if !seen[string(s.Source)] {
			seen[string(s.Source)] = true
			sources = append(sources, string(s.Source))
		}
	}

	baselines = append(baselines, computeBaseline(sessions, "all"))
	for _, src := range sources {
		baselines = append(baselines, computeBaseline(sessions, src))
	}

	anomalies = detectAnomalies(sessions, baselines)
	drifts = detectPermissionDrift(sessions)
	return
}
