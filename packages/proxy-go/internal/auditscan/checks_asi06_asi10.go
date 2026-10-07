// SPDX-License-Identifier: Apache-2.0

package auditscan

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// ── ASI06: Memory & Context Poisoning ──────────────────────────────────────
//
// MINJA is the attack where text placed in something the agent will read later
// tells it that a check has already passed. The patterns are the assertions,
// not the words: "user is admin" appearing in a tool RESULT is data claiming to
// be authority.

var minjaPatterns = []jsRegexp{
	ciLower(`skip\s+(authorization|auth)\s+checks?`),
	ciLower(`user\s+is\s+(verified\s+)?admin`),
	ciLower(`full\s+access\s+(granted|enabled)`),
	ciLower(`ignore\s+(security|safety|restriction)`),
	ciLower(`bypass\s+(auth|security|check)`),
	ciLower(`you\s+have\s+permission`),
	ciLower(`elevated\s+privileges?`),
	ciLower(`disable\s+(logging|audit|monitoring)`),
	ciLower(`trust\s+this\s+(source|input|data)`),
	ciLower(`no\s+verification\s+needed`),
}

func checkMemoryPoisoning(data *AuditData) CheckResult {
	const code, title = "ASI06", "Memory Poisoning"
	var evidence evidenceList

	poisoningPatterns, unscanResults := 0, 0
	var flagged []string

	for _, tc := range data.AllCalls() {
		result := tc.ResultText()
		lowered := tc.ResultLower()

		for _, p := range minjaPatterns {
			if !p.test(lowered) {
				continue
			}
			poisoningPatterns++
			if len(flagged) < 3 {
				// Quote the text as the transcript had it, not lowercased.
				flagged = append(flagged, tc.ToolName+`: result contains "`+p.ciRe.FindString(result)+`"`)
			}
			break
		}

		if jsLen(result) > 100 {
			unscanResults++
		}
	}

	evidence.add(IconInfo, fmt.Sprintf("Scanned %d tool results for memory poisoning patterns", data.TotalToolCalls))
	evidence.add(IconInfo, fmt.Sprintf(
		"%d tool result(s) returned substantial data (>100 chars) — unscanned", unscanResults))

	if poisoningPatterns > 0 {
		evidence.add(IconWarn, fmt.Sprintf(
			"%d MINJA-style poisoning pattern(s) detected in tool results", poisoningPatterns))
		for _, f := range flagged {
			evidence.add(IconWarn, "  "+f)
		}
	} else {
		evidence.add(IconFound, "No MINJA poisoning patterns detected in tool results")
	}

	evidence.add(IconMissing, "No response scanning — tool outputs go directly into agent context")
	evidence.add(IconMissing, "No memory validation — poisoned data can persist across sessions")
	evidence.add(IconMissing, "No context isolation between tool results")

	if poisoningPatterns > 0 {
		return CheckResult{
			Code: code, Title: title, Status: StatusNotProtected, Evidence: evidence,
			Summary:        fmt.Sprintf("%d memory poisoning pattern(s) found in tool results.", poisoningPatterns),
			Details:        `Tool results contain instructions that could manipulate agent behavior (MINJA attack). Patterns like "skip authorization" or "user is admin" found in data returned to agents.`,
			Recommendation: "Implement response scanning with MINJA-informed rules. Add memory validation. Add context isolation.",
		}
	}

	// Unscanned results on their own are PARTIAL. Only an actual poisoning
	// pattern is NOT_PROTECTED — "we cannot see it" is not "it happened".
	if unscanResults > 50 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        fmt.Sprintf("%d unscanned tool results — no poisoning detected, but no scanning exists.", unscanResults),
			Details:        fmt.Sprintf("%d tool results with substantial data passed directly to agent context without scanning. No MINJA patterns detected yet, but no scanning exists to catch future attacks.", unscanResults),
			Recommendation: "Implement response scanning for tool outputs. Add MINJA-informed rules.",
		}
	}

	return CheckResult{
		Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
		Summary:        "No poisoning detected, but no scanning exists to prevent it.",
		Details:        "No MINJA patterns found in current logs. But tool outputs are not scanned — future attacks would go undetected.",
		Recommendation: "Implement response scanning with MINJA-informed rules. Add memory validation.",
	}
}

// ── ASI07: Insecure Inter-Agent Communication ──────────────────────────────

func checkInterAgent(data *AuditData) CheckResult {
	const code, title = "ASI07", "Inter-Agent Comms"
	var evidence evidenceList

	var agentSources []string
	seen := map[string]bool{}
	for _, s := range data.Sessions {
		if !seen[string(s.Source)] {
			seen[string(s.Source)] = true
			agentSources = append(agentSources, string(s.Source))
		}
	}
	multiAgent := len(agentSources) > 1

	delegationCalls, agentSpawns := 0, 0
	for _, tc := range data.AllCalls() {
		toolLower := lowerName(tc)
		argStr := tc.ArgsLower()

		if strings.Contains(toolLower, "task") || strings.Contains(toolLower, "agent") || strings.Contains(toolLower, "delegate") {
			delegationCalls++
		}
		if strings.Contains(argStr, "subagent") || strings.Contains(argStr, "sub_agent") || strings.Contains(argStr, "spawn") {
			agentSpawns++
		}
	}

	evidence.add(IconInfo, fmt.Sprintf("%d agent source(s): %s", len(agentSources), strings.Join(agentSources, ", ")))

	if multiAgent {
		evidence.add(IconWarn, "Multiple agents active — no authenticated communication between them")
	}
	if delegationCalls > 0 {
		evidence.add(IconWarn, fmt.Sprintf("%d task delegation call(s) — no receipt chain or depth limits", delegationCalls))
	}
	if agentSpawns > 0 {
		evidence.add(IconWarn, fmt.Sprintf("%d sub-agent spawn(s) — no fan-out limit", agentSpawns))
	}

	evidence.add(IconMissing, "No receipt chain — inter-agent messages have no verified identity trail")
	evidence.add(IconMissing, "No delegation depth limit (maxChainDepth)")
	evidence.add(IconMissing, "No fan-out limit (maxFanOut)")
	evidence.add(IconMissing, "No agent-to-agent authentication protocol")
	evidence.add(IconMissing, "No message integrity verification between agents")

	if !multiAgent && delegationCalls == 0 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        "Single-agent usage — no inter-agent security needed yet.",
			Details:        "Only one agent source detected. No delegation or sub-agent spawning. Inter-agent security not tested but also not needed for current usage.",
			Recommendation: "When using multi-agent systems, add receipt chain tracking, delegation limits, and authentication.",
		}
	}

	summary := fmt.Sprintf("%d delegation(s) without receipt chain or depth limits.", delegationCalls)
	if multiAgent {
		summary = "Multiple agents active with no communication security."
	}
	return CheckResult{
		Code: code, Title: title, Status: StatusNotProtected, Evidence: evidence,
		Summary:        summary,
		Details:        "Agents communicate without authentication, receipts, or depth limits. A compromised agent can forge messages, create unlimited delegation chains, and spread malicious instructions.",
		Recommendation: "Add receipt chain tracking. Set maxChainDepth and maxFanOut limits. Add agent authentication.",
	}
}

// ── ASI08: Cascading Failures ──────────────────────────────────────────────
//
// The three shapes a runaway agent leaves in a transcript: calls too close
// together to be a person's pace, the same tool failing over and over, and
// errors bunched into a few seconds.

func checkCascadingFailures(data *AuditData, deep *DeepAnalysis) CheckResult {
	const code, title = "ASI08", "Cascading Failures"
	var evidence evidenceList

	allCalls := data.AllCalls()
	errorCount := 0
	for _, tc := range allCalls {
		if tc.Errored() {
			errorCount++
		}
	}
	errorRate := 0.0
	if len(allCalls) > 0 {
		errorRate = float64(errorCount) / float64(len(allCalls))
	}

	burstDetected := 0
	for _, session := range data.Sessions {
		calls := session.ToolCalls
		for i := 0; i < len(calls)-5; i++ {
			t0, ok0 := parseMillis(calls[i].Timestamp)
			t4, ok4 := parseMillis(calls[i+4].Timestamp)
			if ok0 && ok4 && t4-t0 < 2000 {
				burstDetected++
				break // once per session
			}
		}
	}

	retryStorms := 0
	for _, session := range data.Sessions {
		calls := session.ToolCalls
		for i := 0; i < len(calls)-3; i++ {
			window := calls[i : i+3]
			all := true
			for _, c := range window {
				if c.ToolName != window[0].ToolName || !c.Errored() {
					all = false
					break
				}
			}
			if all {
				retryStorms++
				break
			}
		}
	}

	errorSpikes := 0
	for _, session := range data.Sessions {
		var errs []*ToolCall
		for _, tc := range session.ToolCalls {
			if tc.Errored() {
				errs = append(errs, tc)
			}
		}
		if len(errs) < 5 {
			continue
		}
		t0, ok0 := parseMillis(errs[0].Timestamp)
		tN, okN := parseMillis(errs[len(errs)-1].Timestamp)
		if ok0 && okN && tN-t0 < 30000 {
			errorSpikes++
		}
	}

	evidence.add(IconInfo, fmt.Sprintf("%d tool calls, %d errors (%s%% error rate)",
		len(allCalls), errorCount, toFixed(errorRate*100, 1)))

	if errorRate > 0.2 {
		evidence.add(IconWarn, fmt.Sprintf(
			"High error rate: %s%% — potential cascading failure indicator", toFixed(errorRate*100, 1)))
	} else if errorCount > 0 {
		evidence.add(IconInfo, fmt.Sprintf("Error rate %s%% — within normal range", toFixed(errorRate*100, 1)))
	}

	if burstDetected > 0 {
		evidence.add(IconWarn, fmt.Sprintf(
			"%d burst pattern(s) detected (5+ calls in <2s) — no rate limiting", burstDetected))
	}
	if retryStorms > 0 {
		evidence.add(IconWarn, fmt.Sprintf(
			"%d retry storm(s) detected (3+ consecutive errors on same tool)", retryStorms))
	}
	if errorSpikes > 0 {
		evidence.add(IconWarn, fmt.Sprintf("%d error spike(s) detected (5+ errors in <30s)", errorSpikes))
	}

	if deep != nil {
		retryChains := chainsNamed(deep.Chains, "retry-storm")
		if len(retryChains) > retryStorms {
			retryStorms = len(retryChains)
		}
		var highAnomalies []SessionAnomaly
		for _, a := range deep.Anomalies {
			if a.Severity == SeverityHigh {
				highAnomalies = append(highAnomalies, a)
			}
		}
		if len(highAnomalies) > 0 {
			evidence.add(IconWarn, fmt.Sprintf(
				"%d session(s) with abnormal behavior vs baseline", len(highAnomalies)))
			for _, a := range headN(highAnomalies, 3) {
				first := ""
				if len(a.Deviations) > 0 {
					first = a.Deviations[0]
				}
				evidence.add(IconWarn, "  Session "+jsSliceHead(a.SessionID, 8)+": "+first)
			}
		}
	}

	evidence.add(IconMissing, "No fail-closed behavior detected in logs")
	evidence.add(IconMissing, "No circuit breaker pattern detected")
	evidence.add(IconMissing, "No timeout enforcement detected")

	totalIssues := burstDetected + retryStorms + errorSpikes
	if errorRate > 0.2 {
		totalIssues++
	}

	if totalIssues == 0 && errorRate <= 0.05 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        "No failure patterns detected, but no safeguards exist.",
			Details:        "Logs show normal operation — no bursts, retry storms, or error spikes. But no fail-closed design, circuit breakers, or timeouts exist to prevent future cascading failures.",
			Recommendation: "Implement fail-closed mode. Add circuit breakers. Add timeout enforcement.",
		}
	}

	sessionCount := len(data.Sessions)
	if sessionCount == 0 {
		sessionCount = 1
	}
	issueRate := toFixed(float64(totalIssues)/float64(sessionCount)*100, 0)

	if totalIssues > 0 && float64(totalIssues)/float64(sessionCount) < 0.3 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        fmt.Sprintf("%d failure pattern(s) in %d sessions (%s%%).", totalIssues, sessionCount, issueRate),
			Details:        "Some burst patterns or retry storms found at low frequency. No fail-closed design, no circuit breakers.",
			Recommendation: "Implement fail-closed mode. Add circuit breakers. Add rate limiting.",
		}
	}

	if totalIssues > 0 {
		return CheckResult{
			Code: code, Title: title, Status: StatusNotProtected, Evidence: evidence,
			Summary:        fmt.Sprintf("%d failure pattern(s) in %d sessions (%s%%).", totalIssues, sessionCount, issueRate),
			Details:        "Burst patterns, retry storms, or error spikes found in many sessions. No fail-closed design, no circuit breakers, no timeouts.",
			Recommendation: "Implement fail-closed mode. Add circuit breakers. Add rate limiting. Add timeout enforcement.",
		}
	}

	return CheckResult{
		Code: code, Title: title, Status: StatusNotProtected, Evidence: evidence,
		Summary:        "No cascading failure safeguards. High error rate in logs.",
		Details:        "Error rate exceeds threshold. No fail-closed behavior, no circuit breakers, no spike detection exist to prevent cascading failures.",
		Recommendation: "Implement fail-closed mode. Add circuit breakers. Add spike detection. Add timeout enforcement.",
	}
}

// ── ASI09: Human-Agent Trust Exploitation ──────────────────────────────────
//
// A deploy or a delete is only counted when it is an actual COMMAND in a shell
// tool. Writing a file that mentions `git push` is not a deploy, and counting
// it as one was how this check used to be red for everybody.

var highImpactTools = []string{"deploy", "publish"}
var shellTools = []string{"bash", "shell", "exec", "terminal"}

var (
	rxDestructiveDelete = cs(`rm\s+-rf\s+[\/~$.*]`)
	rxWindowsDelete     = ciLower(`del\s+\/[sf]`)
	rxDropTable         = ciLower(`drop\s+(table|database)`)
	rxDeployCommand     = cs(`\b(git\s+push|npm\s+publish|docker\s+push|kubectl\s+apply|terraform\s+apply)\b`)
)

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func checkHumanTrust(data *AuditData, deep *DeepAnalysis) CheckResult {
	const code, title = "ASI09", "Human-Agent Trust"
	var evidence evidenceList

	shellCalls, writeOps, deleteOps, deployOps := 0, 0, 0, 0

	for _, tc := range data.AllCalls() {
		toolLower := lowerName(tc)
		argStr := tc.ArgsLower()

		if containsAny(toolLower, shellTools) || containsAny(toolLower, highImpactTools) {
			shellCalls++
		}
		if strings.Contains(toolLower, "write") || strings.Contains(toolLower, "edit") ||
			strings.Contains(toolLower, "notebookedit") {
			writeOps++
		}

		if !containsAny(toolLower, shellTools) {
			continue
		}
		if rxDestructiveDelete.test(argStr) || rxWindowsDelete.test(argStr) || rxDropTable.test(argStr) {
			deleteOps++
		}
		if rxDeployCommand.test(argStr) {
			deployOps++
		}
	}

	evidence.add(IconInfo, fmt.Sprintf("%d shell/exec call(s) in %d session(s)", shellCalls, len(data.Sessions)))
	evidence.add(IconInfo, fmt.Sprintf("%d file write(s), %d delete operation(s), %d deploy/publish action(s)",
		writeOps, deleteOps, deployOps))

	if deployOps > 0 {
		evidence.add(IconWarn, fmt.Sprintf(
			"%d deploy/publish action(s) executed without human approval gate", deployOps))
	}
	if deleteOps > 0 {
		evidence.add(IconWarn, fmt.Sprintf(
			"%d delete operation(s) executed without human approval gate", deleteOps))
	}

	if deep != nil && len(deep.UnsolicitedActions) > 0 {
		evidence.add(IconWarn, fmt.Sprintf(
			"%d critical action(s) with no matching user request", len(deep.UnsolicitedActions)))
		for _, ua := range headN(deep.UnsolicitedActions, 3) {
			ago := "(no preceding user message)"
			if ua.HasLastUserMessage && ua.TimeSinceLastUserMessage != 0 {
				ago = fmt.Sprintf("(%ds after last user msg)", int(math.Round(ua.TimeSinceLastUserMessage/1000)))
			}
			evidence.add(IconWarn, fmt.Sprintf("  %s: %s %s", ua.ToolName, ua.Action, ago))
		}
		for _, a := range deep.UnsolicitedActions {
			switch a.Action {
			case "deploy":
				deployOps++
			case "delete":
				deleteOps++
			}
		}
	}

	evidence.add(IconMissing, "No approval routing — critical actions not routed for human review")
	evidence.add(IconMissing, "No raw intent routing — humans may see agent-reframed summaries")
	evidence.add(IconMissing, "No policy-generated explanations — agents frame their own requests")
	evidence.add(IconMissing, "No protection against approval fatigue")

	if shellCalls == 0 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        "No critical actions in logs, but no approval workflow exists.",
			Details:        "No file writes, deletions, or deployments detected. But no human approval workflow exists — when critical actions occur, they will execute without review.",
			Recommendation: "Implement approval routing for critical actions. Add raw intent display.",
		}
	}

	if deployOps == 0 && deleteOps == 0 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        fmt.Sprintf("%d shell calls without approval routing, but no high-impact actions.", shellCalls),
			Details:        "Shell commands executed without human approval workflow. No deployments or destructive deletions detected. But no approval routing exists for when high-impact actions occur.",
			Recommendation: "Implement approval routing. Add raw intent routing. Ensure policy-generated explanations.",
		}
	}

	impactRate := "0"
	if shellCalls > 0 {
		impactRate = toFixed(float64(deployOps+deleteOps)/float64(shellCalls)*100, 1)
	}
	denom := shellCalls
	if denom == 0 {
		denom = 1
	}

	if float64(deployOps+deleteOps)/float64(denom) < 0.1 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        fmt.Sprintf("%d high-impact action(s) in %d shell calls (%s%%).", deployOps+deleteOps, shellCalls, impactRate),
			Details:        "Some deploy/delete operations without approval, but at low frequency relative to total shell usage.",
			Recommendation: "Implement approval routing for critical actions. Add raw intent display.",
		}
	}

	return CheckResult{
		Code: code, Title: title, Status: StatusNotProtected, Evidence: evidence,
		Summary:        fmt.Sprintf("%d high-impact action(s) in %d shell calls (%s%%).", deployOps+deleteOps, shellCalls, impactRate),
		Details:        "Deployments, deletions, or publishes executed without human review. No approval routing, no raw intent display, no policy-generated explanations.",
		Recommendation: "Implement approval routing for critical actions. Add raw intent display. Ensure policy-generated explanations.",
	}
}

// ── ASI10: Rogue Agents ────────────────────────────────────────────────────
//
// Drift, not damage. A session that starts by reading and ends by executing has
// changed what it is doing, and the reason nobody notices is that each
// individual step looked reasonable when it happened.

func checkRogueAgents(data *AuditData, deep *DeepAnalysis) CheckResult {
	const code, title = "ASI10", "Rogue Agents"
	var evidence evidenceList

	scopeEscalation, volumeSpikes, unusualTools := 0, 0, 0

	avgCallsPerSession := 0.0
	if len(data.Sessions) > 0 {
		avgCallsPerSession = float64(data.TotalToolCalls) / float64(len(data.Sessions))
	}

	isDangerousTool := func(tc *ToolCall) bool {
		t := lowerName(tc)
		return strings.Contains(t, "exec") || strings.Contains(t, "bash") ||
			strings.Contains(t, "shell") || strings.Contains(t, "delete")
	}

	for _, session := range data.Sessions {
		if float64(len(session.ToolCalls)) > avgCallsPerSession*3 && avgCallsPerSession > 10 {
			volumeSpikes++
		}

		calls := session.ToolCalls
		mid := len(calls) / 2
		firstHalf, secondHalf := calls[:mid], calls[mid:]

		firstDangerous, secondDangerous := 0, 0
		for _, c := range firstHalf {
			if isDangerousTool(c) {
				firstDangerous++
			}
		}
		for _, c := range secondHalf {
			if isDangerousTool(c) {
				secondDangerous++
			}
		}
		if len(secondHalf) > 5 && secondDangerous > firstDangerous*2 && secondDangerous > 3 {
			scopeEscalation++
		}

		// A tool used heavily in exactly one session and nowhere else is either
		// a one-off task or something that arrived with the session.
		var toolOrder []string
		seenTool := map[string]bool{}
		for _, c := range calls {
			if !seenTool[c.ToolName] {
				seenTool[c.ToolName] = true
				toolOrder = append(toolOrder, c.ToolName)
			}
		}
		for _, tool := range toolOrder {
			usedElsewhere := false
			for _, other := range data.Sessions {
				if other.ID == session.ID {
					continue
				}
				for _, tc := range other.ToolCalls {
					if tc.ToolName == tool {
						usedElsewhere = true
						break
					}
				}
				if usedElsewhere {
					break
				}
			}
			if usedElsewhere {
				continue
			}
			count := 0
			for _, c := range calls {
				if c.ToolName == tool {
					count++
				}
			}
			if count > 5 {
				unusualTools++
			}
		}
	}

	evidence.add(IconInfo, fmt.Sprintf("%d session(s), avg %d calls/session",
		len(data.Sessions), int(math.Round(avgCallsPerSession))))

	if volumeSpikes > 0 {
		evidence.add(IconWarn, fmt.Sprintf("%d session(s) with 3x+ volume spike (anomalous activity)", volumeSpikes))
	}
	if scopeEscalation > 0 {
		evidence.add(IconWarn, fmt.Sprintf("%d session(s) show scope escalation (reads → exec/delete)", scopeEscalation))
	}
	if unusualTools > 0 {
		evidence.add(IconWarn, fmt.Sprintf(
			"%d unusual tool usage pattern(s) (tools only used in one session)", unusualTools))
	}

	if deep != nil {
		if len(deep.PermissionDrifts) > 0 {
			if len(deep.PermissionDrifts) > scopeEscalation {
				scopeEscalation = len(deep.PermissionDrifts)
			}
			for _, drift := range headN(deep.PermissionDrifts, 3) {
				line := fmt.Sprintf("Session %s: privilege drift %sx (level %s → %s)",
					jsSliceHead(drift.SessionID, 8), toFixed(drift.DriftRatio, 1),
					toFixed(drift.EarlyPrivilegeLevel, 1), toFixed(drift.LatePrivilegeLevel, 1))
				if len(drift.NewToolTypes) > 0 {
					line += " | new: " + strings.Join(drift.NewToolTypes, ", ")
				}
				evidence.add(IconWarn, line)
			}
		}

		if len(deep.Anomalies) > 0 {
			if len(deep.Anomalies) > volumeSpikes {
				volumeSpikes = len(deep.Anomalies)
			}
			evidence.add(IconWarn, fmt.Sprintf(
				"%d session(s) deviate >2 stddev from behavioral baseline", len(deep.Anomalies)))
			for _, a := range headN(deep.Anomalies, 3) {
				first := ""
				if len(a.Deviations) > 0 {
					first = a.Deviations[0]
				}
				evidence.add(IconWarn, "  "+jsSliceHead(a.SessionID, 8)+": "+first)
			}
		}

		if allBaseline := findBaseline(deep.Baselines, "all"); allBaseline != nil {
			evidence.add(IconInfo, fmt.Sprintf("Baseline: avg %d calls/session | %s",
				int(math.Round(allBaseline.AvgToolCalls)), distributionLine(allBaseline)))
		}
	}

	evidence.add(IconMissing, "No remote kill switch — cannot instantly stop a rogue agent")
	evidence.add(IconMissing, "No auto-shutdown on anomalous behavior")
	evidence.add(IconMissing, "No scope boundaries — agents can self-escalate")

	totalAnomalies := volumeSpikes + scopeEscalation
	sessionCount := len(data.Sessions)
	if sessionCount == 0 {
		sessionCount = 1
	}
	anomalyRate := toFixed(float64(totalAnomalies)/float64(sessionCount)*100, 0)

	if totalAnomalies > 0 && float64(totalAnomalies)/float64(sessionCount) < 0.2 {
		return CheckResult{
			Code: code, Title: title, Status: StatusPartial, Evidence: evidence,
			Summary:        fmt.Sprintf("%d anomaly(ies) in %d sessions (%s%%) — no kill switch.", totalAnomalies, sessionCount, anomalyRate),
			Details:        "Some anomalous patterns at low frequency. No CUSUM baselines or kill switch, but current risk is moderate.",
			Recommendation: "Implement CUSUM behavioral baselines. Add remote kill switch. Add auto-shutdown on anomaly.",
		}
	}

	if totalAnomalies > 0 {
		return CheckResult{
			Code: code, Title: title, Status: StatusNotProtected, Evidence: evidence,
			Summary:        fmt.Sprintf("%d anomaly(ies) in %d sessions (%s%%) — no kill switch.", totalAnomalies, sessionCount, anomalyRate),
			Details:        "Volume spikes or scope escalation patterns found in many sessions. No CUSUM baselines to detect drift. No remote kill switch or auto-shutdown.",
			Recommendation: "Implement CUSUM behavioral baselines. Add remote kill switch. Add auto-shutdown on anomaly.",
		}
	}

	return CheckResult{
		Code: code, Title: title, Status: StatusNotProtected, Evidence: evidence,
		Summary:        "No behavioral monitoring or kill switch. Rogue agents undetectable.",
		Details:        "No behavioral baselines, no drift detection, no kill switch. If an agent becomes rogue, there is no way to detect or stop it.",
		Recommendation: "Implement CUSUM behavioral baselines. Add remote kill switch. Add auto-shutdown. Set scope boundaries.",
	}
}

// distributionLine renders "exec:41%, read:30%, …" biggest first. The sort is
// stable over the order the categories were first counted in, because Go map
// iteration is random and this string ends up in a report a user may diff
// against yesterday's.
func distributionLine(b *SessionBaseline) string {
	cats := make([]string, 0, len(b.ToolTypeDistribution))
	cats = append(cats, b.distOrder...)
	if len(cats) != len(b.ToolTypeDistribution) {
		// distOrder is only absent on a hand-built baseline; fall back to a
		// name sort so the output is still deterministic.
		cats = cats[:0]
		for k := range b.ToolTypeDistribution {
			cats = append(cats, k)
		}
		sort.Strings(cats)
	}
	sort.SliceStable(cats, func(i, j int) bool {
		return b.ToolTypeDistribution[cats[i]] > b.ToolTypeDistribution[cats[j]]
	})
	parts := make([]string, 0, len(cats))
	for _, c := range cats {
		parts = append(parts, c+":"+toFixed(b.ToolTypeDistribution[c], 0)+"%")
	}
	return strings.Join(parts, ", ")
}
