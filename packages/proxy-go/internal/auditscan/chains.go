package auditscan

import (
	"regexp"
	"strings"
)

// Chain analysis is the part of the audit that looks at ORDER. A credential
// read is not a finding; a credential read followed by a network call is. None
// of the ten checks can see that on its own, so the sequences are matched once
// here and the checks that care ask for the result.

func lowerName(tc *ToolCall) string { return tc.NameLower() }

func isFileRead(tc *ToolCall) bool {
	t := lowerName(tc)
	return strings.Contains(t, "read") || strings.Contains(t, "cat") ||
		strings.Contains(t, "grep") || strings.Contains(t, "glob")
}

func isFileWrite(tc *ToolCall) bool {
	t := lowerName(tc)
	return strings.Contains(t, "write") || strings.Contains(t, "edit")
}

func isShellExec(tc *ToolCall) bool {
	t := lowerName(tc)
	return strings.Contains(t, "bash") || strings.Contains(t, "shell") ||
		strings.Contains(t, "exec") || strings.Contains(t, "terminal")
}

func isNetworkCall(tc *ToolCall) bool {
	t := lowerName(tc)
	argStr := tc.ArgsLower()
	if strings.Contains(t, "web") || strings.Contains(t, "fetch") || strings.Contains(t, "navigate") {
		return true
	}
	return isShellExec(tc) && (strings.Contains(argStr, "curl ") ||
		strings.Contains(argStr, "wget ") || strings.Contains(argStr, "nc ") ||
		strings.Contains(argStr, "scp "))
}

var (
	rxSudo  = regexp.MustCompile(`\bsudo\b`)
	rxChmod = regexp.MustCompile(`\bchmod\b`)
	rxChown = regexp.MustCompile(`\bchown\b`)
	rxRunas = regexp.MustCompile(`\brunas\b`)
	// The .env variants are spelled out because a bare `.env` prefix match also
	// hits `.environment` and every project has one of those.
	rxDotEnv = regexp.MustCompile(`\.env(?:\b|\.production|\.local|\.staging)`)
)

func isPrivilegeEscalation(tc *ToolCall) bool {
	if !isShellExec(tc) {
		return false
	}
	argStr := tc.ArgsLower()
	return rxSudo.MatchString(argStr) || rxChmod.MatchString(argStr) ||
		rxChown.MatchString(argStr) || rxRunas.MatchString(argStr)
}

func readsSensitiveFile(tc *ToolCall) bool {
	argStr := tc.ArgsLower()
	return rxDotEnv.MatchString(argStr) ||
		strings.Contains(argStr, "credentials") ||
		strings.Contains(argStr, "id_rsa") ||
		strings.Contains(argStr, "id_ed25519") ||
		strings.Contains(argStr, ".pem") ||
		strings.Contains(argStr, "/etc/shadow") ||
		strings.Contains(argStr, "service-account")
}

// extractSummary is the one-line description of a step, taking whichever of the
// usual argument names the tool happened to use.
func extractSummary(tc *ToolCall) string {
	for _, key := range []string{"command", "file_path", "path", "url"} {
		if v, ok := tc.Arguments.Get(key); ok && truthy(v) {
			return jsString(v)
		}
	}
	return jsSliceHead(tc.ArgsJSON(), 60)
}

type chainPattern struct {
	name        string
	severity    Severity
	description string
	steps       []func(*ToolCall) bool
	maxGap      int
	// requireContentOverlap keeps "read a file, then ran a command" from being
	// reported when the command has nothing of the file in it. Adjacency alone
	// describes most of a normal working session.
	requireContentOverlap bool
}

func chainPatterns() []chainPattern {
	return []chainPattern{
		{
			name: "credential-exfiltration", severity: SeverityHigh,
			description: "Credential file read followed by network call",
			steps:       []func(*ToolCall) bool{readsSensitiveFile, isNetworkCall},
			maxGap:      10,
		},
		{
			name: "cross-contamination", severity: SeverityMedium,
			description:           "File read followed by file write containing read content",
			steps:                 []func(*ToolCall) bool{isFileRead, isFileWrite},
			maxGap:                5,
			requireContentOverlap: true,
		},
		{
			name: "privilege-escalation-sequence", severity: SeverityHigh,
			description: "Normal read followed by privilege escalation then execution",
			steps:       []func(*ToolCall) bool{isFileRead, isPrivilegeEscalation, isShellExec},
			maxGap:      8,
		},
		{
			name: "read-exec-chain", severity: SeverityMedium,
			description: "File read followed by shell exec using read content",
			steps: []func(*ToolCall) bool{
				func(tc *ToolCall) bool { return isFileRead(tc) && !readsSensitiveFile(tc) },
				func(tc *ToolCall) bool { return isShellExec(tc) && !isPrivilegeEscalation(tc) },
			},
			maxGap:                3,
			requireContentOverlap: true,
		},
	}
}

// hasContentOverlap samples the source's output and looks for any of it in the
// sink's arguments. It samples rather than searching the whole string because
// the results are capped at 2000 characters and a full cross product over a
// long session is the only part of this tool that could get slow.
func hasContentOverlap(source, sink *ToolCall) bool {
	sourceResult := source.ResultText()
	if jsLen(sourceResult) < 20 {
		return false
	}
	sinkArgs := sink.ArgsJSON()
	limit := jsLen(sourceResult) - 30
	if limit > 500 {
		limit = 500
	}
	for i := 0; i < limit; i += 15 {
		chunk := strings.TrimSpace(jsSliceRange(sourceResult, i, i+30))
		if jsLen(chunk) < 15 {
			continue
		}
		if strings.Contains(sinkArgs, chunk) {
			return true
		}
	}
	return false
}

// findRetryStorms reports a tool that failed four times in a row. It is scored
// low on its own; what it feeds is the cascading-failure check.
func findRetryStorms(session *SessionInfo) []ChainMatch {
	var matches []ChainMatch
	calls := session.ToolCalls

	for i := 0; i < len(calls)-3; i++ {
		window := calls[i : i+4]
		all := true
		for _, c := range window {
			if c.ToolName != window[0].ToolName || !c.Errored() {
				all = false
				break
			}
		}
		if !all {
			continue
		}
		steps := make([]ChainStep, 0, len(window))
		for j, c := range window {
			steps = append(steps, ChainStep{
				Index: i + j, ToolName: c.ToolName,
				Summary: "error: " + jsSliceHead(c.ResultText(), 50),
			})
		}
		matches = append(matches, ChainMatch{
			ChainName: "retry-storm", SessionID: session.ID, Steps: steps,
			Severity:    SeverityLow,
			Description: window[0].ToolName + " called 4+ times with consecutive errors",
		})
		break
	}
	return matches
}

func findChainMatches(session *SessionInfo) []ChainMatch {
	matches := findRetryStorms(session)
	calls := session.ToolCalls

	for _, pattern := range chainPatterns() {
		for startIdx := 0; startIdx < len(calls); startIdx++ {
			if !pattern.steps[0](calls[startIdx]) {
				continue
			}
			stepMatches := []ChainStep{{
				Index: startIdx, ToolName: calls[startIdx].ToolName,
				Summary: extractSummary(calls[startIdx]),
			}}

			currentIdx := startIdx
			matched := true
			for stepNum := 1; stepNum < len(pattern.steps); stepNum++ {
				found := false
				last := currentIdx + pattern.maxGap
				if last > len(calls)-1 {
					last = len(calls) - 1
				}
				for j := currentIdx + 1; j <= last; j++ {
					if pattern.steps[stepNum](calls[j]) {
						stepMatches = append(stepMatches, ChainStep{
							Index: j, ToolName: calls[j].ToolName, Summary: extractSummary(calls[j]),
						})
						currentIdx = j
						found = true
						break
					}
				}
				if !found {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}

			if pattern.requireContentOverlap {
				first := calls[stepMatches[0].Index]
				last := calls[stepMatches[len(stepMatches)-1].Index]
				if !hasContentOverlap(first, last) {
					continue
				}
			}

			matches = append(matches, ChainMatch{
				ChainName: pattern.name, SessionID: session.ID, Steps: stepMatches,
				Severity: pattern.severity, Description: pattern.description,
			})
			// One match per pattern per session: the finding is "this happened
			// here", and repeating it per occurrence buries the other patterns.
			break
		}
	}
	return matches
}

// AnalyzeChains runs the sequence patterns over every session.
func AnalyzeChains(sessions []*SessionInfo) []ChainMatch {
	var all []ChainMatch
	for _, s := range sessions {
		all = append(all, findChainMatches(s)...)
	}
	return all
}
