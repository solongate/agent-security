// SPDX-License-Identifier: Apache-2.0

package auditscan

import (
	"regexp"
	"strings"
)

// Data-flow analysis answers a narrower question than chain analysis: did a
// value that came OUT of one tool go INTO a later one that can send it
// somewhere. That is the difference between an agent that read a secret and an
// agent that leaked one.

type sensitivePattern struct {
	re   *regexp.Regexp
	kind string
}

// The patterns are the ones a secret is actually recognisable by in a tool
// result. Each one that captures a group captures the value rather than the
// label, because it is the value that has to be found again at the sink.
var sensitivePatterns = []sensitivePattern{
	{regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`), "openai_api_key"},
	{regexp.MustCompile(`sk_live_[a-zA-Z0-9]+`), "stripe_key"},
	{regexp.MustCompile(`Bearer\s+[a-zA-Z0-9._\-]{20,}`), "bearer_token"},
	{regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`), "github_pat"},
	{regexp.MustCompile(`glpat-[a-zA-Z0-9\-]{20,}`), "gitlab_pat"},
	{regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{16,})['"]?`), "api_key"},
	{regexp.MustCompile(`(?i)password\s*[:=]\s*['"]?([^\s'"]{8,})['"]?`), "password"},
	{regexp.MustCompile(`(?i)AWS[_A-Z]*KEY[_A-Z]*\s*[:=]\s*['"]?([A-Z0-9]{16,})['"]?`), "aws_key"},
	{regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----`), "private_key"},
	{regexp.MustCompile(`(?i)DATABASE_URL\s*[:=]\s*['"]?([^\s'"]+)['"]?`), "database_url"},
}

// These are matched against the arguments AFTER lowercasing, so the three that
// carry /i in the original are compiled case-sensitively here. Same answer, and
// none of the case folding.
var sensitiveFilePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\.env(?:\b|\.production|\.local|\.staging)`),
	regexp.MustCompile(`credentials`),
	regexp.MustCompile(`secrets?\b`),
	regexp.MustCompile(`id_rsa`),
	regexp.MustCompile(`id_ed25519`),
	regexp.MustCompile(`\.pem$`),
	regexp.MustCompile(`service.account`),
	regexp.MustCompile(`\.npmrc`),
}

func isSensitiveFileAccess(tc *ToolCall) bool {
	argStr := tc.ArgsLower()
	for _, p := range sensitiveFilePatterns {
		if p.MatchString(argStr) {
			return true
		}
	}
	return false
}

func isNetworkOrExecSink(tc *ToolCall) bool {
	t := lowerName(tc)
	argStr := tc.ArgsLower()
	if strings.Contains(t, "web") || strings.Contains(t, "fetch") || strings.Contains(t, "navigate") {
		return true
	}
	isExec := strings.Contains(t, "bash") || strings.Contains(t, "shell") || strings.Contains(t, "exec")
	return isExec && (strings.Contains(argStr, "curl") || strings.Contains(argStr, "wget") ||
		strings.Contains(argStr, "nc ") || strings.Contains(argStr, "scp ") ||
		strings.Contains(argStr, "http"))
}

// AnalyzeDataFlow pairs a tool result carrying something sensitive with a later
// call that could send it out, and only reports the pair when part of the value
// actually appears in the sink's arguments.
func AnalyzeDataFlow(sessions []*SessionInfo) []DataFlowLeak {
	var leaks []DataFlowLeak

	for _, session := range sessions {
		calls := session.ToolCalls

		for i := 0; i < len(calls); i++ {
			source := calls[i]
			sourceResult := source.ResultText()
			if jsLen(sourceResult) < 10 {
				continue
			}

			type token struct{ kind, value string }
			var found []token
			for _, sp := range sensitivePatterns {
				m := sp.re.FindStringSubmatch(sourceResult)
				if m == nil {
					continue
				}
				// The captured group is the value; without one the whole match
				// is. It is the VALUE that has to be found again at the sink.
				val := m[0]
				if len(m) > 1 && m[1] != "" {
					val = m[1]
				}
				found = append(found, token{sp.kind, jsSliceHead(val, 30)})
			}

			isSensitiveRead := isSensitiveFileAccess(source)
			if len(found) == 0 && !isSensitiveRead {
				continue
			}

			// Only look a short way ahead: a value used twenty calls later is
			// not a chain any more, it is the same session doing its job.
			end := i + 20
			if end > len(calls) {
				end = len(calls)
			}
			for j := i + 1; j < end; j++ {
				sink := calls[j]
				if !isNetworkOrExecSink(sink) {
					continue
				}
				sinkArgs := sink.ArgsJSON()

				for _, tk := range found {
					if strings.Contains(sinkArgs, jsSliceHead(tk.value, 15)) {
						leaks = append(leaks, DataFlowLeak{
							SessionID: session.ID, SourceIndex: i, SinkIndex: j,
							SourceToolName: source.ToolName, SinkToolName: sink.ToolName,
							DataType: tk.kind, Pattern: jsSliceHead(tk.value, 20) + "...",
						})
						break
					}
				}

				if isSensitiveRead && jsLen(sourceResult) > 20 {
					limit := jsLen(sourceResult) - 20
					if limit > 300 {
						limit = 300
					}
					for k := 0; k < limit; k += 20 {
						chunk := strings.TrimSpace(jsSliceRange(sourceResult, k, k+20))
						if jsLen(chunk) < 10 {
							continue
						}
						if strings.Contains(sinkArgs, chunk) {
							leaks = append(leaks, DataFlowLeak{
								SessionID: session.ID, SourceIndex: i, SinkIndex: j,
								SourceToolName: source.ToolName, SinkToolName: sink.ToolName,
								DataType: "file_content", Pattern: jsSliceHead(chunk, 20) + "...",
							})
							break
						}
					}
				}
			}
		}
	}

	return leaks
}
