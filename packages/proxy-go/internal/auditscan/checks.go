package auditscan

import "regexp"

// The ten checks are the OWASP Agentic Top 10, each answered from what the
// transcripts actually show rather than from what is configured. That is the
// whole design: this tool runs before SolonGate is installed and has to be able
// to tell someone what their agents have already been doing.
//
// Two rules run through all of them and are worth stating once:
//
//   - Absence of evidence is PARTIAL, never PROTECTED, wherever the control
//     that would prevent the thing does not exist. "Nothing bad happened yet"
//     and "nothing can happen" are different answers and the report says which.
//   - A finding is rated against volume. One `sudo` in four thousand calls is a
//     developer working; forty is a pattern. The thresholds below are the ones
//     the npm tool ships, kept identical so a score does not move when someone
//     switches implementations.

// jsRegexp is a JavaScript regular expression: the compiled matcher plus the
// literal source text, because several checks quote the pattern back to the
// user (`pattern.source.slice(0, 30)`) and Go's own String() would print the
// (?i) prefix the port had to add.
type jsRegexp struct {
	re     *regexp.Regexp
	source string
	// ciRe is the case-insensitive form over the ORIGINAL text, used only where
	// a check reports the matched substring and the user should see the casing
	// the transcript actually had.
	ciRe        *regexp.Regexp
	insensitive bool
}

// ci compiles a JavaScript /…/i pattern.
func ci(source string) jsRegexp {
	return jsRegexp{re: regexp.MustCompile("(?i)" + source), source: source, insensitive: true}
}

// cs compiles a case-SENSITIVE JavaScript pattern.
func cs(source string) jsRegexp {
	return jsRegexp{re: regexp.MustCompile(source), source: source}
}

func (p jsRegexp) test(s string) bool { return p.re.MatchString(s) }

// sourceHead is `pattern.source.slice(0, n)`.
func (p jsRegexp) sourceHead(n int) string { return jsSliceHead(p.source, n) }

// ciLower compiles a JavaScript /…/i pattern for matching against text that has
// ALREADY been lowercased.
//
// Case-insensitive matching in Go runs Unicode case folding on every rune and
// was, measurably, the most expensive thing the checks do — the folding alone
// was six per cent of the whole scan. Where the haystack is already lowercase,
// a lowercase case-SENSITIVE pattern gives the same answer for these ASCII
// patterns and skips the folding entirely. The literal source is kept exactly
// as written, because two checks quote the pattern back to the user.
func ciLower(source string) jsRegexp {
	return jsRegexp{
		re:          regexp.MustCompile(lowerPatternLiterals(source)),
		ciRe:        regexp.MustCompile("(?i)" + source),
		source:      source,
		insensitive: true,
	}
}

// lowerPatternLiterals lowercases the LITERAL characters of a pattern and
// leaves escape sequences alone. \S, \D, \W and \B mean the opposite of their
// lowercase forms, so folding a pattern blindly would silently invert it.
func lowerPatternLiterals(source string) string {
	out := []byte(source)
	for i := 0; i < len(out); i++ {
		if out[i] == '\\' {
			i++
			continue
		}
		if out[i] >= 'A' && out[i] <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

// RunAllChecks produces the ten results in report order.
//
// The deep analysis runs ONCE and is shared. Four of the checks need the chain
// and baseline work, and computing it per check would walk every session's
// calls ten times over — on a machine with a year of transcripts that is the
// difference between a scan and a wait.
func RunAllChecks(data *AuditData) []CheckResult {
	baselines, anomalies, drifts := AnalyzeBaseline(data.Sessions)
	deep := &DeepAnalysis{
		Chains:             AnalyzeChains(data.Sessions),
		DataFlowLeaks:      AnalyzeDataFlow(data.Sessions),
		PermissionDrifts:   drifts,
		Baselines:          baselines,
		Anomalies:          anomalies,
		UnsolicitedActions: FindUnsolicitedActions(data.Sessions),
	}

	return []CheckResult{
		checkGoalHijacking(data, deep),
		checkToolMisuse(data, deep),
		checkIdentityAbuse(data, deep),
		checkSupplyChain(data),
		checkCodeExecution(data, deep),
		checkMemoryPoisoning(data),
		checkInterAgent(data),
		checkCascadingFailures(data, deep),
		checkHumanTrust(data, deep),
		checkRogueAgents(data, deep),
	}
}

// evidenceList accumulates the bullet points under one check.
type evidenceList []Evidence

func (e *evidenceList) add(icon EvidenceIcon, text string) {
	*e = append(*e, Evidence{Icon: icon, Text: text})
}

// chainsNamed picks the chain kinds one check cares about.
func chainsNamed(chains []ChainMatch, names ...string) []ChainMatch {
	var out []ChainMatch
	for _, c := range chains {
		for _, n := range names {
			if c.ChainName == n {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// chainToolPath renders a chain as "Read → Bash → WebFetch".
func chainToolPath(c ChainMatch) string {
	out := ""
	for i, s := range c.Steps {
		if i > 0 {
			out += " → "
		}
		out += s.ToolName
	}
	return out
}

// plural is the "issue"/"issues" the summaries switch on.
func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}

// headN caps a slice for display without panicking on a short one.
func headN[T any](items []T, n int) []T {
	if len(items) < n {
		return items
	}
	return items[:n]
}
