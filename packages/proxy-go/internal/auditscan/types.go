// Package auditscan is the `solongate-audit` tool: it reads the transcripts the
// AI clients on this machine have already written, and grades what they show
// against the OWASP Agentic Top 10.
//
// It is a port of packages/proxy/src/audit. The package is not called `audit`
// because `solongate audit` is a different command in the same CLI — that one
// browses the audit log the guard posts to the cloud, and lives in another
// slice. This one never talks to the cloud and never needs a login: it reads
// files that are already on disk.
//
// Nothing here is on the guard's decision path. The PostToolUse hook that runs
// on every tool call is packages/proxy/hooks/audit.mjs, a separate self-contained
// file that imports none of this; see the note in cmd/solongate-audit.
package auditscan

import "strings"

// CheckStatus is the verdict for one OWASP category. Three values, because the
// interesting case is the middle one: a category with no evidence of abuse but
// also no control preventing it is PARTIAL, not PROTECTED.
type CheckStatus string

const (
	StatusProtected    CheckStatus = "PROTECTED"
	StatusPartial      CheckStatus = "PARTIAL"
	StatusNotProtected CheckStatus = "NOT_PROTECTED"
)

// EvidenceIcon marks what a line of evidence is: something found, something
// missing, something to look at, or context.
type EvidenceIcon string

const (
	IconFound   EvidenceIcon = "found"
	IconMissing EvidenceIcon = "missing"
	IconWarn    EvidenceIcon = "warn"
	IconInfo    EvidenceIcon = "info"
)

type Evidence struct {
	Icon EvidenceIcon `json:"icon"`
	Text string       `json:"text"`
}

type CheckResult struct {
	Code           string      `json:"code"`
	Title          string      `json:"title"`
	Status         CheckStatus `json:"status"`
	Summary        string      `json:"summary"`
	Details        string      `json:"details"`
	Evidence       []Evidence  `json:"evidence"`
	Recommendation string      `json:"recommendation,omitempty"`
}

// Source is which client wrote the transcript a call came from.
type Source string

const (
	SourceClaude      Source = "claude"
	SourceCodex       Source = "codex"
	SourceAntigravity Source = "antigravity"
	SourceOpenClaw    Source = "openclaw"
)

// ToolCall is one tool invocation, normalised out of whichever transcript
// format it was found in.
//
// Result and IsError are pointers because "no result was recorded" and "a
// result was recorded and it was not an error" are different facts, and the
// JSON export distinguishes them: a call the transcript never paired with an
// outcome omits both fields, exactly as the npm exporter does.
type ToolCall struct {
	ID        string  `json:"id"`
	ToolName  string  `json:"toolName"`
	Arguments *Args   `json:"arguments"`
	Timestamp string  `json:"timestamp"`
	Source    Source  `json:"source"`
	SessionID string  `json:"sessionId"`
	Result    *string `json:"result,omitempty"`
	IsError   *bool   `json:"isError,omitempty"`

	// Nearly every check lowercases the tool name and the serialised arguments
	// before matching. Both are fixed once a transcript is read, and computing
	// them per check meant ten passes over the same eleven thousand calls.
	argsLower      string
	hasArgsLower   bool
	nameLower      string
	hasNameLower   bool
	resultLower    string
	hasResultLower bool
}

// ResultLower is the tool result lowercased once. Two checks scan every result
// with ten case-insensitive patterns each, and folding case inside the regex
// engine costs far more than folding the string once.
func (tc *ToolCall) ResultLower() string {
	if !tc.hasResultLower {
		tc.resultLower = strings.ToLower(tc.ResultText())
		tc.hasResultLower = true
	}
	return tc.resultLower
}

// ArgsLower is `JSON.stringify(tc.arguments).toLowerCase()`.
func (tc *ToolCall) ArgsLower() string {
	if !tc.hasArgsLower {
		tc.argsLower = strings.ToLower(tc.ArgsJSON())
		tc.hasArgsLower = true
	}
	return tc.argsLower
}

// NameLower is `tc.toolName.toLowerCase()`.
func (tc *ToolCall) NameLower() string {
	if !tc.hasNameLower {
		tc.nameLower = strings.ToLower(tc.ToolName)
		tc.hasNameLower = true
	}
	return tc.nameLower
}

// ResultText is `tc.result || ”` — the form every check reads.
func (tc *ToolCall) ResultText() string {
	if tc == nil || tc.Result == nil {
		return ""
	}
	return *tc.Result
}

// Errored is `tc.isError` under JavaScript truthiness: unrecorded is not an
// error.
func (tc *ToolCall) Errored() bool {
	return tc != nil && tc.IsError != nil && *tc.IsError
}

func (tc *ToolCall) setResult(s string) { tc.Result = &s }
func (tc *ToolCall) setIsError(b bool)  { tc.IsError = &b }

// ArgsJSON is `JSON.stringify(tc.arguments)`, the haystack most checks grep.
func (tc *ToolCall) ArgsJSON() string {
	if tc.Arguments == nil {
		return "{}"
	}
	return tc.Arguments.String()
}

type UserMessage struct {
	Timestamp string `json:"timestamp"`
	Text      string `json:"text"`
	// Index of the first tool call that followed this message, or -1. It is how
	// a critical action gets attributed to a request, or found to have none.
	NextToolCallIndex int `json:"nextToolCallIndex,omitempty"`
}

type SessionInfo struct {
	ID           string        `json:"id"`
	Source       Source        `json:"source"`
	StartTime    string        `json:"startTime"`
	EndTime      string        `json:"endTime,omitempty"`
	Model        string        `json:"model,omitempty"`
	ToolCalls    []*ToolCall   `json:"toolCalls"`
	UserMessages []UserMessage `json:"userMessages,omitempty"`
	FilePath     string        `json:"filePath"`
}

type TimeRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type AuditData struct {
	Sessions       []*SessionInfo `json:"sessions"`
	TotalToolCalls int            `json:"totalToolCalls"`
	// Which AI tools were found, in display form ("Claude Code", "Codex", …).
	Sources   []string   `json:"sources"`
	TimeRange *TimeRange `json:"timeRange"`
}

// AllCalls flattens every session's calls in session order, the way
// `sessions.flatMap(s => s.toolCalls)` does.
func (d *AuditData) AllCalls() []*ToolCall {
	out := make([]*ToolCall, 0, d.TotalToolCalls)
	for _, s := range d.Sessions {
		out = append(out, s.ToolCalls...)
	}
	return out
}

// ── Deep analysis ──────────────────────────────────────────────────────────

type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

type ChainStep struct {
	Index    int    `json:"index"`
	ToolName string `json:"toolName"`
	Summary  string `json:"summary"`
}

type ChainMatch struct {
	ChainName   string      `json:"chainName"`
	SessionID   string      `json:"sessionId"`
	Steps       []ChainStep `json:"steps"`
	Severity    Severity    `json:"severity"`
	Description string      `json:"description"`
}

type DataFlowLeak struct {
	SessionID      string `json:"sessionId"`
	SourceIndex    int    `json:"sourceIndex"`
	SinkIndex      int    `json:"sinkIndex"`
	SourceToolName string `json:"sourceToolName"`
	SinkToolName   string `json:"sinkToolName"`
	DataType       string `json:"dataType"`
	Pattern        string `json:"pattern"`
}

type PermissionDrift struct {
	SessionID           string   `json:"sessionId"`
	EarlyPrivilegeLevel float64  `json:"earlyPrivilegeLevel"`
	LatePrivilegeLevel  float64  `json:"latePrivilegeLevel"`
	DriftRatio          float64  `json:"driftRatio"`
	NewToolTypes        []string `json:"newToolTypes"`
}

type SessionBaseline struct {
	// "all" alongside the four client sources.
	Source               string             `json:"source"`
	AvgToolCalls         float64            `json:"avgToolCalls"`
	StddevToolCalls      float64            `json:"stddevToolCalls"`
	ToolTypeDistribution map[string]float64 `json:"toolTypeDistribution"`
	AvgDurationMs        float64            `json:"avgDurationMs"`
	StddevDurationMs     float64            `json:"stddevDurationMs"`

	// distOrder keeps the categories in the order they were first counted, so
	// the baseline line in the report is stable across runs. Go map iteration is
	// random and this string is printed.
	distOrder []string
}

type SessionAnomaly struct {
	SessionID  string   `json:"sessionId"`
	Source     string   `json:"source"`
	Deviations []string `json:"deviations"`
	Severity   Severity `json:"severity"`
}

type UnsolicitedAction struct {
	SessionID             string `json:"sessionId"`
	ToolCallIndex         int    `json:"toolCallIndex"`
	ToolName              string `json:"toolName"`
	Action                string `json:"action"`
	LastUserMessageBefore string `json:"lastUserMessageBefore,omitempty"`
	// Milliseconds since the last user message, and whether there was one.
	TimeSinceLastUserMessage float64 `json:"timeSinceLastUserMessage,omitempty"`
	HasLastUserMessage       bool    `json:"-"`
}

// DeepAnalysis is computed once and shared by every check, because four of the
// ten need the same chain and baseline work and running it per check would walk
// every session ten times.
type DeepAnalysis struct {
	Chains             []ChainMatch
	DataFlowLeaks      []DataFlowLeak
	PermissionDrifts   []PermissionDrift
	Baselines          []SessionBaseline
	Anomalies          []SessionAnomaly
	UnsolicitedActions []UnsolicitedAction
}
