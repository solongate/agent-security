package sdk

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/core"
)

// ── Exfiltration chain tracking ────────────────────────────────────────────

// Tools that bring data IN.
var dataSourceTools = map[string]bool{
	"file_read": true, "db_query": true, "read_file": true, "readFile": true,
	"database_query": true, "sql_query": true, "get_secret": true, "read_resource": true,
}

// Tools that can send data OUT.
var dataSinkTools = map[string]bool{
	"web_fetch": true, "shell_exec": true, "http_request": true, "send_email": true,
	"fetch": true, "curl": true, "wget": true, "write_file": true, "writeFile": true,
}

const (
	chainWindowSize   = 10
	chainTimeWindowMs = 60_000
)

// ExfiltrationChainTracker watches for a read followed by a send.
//
// Neither call is remarkable on its own, which is exactly why this exists: the
// policy engine sees one call at a time and cannot express "not after that
// other one". The window is short and small on purpose — over a long enough
// history every session contains a read and a send, and a detector that fires
// on everything is off.
type ExfiltrationChainTracker struct {
	mu     sync.Mutex
	recent [chainWindowSize]struct {
		name string
		at   int64
	}
	writeIndex int
	count      int
}

func NewExfiltrationChainTracker() *ExfiltrationChainTracker { return &ExfiltrationChainTracker{} }

func (t *ExfiltrationChainTracker) Record(toolName string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.recent[t.writeIndex].name = toolName
	t.recent[t.writeIndex].at = nowMillis()
	t.writeIndex = (t.writeIndex + 1) % chainWindowSize
	if t.count < chainWindowSize {
		t.count++
	}
}

// DetectChain reports whether this call is a sink that follows a recent source.
func (t *ExfiltrationChainTracker) DetectChain(currentTool string) bool {
	if !dataSinkTools[currentTool] {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := nowMillis() - chainTimeWindowMs
	for i := 0; i < t.count; i++ {
		c := t.recent[i]
		if dataSourceTools[c.name] && c.at >= cutoff {
			return true
		}
	}
	return false
}

// ── The pipeline ───────────────────────────────────────────────────────────

// PolicyEvaluator is whatever decides. The SDK does not ship one: policy
// evaluation is packages/guard-go's, which compiles the policy JSON to Rego and
// runs it through embedded OPA, and duplicating that here would mean two
// implementations of the rules that can disagree. See dependsOn.
type PolicyEvaluator interface {
	// LoadPolicySet replaces the policy being enforced.
	LoadPolicySet(policySet core.PolicySet) error
	// Evaluate never returns an error. A denial is an outcome, not a failure,
	// and an evaluator that could fail would need a caller to decide what a
	// failure means — which is the fail-open question this design refuses to
	// leave to a call site.
	Evaluate(request core.ExecutionRequest) core.PolicyDecision
}

// FailClosedEvaluator is what a gateway gets until a real evaluator is
// installed: everything is denied.
//
// It denies rather than allows, and that is the whole point. A gateway with no
// policy loaded has no basis to permit anything, and the alternative — allowing
// until a policy arrives — makes every startup a window in which nothing is
// enforced and nothing says so.
type FailClosedEvaluator struct {
	mu        sync.RWMutex
	policySet core.PolicySet
}

func (e *FailClosedEvaluator) LoadPolicySet(policySet core.PolicySet) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policySet = policySet
	return nil
}

func (e *FailClosedEvaluator) Evaluate(core.ExecutionRequest) core.PolicyDecision {
	return core.PolicyDecision{
		Effect:      core.DefaultPolicyEffect,
		MatchedRule: nil,
		Reason: "No policy evaluator loaded — failing closed (default DENY). " +
			"Install an evaluator with WithPolicyEvaluator, or use the guard binary.",
		Timestamp:        time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		EvaluationTimeMs: 0,
	}
}

// PolicySet returns what was last loaded, for reporting.
func (e *FailClosedEvaluator) PolicySet() core.PolicySet {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policySet
}

// UpstreamCall is the tool handler the gateway is protecting.
type UpstreamCall func(ctx context.Context, params core.McpCallToolParams) (core.McpCallToolResult, error)

// InterceptorOptions is everything one pass through the pipeline needs.
type InterceptorOptions struct {
	PolicyEvaluator PolicyEvaluator
	ValidateSchemas bool
	VerboseErrors   bool
	OnDecision      func(core.ExecutionResult)

	TokenIssuer    *TokenIssuer
	ServerVerifier *ServerVerifier
	RateLimiter    *RateLimiter

	RateLimitPerTool         int
	GlobalRateLimitPerMinute int

	ExfiltrationTracker  *ExfiltrationChainTracker
	ResponseScanConfig   *ResponseScanConfig
	BlockUnsafeResponses bool
}

// InterceptToolCall runs one tool call through the whole pipeline:
//
//  1. rate limit          — per tool and globally
//  2. exfiltration chain  — a sink right after a source
//  3. policy evaluation   — the actual decision
//  4. capability token    — proof this call was allowed
//  5. request signature   — proof it came from the gateway
//  6. the upstream call
//  7. response scan       — injected instructions coming back
//  8. rate limit record
//  9. audit
//
// The order is load-bearing. The cheap local refusals come first so a flood
// cannot be turned into work, and nothing that touches the network happens
// before the decision is made.
func InterceptToolCall(ctx context.Context, params core.McpCallToolParams, upstream UpstreamCall, options InterceptorOptions) (core.McpCallToolResult, error) {
	requestID, err := randomUUID()
	if err != nil {
		// Without a request id there is nothing to tie an audit entry to, and a
		// predictable one would let two calls share a capability token.
		return DeniedToolResult("Could not start a secured request."), nil
	}
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	arguments := params.Arguments
	if arguments == nil {
		arguments = map[string]any{}
	}

	request := core.ExecutionRequest{
		Context:            core.NewSecurityContext(requestID),
		ToolName:           params.Name,
		ServerName:         "default",
		Arguments:          arguments,
		RequiredPermission: core.GuessPermission(params.Name),
		Timestamp:          timestamp,
	}

	emit := func(result core.ExecutionResult) {
		if options.OnDecision != nil {
			options.OnDecision(result)
		}
	}

	// ── 1. rate limit ──
	if options.RateLimiter != nil {
		if options.RateLimitPerTool > 0 {
			if !options.RateLimiter.CheckLimit(params.Name, options.RateLimitPerTool).Allowed {
				emit(core.ExecutionResult{
					Status: core.StatusError, Request: request, Timestamp: timestamp,
					Err: core.NewRateLimitError(params.Name, options.RateLimitPerTool),
				})
				return DeniedToolResult(`Rate limit exceeded for tool "` + params.Name + `"`), nil
			}
		}
		if options.GlobalRateLimitPerMinute > 0 {
			if !options.RateLimiter.CheckGlobalLimit(options.GlobalRateLimitPerMinute).Allowed {
				emit(core.ExecutionResult{
					Status: core.StatusError, Request: request, Timestamp: timestamp,
					Err: core.NewRateLimitError("*", options.GlobalRateLimitPerMinute),
				})
				return DeniedToolResult("Global rate limit exceeded"), nil
			}
		}
	}

	// ── 2. exfiltration chain ──
	if options.ExfiltrationTracker != nil {
		if options.ExfiltrationTracker.DetectChain(params.Name) {
			decision := core.PolicyDecision{
				Effect:      core.EffectDeny,
				MatchedRule: nil,
				Reason: `Exfiltration chain detected: data-sink tool "` + params.Name +
					`" called after recent data-source tool`,
				Timestamp:        timestamp,
				EvaluationTimeMs: 0,
			}
			emit(core.ExecutionResult{
				Status: core.StatusDenied, Request: request, Decision: &decision, Timestamp: timestamp,
			})
			return DeniedToolResult(
				`Potential data exfiltration chain blocked: "` + params.Name +
					`" called after a data-access tool`), nil
		}
		options.ExfiltrationTracker.Record(params.Name)
	}

	// ── 3. policy ──
	evaluator := options.PolicyEvaluator
	if evaluator == nil {
		evaluator = &FailClosedEvaluator{}
	}
	decision := evaluator.Evaluate(request)

	if decision.Effect == core.EffectDeny {
		emit(core.ExecutionResult{
			Status: core.StatusDenied, Request: request, Decision: &decision, Timestamp: timestamp,
		})
		reason := "Tool execution denied by security policy."
		if options.VerboseErrors {
			reason = decision.Reason
		}
		return DeniedToolResult(reason), nil
	}

	// ── 4. capability token ──
	callParams := params
	var capabilityToken string
	if options.TokenIssuer != nil {
		token, err := options.TokenIssuer.Issue(requestID,
			[]core.Permission{core.PermExecute}, []string{params.Name}, nil, nil)
		if err != nil {
			emit(core.ExecutionResult{
				Status: core.StatusError, Request: request, Timestamp: timestamp,
				Err: core.NewError("Could not issue a capability token: "+err.Error(), "TOKEN_ISSUE_FAILED", nil),
			})
			// An allowed call with no token is an unattested call. Refuse it
			// rather than pass it upstream unproven.
			return DeniedToolResult("Could not issue a capability token for this call."), nil
		}
		capabilityToken = token
	}

	// ── 5. signature ──
	if options.ServerVerifier != nil && capabilityToken != "" {
		signed, err := options.ServerVerifier.CreateSignedRequest(params, capabilityToken)
		if err != nil {
			return DeniedToolResult("Could not sign this call."), nil
		}
		// The signed envelope travels alongside the parameters, in a reserved
		// argument the upstream verifies and drops. The tool's own arguments
		// are left exactly as they were, so a server that does not verify still
		// sees the call it expects.
		wrapped := map[string]any{}
		for k, v := range arguments {
			wrapped[k] = v
		}
		wrapped["__solongate"] = signed
		callParams = core.McpCallToolParams{Name: params.Name, Arguments: wrapped}
	}

	// ── 6. upstream ──
	start := time.Now()
	toolResult, err := upstream(ctx, callParams)
	durationMs := float64(time.Since(start).Nanoseconds()) / 1e6

	if err != nil {
		emit(core.ExecutionResult{
			Status: core.StatusError, Request: request, Timestamp: timestamp,
			Err: core.NewPolicyDeniedError(params.Name, err.Error(), nil),
		})
		// The upstream's failure is returned as-is. The gateway allowed this
		// call; turning the tool's own error into a denial would tell the model
		// something untrue about why it failed.
		return core.McpCallToolResult{}, err
	}

	// ── 7. response scan ──
	scanConfig := DefaultResponseScanConfig()
	if options.ResponseScanConfig != nil {
		scanConfig = *options.ResponseScanConfig
	}
	for i := range toolResult.Content {
		item := &toolResult.Content[i]
		if item.Type != "text" || item.Text == "" {
			continue
		}
		scan := ScanResponse(item.Text, scanConfig)
		if scan.Safe {
			continue
		}
		if options.BlockUnsafeResponses {
			descriptions := make([]string, 0, len(scan.Threats))
			for _, t := range scan.Threats {
				descriptions = append(descriptions, t.Description)
			}
			return DeniedToolResult("Response blocked by security scanner: " +
				strings.Join(descriptions, "; ")), nil
		}
		item.Text = ResponseWarningMarker + "\n\n" + item.Text
	}

	// ── 8. record ──
	if options.RateLimiter != nil {
		options.RateLimiter.RecordCall(params.Name)
	}

	// ── 9. audit ──
	emit(core.ExecutionResult{
		Status: core.StatusAllowed, Request: request, Decision: &decision,
		ToolResult: toolResult, DurationMs: durationMs, Timestamp: timestamp,
	})

	return toolResult, nil
}
