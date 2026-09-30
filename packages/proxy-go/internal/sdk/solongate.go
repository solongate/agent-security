package sdk

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/core"
)

// LicenseError is a missing or unusable API key.
//
// It is a distinct type because it is the one startup failure with an action
// attached, and the message carries that action rather than only the fault.
type LicenseError struct{ Reason string }

func (e *LicenseError) Error() string {
	return e.Reason + "\n" +
		"  Pair this machine with `solongate`, or set SOLONGATE_API_KEY.\n" +
		"  Usage: sdk.New(sdk.Options{Name: \"...\", APIKey: \"sg_live_xxx\"})"
}

// Options are the constructor arguments.
type Options struct {
	Name    string
	Version string
	// APIKey, or SOLONGATE_API_KEY from the environment.
	APIKey string
	Config *Config
	// PolicySet pins a policy locally. When set, nothing is fetched and nothing
	// is polled — the gateway enforces exactly this and only this.
	PolicySet *core.PolicySet
	// PolicyEvaluator is what actually decides. Without one every call is
	// denied; see FailClosedEvaluator.
	PolicyEvaluator PolicyEvaluator
}

// SolonGate is the security gateway for a tool server.
//
//	[model] → ExecuteToolCall → [pipeline] → [the tool]
//
// One value holds everything a gateway needs and is safe to share across
// concurrent calls.
type SolonGate struct {
	config    Config
	warnings  []string
	logger    *SecurityLogger
	evaluator PolicyEvaluator

	tokenIssuer    *TokenIssuer
	serverVerifier *ServerVerifier
	rateLimiter    *RateLimiter
	exfilTracker   *ExfiltrationChainTracker

	// apiKey is kept because the shape check in New still rejects a malformed one,
	// and because a person reading a config with a key in it deserves the gate to
	// notice. NOTHING IS DONE WITH IT: there is no request to sign and no licence to
	// check. It is not required, and a gateway built without one is fully armed.
	apiKey string

	mu         sync.Mutex
	pollCancel context.CancelFunc
	pollDone   chan struct{}
}

// New builds a gateway.
//
// NO KEY IS REQUIRED, and that is the point. This used to refuse without one — "A
// valid SolonGate API key is required" — which is a licence check, and what it
// licensed is deleted. The MCP proxy builds its gate through here, so that refusal
// was the last thing standing between a machine with no service and a working
// proxy.
func New(options Options) (*SolonGate, error) {
	apiKey := options.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("SOLONGATE_API_KEY")
	}
	if apiKey != "" && !strings.HasPrefix(apiKey, "sg_live_") && !strings.HasPrefix(apiKey, "sg_test_") {
		return nil, &LicenseError{
			Reason: "Invalid API key format. Keys must start with 'sg_live_' or 'sg_test_'."}
	}

	cfg, warnings := ResolveConfig(options.Config)
	logger := NewSecurityLogger(cfg.LogLevel, cfg.LoggingOn())
	for _, w := range warnings {
		logger.Warn(w)
	}

	evaluator := options.PolicyEvaluator
	if evaluator == nil {
		evaluator = &FailClosedEvaluator{}
	}

	g := &SolonGate{
		config:       cfg,
		warnings:     warnings,
		logger:       logger,
		evaluator:    evaluator,
		rateLimiter:  NewRateLimiter(),
		exfilTracker: NewExfiltrationChainTracker(),
		apiKey:       apiKey,
	}

	policySet := options.PolicySet
	if policySet == nil {
		policySet = cfg.PolicySet
	}
	if policySet != nil {
		if err := evaluator.LoadPolicySet(*policySet); err != nil {
			return nil, err
		}
	}

	if cfg.TokenSecret != "" {
		issuerName := cfg.TokenIssuer
		if issuerName == "" {
			issuerName = options.Name
		}
		issuer, err := NewTokenIssuer(cfg.TokenSecret, cfg.TokenTTLSeconds, issuerName)
		if err != nil {
			return nil, err
		}
		g.tokenIssuer = issuer
	}

	if cfg.GatewaySecret != "" {
		verifier, err := NewServerVerifier(cfg.GatewaySecret, 0)
		if err != nil {
			return nil, err
		}
		g.serverVerifier = verifier
	}

	return g, nil
}

// ExecuteToolCall runs one call through the pipeline.
func (g *SolonGate) ExecuteToolCall(ctx context.Context, params core.McpCallToolParams, upstream UpstreamCall) (core.McpCallToolResult, error) {
	// This used to begin with validateLicense, which GET /auth/me'd on the first
	// call of the process and refused every tool call on a 401 or a 403. That made a
	// third party's answer a precondition for a local security decision: with the
	// wrong key, a gateway configured to deny `rm -rf` would not deny it — it would
	// refuse to run at all, and a tool server that refuses to run gets the gate
	// taken out. The policy is enforced from a file on this machine; nothing about
	// enforcing it needs permission.
	start := time.Now()
	return InterceptToolCall(ctx, params, upstream, InterceptorOptions{
		PolicyEvaluator: g.evaluator,
		ValidateSchemas: g.config.ValidateSchemasOn(),
		VerboseErrors:   g.config.VerboseErrors,
		OnDecision: func(result core.ExecutionResult) {
			g.logger.LogDecision(result)
			g.recordAudit(params, result, float64(time.Since(start).Nanoseconds())/1e6)
		},
		TokenIssuer:              g.tokenIssuer,
		ServerVerifier:           g.serverVerifier,
		RateLimiter:              g.rateLimiter,
		RateLimitPerTool:         g.config.RateLimitPerTool,
		GlobalRateLimitPerMinute: g.config.GlobalRateLimitPerMinute,
		ExfiltrationTracker:      g.exfilTracker,
		DLPBlock:                 g.config.DLPBlock,
		ResponseScanConfig:       g.config.ResponseScanning,
		BlockUnsafeResponses:     g.config.BlockUnsafeResponses,
	})
}

// recordAudit hands one decision to the cloud WITHOUT the call waiting for it.
//
// This is the same constraint the guard has, for the same reason: the verdict
// is the product and the audit line is bookkeeping. Awaiting the POST put a
// network round trip between "blocked" and the agent hearing it — measured at
// 1643ms per denial against the real API. The guard solves it by handing the
// record to a detached child, because the guard process exits immediately after
// the verdict. A gateway does not exit, so a goroutine is the same trade
// without the process: the record still goes, and nothing waits for it.
func (g *SolonGate) recordAudit(params core.McpCallToolParams, result core.ExecutionResult, elapsedMs float64) {
	args := params.Arguments
	if args == nil {
		args = map[string]any{}
	}
	entry := auditEntry{Tool: params.Name, Arguments: args, EvaluationTimeMs: elapsedMs}

	switch result.Status {
	case core.StatusAllowed, core.StatusDenied:
		if result.Decision == nil {
			return
		}
		entry.Decision = "DENY"
		if result.Decision.Effect == core.EffectAllow {
			entry.Decision = "ALLOW"
		}
		entry.Reason = result.Decision.Reason
		if result.Decision.MatchedRule != nil {
			entry.MatchedRule = result.Decision.MatchedRule.ID
		}
	case core.StatusError:
		entry.Decision = "DENY"
		if result.Err != nil {
			entry.Reason = result.Err.Error()
		}
	default:
		return
	}

	// The same file the guard, the hooks and the proxy write. This used to POST the
	// entry to a service; a gate embedded in somebody's tool server has no more
	// business shipping their tool calls off the machine than the guard did.
	writeAuditEntry(entry, func(line string) { g.logger.Warn(line) })
}

// LoadPolicy replaces the policy at runtime.
func (g *SolonGate) LoadPolicy(policySet core.PolicySet) error {
	return g.evaluator.LoadPolicySet(policySet)
}

// Warnings is every configuration warning this gateway started with.
func (g *SolonGate) Warnings() []string { return append([]string(nil), g.warnings...) }

func (g *SolonGate) RateLimiter() *RateLimiter       { return g.rateLimiter }
func (g *SolonGate) TokenIssuer() *TokenIssuer       { return g.tokenIssuer }
func (g *SolonGate) Evaluator() PolicyEvaluator      { return g.evaluator }
func (g *SolonGate) ServerVerifier() *ServerVerifier { return g.serverVerifier }

// Close stops the policy poller and waits for it to finish.
//
// Waiting matters in a test: a poller still running after the gateway it
// belongs to has gone is what makes a test suite flake on an unrelated case
// half a minute later.
func (g *SolonGate) Close() {
	g.mu.Lock()
	cancel, done := g.pollCancel, g.pollDone
	g.pollCancel, g.pollDone = nil, nil
	g.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
