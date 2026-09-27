package sdk

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/api"
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

	apiKey string
	cloud  *api.Client

	mu               sync.Mutex
	licenseValidated bool
	pollCancel       context.CancelFunc
	pollDone         chan struct{}
}

// New builds a gateway.
//
// The key is checked for SHAPE here and for validity on the first call. Both
// checks exist: a typo'd key should fail at startup where someone is watching,
// and a revoked one can only be found out from the API.
func New(options Options) (*SolonGate, error) {
	apiKey := options.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("SOLONGATE_API_KEY")
	}
	if apiKey == "" {
		return nil, &LicenseError{Reason: "A valid SolonGate API key is required."}
	}
	if !strings.HasPrefix(apiKey, "sg_live_") && !strings.HasPrefix(apiKey, "sg_test_") {
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
		cloud:        newCloudClient(apiKey, cfg.APIURL),
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

	// A live key with no local policy means the policy comes from the cloud,
	// and it keeps coming: a rule added in the dashboard has to reach a running
	// gateway without a restart.
	if policySet == nil && strings.HasPrefix(apiKey, "sg_live_") {
		g.fetchCloudPolicyOnce()
		g.startPolicyPolling()
	}

	return g, nil
}

// ExecuteToolCall runs one call through the pipeline.
func (g *SolonGate) ExecuteToolCall(ctx context.Context, params core.McpCallToolParams, upstream UpstreamCall) (core.McpCallToolResult, error) {
	if err := g.validateLicense(ctx); err != nil {
		return core.McpCallToolResult{}, err
	}

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
		ResponseScanConfig:       g.config.ResponseScanning,
		BlockUnsafeResponses:     g.config.BlockUnsafeResponses,
	})
}

// validateLicense runs once, on the first call.
//
// A NETWORK failure allows the call through, and that is deliberate: the key
// was already accepted in shape, the policy is enforced locally, and refusing
// every tool call because the licence server is unreachable would turn an
// outage at SolonGate into an outage in every customer's tool server. A 401 or
// a 403 is a different thing — that is an answer, and it is honoured.
func (g *SolonGate) validateLicense(ctx context.Context) error {
	g.mu.Lock()
	if g.licenseValidated {
		g.mu.Unlock()
		return nil
	}
	g.mu.Unlock()

	if strings.HasPrefix(g.apiKey, "sg_test_") {
		// A test key in production is a configuration mistake that would
		// otherwise be invisible: it works, so nobody finds out until the audit
		// trail is missing.
		if os.Getenv("NODE_ENV") == "production" || os.Getenv("GO_ENV") == "production" {
			return &LicenseError{
				Reason: "Test API keys (sg_test_) cannot be used in production. Use a sg_live_ key instead."}
		}
		g.markValidated()
		return nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := g.cloud.Do(reqCtx, http.MethodGet, "/auth/me", api.RequestOptions{Timeout: 5 * time.Second}, nil)
	if err != nil {
		var apiErr *api.Error
		if errors.As(err, &apiErr) {
			switch apiErr.Status {
			case 401:
				return &LicenseError{Reason: "Invalid or expired API key."}
			case 403:
				return &LicenseError{Reason: "This API key is not permitted to use this API."}
			}
		}
		g.logger.Warn("License validation failed (network error), allowing through: " + err.Error())
	}
	g.markValidated()
	return nil
}

func (g *SolonGate) markValidated() {
	g.mu.Lock()
	g.licenseValidated = true
	g.mu.Unlock()
}

// fetchCloudPolicyOnce loads the account's policy in the background.
//
// It does not block New. A gateway that waited for the network to start would
// make a tool server's boot time depend on SolonGate's availability, and the
// gateway is fail-closed until the policy lands anyway — so waiting buys
// nothing and costs a startup dependency.
func (g *SolonGate) fetchCloudPolicyOnce() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		policySet, _, err := fetchDefaultPolicy(ctx, g.cloud)
		if err != nil {
			return
		}
		if err := g.evaluator.LoadPolicySet(policySet); err != nil {
			g.logger.Warn("Cloud policy was rejected by the evaluator: " + err.Error())
		}
	}()
}

// startPolicyPolling re-reads the policy every minute and reloads it when the
// version changes.
func (g *SolonGate) startPolicyPolling() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	g.pollCancel = cancel
	g.pollDone = done

	go func() {
		defer close(done)
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		currentVersion := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			reqCtx, reqCancel := context.WithTimeout(ctx, 10*time.Second)
			policySet, version, err := fetchDefaultPolicy(reqCtx, g.cloud)
			reqCancel()
			if err != nil || version == 0 || version == currentVersion {
				continue
			}
			if err := g.evaluator.LoadPolicySet(policySet); err != nil {
				g.logger.Warn("Cloud policy was rejected by the evaluator: " + err.Error())
				continue
			}
			currentVersion = version
		}
	}()
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
	if !strings.HasPrefix(g.apiKey, "sg_live_") {
		return
	}

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

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = postAuditLog(ctx, g.cloud, entry)
	}()
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
