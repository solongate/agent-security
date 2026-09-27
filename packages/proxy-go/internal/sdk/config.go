// Package sdk is the embeddable gateway: the security pipeline a tool server
// puts in front of its own handlers.
//
// It is a port of packages/proxy/src/sdk. The npm package keeps exporting the
// TypeScript one; this is a second implementation for Go tool servers, and the
// two do not have to be used together.
//
// The shape is the same in both: one SolonGate value holds the policy, the rate
// limiter, the token issuer and the audit sink, and every tool call goes
// through ExecuteToolCall, which either calls upstream or returns a denial.
// Nothing in the pipeline throws for a denial — a denial is an ordinary
// outcome, and a caller that has to catch an exception to find out will
// eventually forget to.
package sdk

import (
	"strings"

	"github.com/codeyevsky/solongate/proxy/internal/core"
)

// Config is every knob, with secure defaults. Weakening one is possible and
// deliberate; each weakening produces a warning the host is expected to print,
// because a gateway that is quietly less strict than it looks is the failure
// this design exists to prevent.
//
// The two settings whose safe value is TRUE are pointers, and that is the whole
// reason. The TypeScript merges a partial config over the defaults, so a field
// nobody mentioned keeps its default. Go has no "unmentioned" for a bool: a
// caller writing `&Config{APIURL: "…"}` would get false for every one, and
// would have turned schema validation and logging off by not talking about
// them. A nil pointer means "not mentioned" and takes the default.
type Config struct {
	// PolicySet, when set, is enforced instead of anything fetched from the
	// cloud. Nothing is fetched at all in that case.
	PolicySet *core.PolicySet

	// ValidateSchemas is carried through to the interceptor but NOTHING READS
	// IT YET, in this port or in the TypeScript it comes from: validating a
	// call against a tool's declared schema needs a tool registry the gateway
	// does not have. It is here so the field does not have to be reintroduced
	// later, and it is documented as inert so nobody reads its presence as a
	// guarantee that arguments are being checked.
	ValidateSchemas *bool
	EnableLogging   *bool
	LogLevel        LogLevel
	// EvaluationTimeoutMs is a WARNING threshold, not a deadline. Evaluation is
	// not cancelled at it — an evaluation that is cut short has no answer, and
	// no answer is not a security decision.
	EvaluationTimeoutMs int
	// VerboseErrors sends the real denial reason back to the model. Off by
	// default: the reason names rules and paths, and the model is the untrusted
	// party.
	VerboseErrors bool

	GlobalRateLimitPerMinute int
	RateLimitPerTool         int

	TokenSecret      string
	TokenTTLSeconds  int
	TokenIssuer      string
	GatewaySecret    string
	APIURL           string
	ResponseScanning *ResponseScanConfig
	// BlockUnsafeResponses turns a flagged upstream response into a denial
	// instead of a warning banner. Off by default, because the scanner reports
	// suspicion and a false positive would silently break a working tool.
	BlockUnsafeResponses bool
}

// Bool is a helper for setting one of the pointer fields above:
//
//	sdk.Config{EnableLogging: sdk.Bool(false)}
func Bool(v bool) *bool { return &v }

// DefaultConfig is the starting point for every gateway.
func DefaultConfig() Config {
	return Config{
		ValidateSchemas:          Bool(true),
		EnableLogging:            Bool(true),
		LogLevel:                 LevelInfo,
		EvaluationTimeoutMs:      core.PolicyEvaluationTimeout,
		VerboseErrors:            false,
		GlobalRateLimitPerMinute: 600,
		RateLimitPerTool:         core.DefaultRateLimitPerMinute,
		TokenTTLSeconds:          core.TokenDefaultTTLSeconds,
	}
}

// ValidateSchemasOn and LoggingOn read the pointer fields with the default
// applied, so a caller never has to.
func (c Config) ValidateSchemasOn() bool { return c.ValidateSchemas == nil || *c.ValidateSchemas }
func (c Config) LoggingOn() bool         { return c.EnableLogging == nil || *c.EnableLogging }

// ResolveConfig fills in the defaults a caller left alone and returns the
// warnings for the ones they overrode.
//
// A zero value means "not set" for every numeric field here, which is why none
// of them has a meaningful zero: a rate limit of 0 would be unlimited, and that
// is a setting a caller has to ask for by name rather than reach by omission.
func ResolveConfig(user *Config) (Config, []string) {
	cfg := DefaultConfig()
	var warnings []string

	if user != nil {
		u := *user
		if u.PolicySet != nil {
			cfg.PolicySet = u.PolicySet
		}
		if u.ValidateSchemas != nil {
			cfg.ValidateSchemas = u.ValidateSchemas
		}
		if u.EnableLogging != nil {
			cfg.EnableLogging = u.EnableLogging
		}
		cfg.VerboseErrors = u.VerboseErrors
		cfg.BlockUnsafeResponses = u.BlockUnsafeResponses
		if u.LogLevel != "" {
			cfg.LogLevel = u.LogLevel
		}
		if u.EvaluationTimeoutMs != 0 {
			cfg.EvaluationTimeoutMs = u.EvaluationTimeoutMs
		}
		if u.GlobalRateLimitPerMinute != 0 {
			cfg.GlobalRateLimitPerMinute = u.GlobalRateLimitPerMinute
		}
		if u.RateLimitPerTool != 0 {
			cfg.RateLimitPerTool = u.RateLimitPerTool
		}
		if u.TokenSecret != "" {
			cfg.TokenSecret = u.TokenSecret
		}
		if u.TokenTTLSeconds != 0 {
			cfg.TokenTTLSeconds = u.TokenTTLSeconds
		}
		if u.TokenIssuer != "" {
			cfg.TokenIssuer = u.TokenIssuer
		}
		if u.GatewaySecret != "" {
			cfg.GatewaySecret = u.GatewaySecret
		}
		if u.APIURL != "" {
			cfg.APIURL = u.APIURL
		}
		if u.ResponseScanning != nil {
			cfg.ResponseScanning = u.ResponseScanning
		}
	}

	if !cfg.ValidateSchemasOn() {
		warnings = append(warnings, core.UnsafeConfigurationWarnings["DISABLED_VALIDATION"])
	}
	if cfg.GlobalRateLimitPerMinute == 0 {
		warnings = append(warnings, core.UnsafeConfigurationWarnings["RATE_LIMIT_ZERO"])
	}
	if cfg.VerboseErrors {
		warnings = append(warnings,
			"Verbose errors enabled: internal error details will be sent to the LLM.")
	}
	if cfg.TokenSecret != "" && len(cfg.TokenSecret) < core.TokenMinSecretLength {
		warnings = append(warnings,
			"Token secret is shorter than 32 characters. Use a longer secret for production.")
	}
	// Plaintext HTTP is only tolerated against a loopback address, where there
	// is no network for anyone to read the key off.
	if strings.HasPrefix(cfg.APIURL, "http://") &&
		!strings.HasPrefix(cfg.APIURL, "http://localhost") &&
		!strings.HasPrefix(cfg.APIURL, "http://127.0.0.1") {
		warnings = append(warnings,
			"API URL uses plaintext HTTP. API keys will be sent unencrypted. Use HTTPS in production.")
	}

	return cfg, warnings
}
